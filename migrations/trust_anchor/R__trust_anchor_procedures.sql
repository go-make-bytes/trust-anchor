-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 go-make-bytes contributors

-- R: repeatable migration — the trust_anchor store API (5 procedures).
--
-- These back the store.Store interface the trust-anchor service uses
-- (SaveSnapshot/LoadLatestSnapshot, SaveBootstrap/LoadLatestBootstrap). They run
-- as the migrating owner (the owner of the tables — implicit ownership), so the
-- EXECUTE-only `trust_anchor_public` service role drives them without any table privileges. Each:
--   * uses the uniform JSONB envelope `(pi_data jsonb, INOUT po_data jsonb)`,
--   * pins `search_path` ending in pg_temp (SECURITY DEFINER hardening),
--   * returns a structured result via util.result_success / util.result_error
--     with `<domain>:<reason>` error codes,
--   * validates BEFORE any write (Pattern A: return) and, on any unexpected
--     error after a write, re-raises a structured error with SQLSTATE P0001
--     (Pattern B) so the transaction ROLLS BACK rather than committing a partial
--     write.
-- For the *save* procedures, `pi_data` IS the full serialized object (the Go
-- backend passes the marshalled trust.Snapshot / trust.Bootstrap directly); the
-- object is stored verbatim in `content` and key columns are projected from it.
-- Re-applied automatically whenever the checksum changes.

-- trust_anchor.save_snapshot — save a snapshot: one row for each VERSION.
-- pi_data = serialized trust.Snapshot (id, prevId, generatedAt, lotlSequence, …).
-- If the newest row already holds this id, that row is replaced in place: its
-- content, generated_at and lotl_sequence become the new ones, while row_id, seq,
-- prev_id and created_at stay as they were. Any other id is a new row, including an
-- id that only an OLDER row holds (the history A, B, A is three rows): only the newest
-- row is ever replaced. Answers snapshotId and replaced (true when a row was replaced).
-- Callers of save_snapshot and sweep_snapshots are serialized by one transaction-level
-- advisory lock (the same key in both), so two saves cannot both read the same newest
-- row and then both insert. The lock is not a table lock: it waits for no open
-- transaction on the table and for no vacuum, and it blocks nothing but these two
-- procedures, so load_latest_snapshot is never held up. A wait for it ends after ten
-- seconds (lock_timeout): the call then fails as trust_anchor:save_snapshot_failed and
-- nothing is written, and the caller can try again.
CREATE OR REPLACE PROCEDURE trust_anchor.save_snapshot(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = trust_anchor, util, pg_temp
SET lock_timeout = '10s'
AS $$
DECLARE
    v_id       text := pi_data->>'id';
    v_newest   text;
    v_replaced boolean := false;
BEGIN
    IF v_id IS NULL OR v_id = '' THEN
        po_data := util.result_error('trust_anchor:invalid', 'snapshot id is required');
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('trust_anchor.snapshot'));

    SELECT row_id INTO v_newest
    FROM trust_anchor.snapshot
    WHERE seq = (SELECT max(seq) FROM trust_anchor.snapshot)
      AND snapshot_id = v_id;

    IF v_newest IS NOT NULL THEN
        UPDATE trust_anchor.snapshot
           SET content       = pi_data,
               generated_at  = COALESCE((pi_data->>'generatedAt')::timestamptz, now()),
               lotl_sequence = COALESCE((pi_data->>'lotlSequence')::bigint, 0)
         WHERE row_id = v_newest;
        v_replaced := true;
    ELSE
        INSERT INTO trust_anchor.snapshot (snapshot_id, prev_id, generated_at, lotl_sequence, content)
        VALUES (
            v_id,
            NULLIF(pi_data->>'prevId', ''),
            COALESCE((pi_data->>'generatedAt')::timestamptz, now()),
            COALESCE((pi_data->>'lotlSequence')::bigint, 0),
            pi_data
        );
    END IF;

    po_data := util.result_success(jsonb_build_object('snapshotId', v_id, 'replaced', v_replaced));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('trust_anchor:save_snapshot_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- trust_anchor.load_latest_snapshot — newest snapshot, or {"snapshot": null}.
-- pi_data is ignored. Returns data = {"snapshot": <full object> | null}; the Go
-- backend treats null as "none persisted yet" → (nil, nil).
CREATE OR REPLACE PROCEDURE trust_anchor.load_latest_snapshot(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = trust_anchor, util, pg_temp
AS $$
DECLARE
    v_content jsonb;
BEGIN
    SELECT content INTO v_content
    FROM trust_anchor.snapshot
    ORDER BY seq DESC
    LIMIT 1;

    po_data := util.result_success(jsonb_build_object('snapshot', v_content));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('trust_anchor:load_snapshot_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- trust_anchor.sweep_snapshots — remove versions that a newer version replaced long ago.
-- pi_data = {"before": <timestamptz>}. A row is removed when it is NOT the newest row
-- and its successor (the row with the next higher seq) was created before that
-- instant: a version leaves once it has been replaced for long enough. The newest row
-- is never removed, whatever the instant. Strictly before: a successor created exactly
-- at the instant keeps the older row. Answers {"removed": <count>}.
-- A missing, null or unreadable instant is refused as trust_anchor:invalid before
-- anything is touched, and so is an instant that is not finite (infinity, -infinity)
-- or is later than twelve hours ago: a version replaced less than twelve hours ago can
-- never be swept, whatever the caller asks. The calling service keeps a longer minimum
-- of its own; this floor is deliberately lower, so a small difference between the
-- service's clock and the database's never refuses a legitimate sweep.
-- Callers are serialized with save_snapshot by the same advisory lock, and a wait for
-- it ends after ten seconds (lock_timeout): the call then fails as
-- trust_anchor:sweep_snapshots_failed and nothing is removed.
CREATE OR REPLACE PROCEDURE trust_anchor.sweep_snapshots(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = trust_anchor, util, pg_temp
SET lock_timeout = '10s'
AS $$
DECLARE
    v_raw     text;
    v_before  timestamptz;
    v_removed bigint;
BEGIN
    v_raw := CASE WHEN jsonb_typeof(pi_data) = 'object' THEN pi_data->>'before' END;
    IF v_raw IS NULL THEN
        po_data := util.result_error('trust_anchor:invalid', 'before is required');
        RETURN;
    END IF;
    BEGIN
        v_before := v_raw::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        po_data := util.result_error('trust_anchor:invalid', 'before is not a time');
        RETURN;
    END;
    IF NOT isfinite(v_before) OR v_before > now() - interval '12 hours' THEN
        po_data := util.result_error('trust_anchor:invalid', 'before must be a finite time at least 12 hours in the past');
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('trust_anchor.snapshot'));

    WITH ordered AS (
        SELECT row_id, lead(created_at) OVER (ORDER BY seq) AS successor_created_at
        FROM trust_anchor.snapshot
    ), removed AS (
        DELETE FROM trust_anchor.snapshot s
        USING ordered o
        WHERE s.row_id = o.row_id
          AND o.successor_created_at IS NOT NULL
          AND o.successor_created_at < v_before
        RETURNING s.row_id
    )
    SELECT count(*) INTO v_removed FROM removed;

    po_data := util.result_success(jsonb_build_object('removed', v_removed));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('trust_anchor:sweep_snapshots_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- trust_anchor.save_bootstrap — append a new approved bootstrap version.
-- pi_data = serialized trust.Bootstrap (version, ojReference, activatedAt, …).
CREATE OR REPLACE PROCEDURE trust_anchor.save_bootstrap(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = trust_anchor, util, pg_temp
AS $$
DECLARE
    v_version int;
BEGIN
    IF pi_data->>'version' IS NULL THEN
        po_data := util.result_error('trust_anchor:invalid', 'bootstrap version is required');
        RETURN;
    END IF;
    v_version := (pi_data->>'version')::int;

    INSERT INTO trust_anchor.bootstrap (version, oj_reference, seeded, activated_at, content)
    VALUES (
        v_version,
        COALESCE(pi_data->>'ojReference', ''),
        COALESCE((pi_data->>'seeded')::boolean, false),
        COALESCE((pi_data->>'activatedAt')::timestamptz, now()),
        pi_data
    );

    po_data := util.result_success(jsonb_build_object('version', v_version));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('trust_anchor:save_bootstrap_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- trust_anchor.load_latest_bootstrap — authoritative bootstrap (highest version,
-- newest write as tiebreaker), or {"bootstrap": null} when none.
CREATE OR REPLACE PROCEDURE trust_anchor.load_latest_bootstrap(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = trust_anchor, util, pg_temp
AS $$
DECLARE
    v_content jsonb;
BEGIN
    SELECT content INTO v_content
    FROM trust_anchor.bootstrap
    ORDER BY version DESC, seq DESC
    LIMIT 1;

    po_data := util.result_success(jsonb_build_object('bootstrap', v_content));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('trust_anchor:load_bootstrap_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- Procedures are owned by the migrating role (implicit ownership) — no explicit
-- OWNER TO, so the script stays owner-name-free and portable across deployments.
-- EXECUTE-only: revoke from PUBLIC, grant only to the service role.
REVOKE ALL ON PROCEDURE trust_anchor.save_snapshot(jsonb, jsonb)         FROM PUBLIC;
REVOKE ALL ON PROCEDURE trust_anchor.load_latest_snapshot(jsonb, jsonb)  FROM PUBLIC;
REVOKE ALL ON PROCEDURE trust_anchor.sweep_snapshots(jsonb, jsonb)       FROM PUBLIC;
REVOKE ALL ON PROCEDURE trust_anchor.save_bootstrap(jsonb, jsonb)        FROM PUBLIC;
REVOKE ALL ON PROCEDURE trust_anchor.load_latest_bootstrap(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE trust_anchor.save_snapshot(jsonb, jsonb)         TO trust_anchor_public;
GRANT EXECUTE ON PROCEDURE trust_anchor.load_latest_snapshot(jsonb, jsonb)  TO trust_anchor_public;
GRANT EXECUTE ON PROCEDURE trust_anchor.sweep_snapshots(jsonb, jsonb)       TO trust_anchor_public;
GRANT EXECUTE ON PROCEDURE trust_anchor.save_bootstrap(jsonb, jsonb)        TO trust_anchor_public;
GRANT EXECUTE ON PROCEDURE trust_anchor.load_latest_bootstrap(jsonb, jsonb) TO trust_anchor_public;
