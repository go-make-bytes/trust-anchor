-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 go-make-bytes contributors

-- V2: fold the repeated rows of one snapshot id into one row per version.
--
-- From this version on, saving the id the newest row already holds replaces that row
-- in place (R__trust_anchor_procedures.sql), so the table keeps one row for each
-- version. Databases written by the earlier procedure hold the same id many times
-- over, one row for every save. This folds them the way in-place saves would have
-- left them.
--
-- A run is a stretch of NEIGHBOURING rows (by seq) with the same snapshot_id. The
-- same id seen again after a different one starts a new run: the history A, A, B, A
-- is three runs, not two. In each run:
--   * the NEWEST row stays, with its own content (the latest save is what is served);
--   * it takes the run's FIRST created_at and FIRST prev_id, which in-place saves
--     leave untouched;
--   * the other rows of the run are deleted.
-- The newest row of the table is the newest row of its run, so it is the same row
-- with the same content before and after.
--
-- Safe on an empty table, on one row, and to replay: a table with no repeated
-- neighbours has only one-row runs, and nothing is updated or deleted.
--
-- The count of rows removed is printed as a notice (0 on an empty table, on one row
-- and on a replay).

DO $$
DECLARE
    v_removed bigint;
BEGIN
WITH marked AS (
    SELECT row_id, seq, snapshot_id, prev_id, created_at,
           -- rows of one run share this value: the position in the whole history minus
           -- the position among the rows of the same id
           row_number() OVER (ORDER BY seq)
             - row_number() OVER (PARTITION BY snapshot_id ORDER BY seq) AS run_no
      FROM trust_anchor.snapshot
), runs AS (
    SELECT row_id, seq,
           min(seq) OVER w                              AS first_seq,
           max(seq) OVER w                              AS last_seq,
           first_value(created_at) OVER (w ORDER BY seq) AS first_created_at,
           first_value(prev_id)    OVER (w ORDER BY seq) AS first_prev_id
      FROM marked
    WINDOW w AS (PARTITION BY snapshot_id, run_no)
), kept AS (
    UPDATE trust_anchor.snapshot s
       SET created_at = r.first_created_at,
           prev_id    = r.first_prev_id
      FROM runs r
     WHERE s.row_id = r.row_id
       AND r.seq = r.last_seq
       AND r.first_seq < r.last_seq
    RETURNING s.row_id
), gone AS (
    DELETE FROM trust_anchor.snapshot s
     USING runs r
     WHERE s.row_id = r.row_id
       AND r.seq < r.last_seq
    RETURNING s.row_id
)
SELECT count(*) INTO v_removed FROM gone;

RAISE NOTICE 'trust_anchor.snapshot: folded % repeated row(s) into their runs', v_removed;
END $$;
