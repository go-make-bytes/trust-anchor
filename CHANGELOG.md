# Changelog

Notable changes to this service, newest first. Dated rather than versioned: the image is
published per branch and commit, so what matters is what landed on a given day. This file is
written for whoever runs the service or integrates against it.

## 2026-08-31

### Added

- **`TRUST_TERRITORIES` understands the group `EU`.** `TRUST_TERRITORIES=EU` expands — per cycle,
  from the freshly **verified** LOTL, never from a hardcoded list — to every territory the LOTL
  publishes an XML trusted-list pointer for: today the 27 member states (Greece under its
  publisher code `EL`, not `GR`) plus IS, LI, NO and UK. Explicit codes combine with the group and
  de-duplicate, so `EU,LV` equals `EU`, and `EU,UA` is legal: a code the LOTL has no pointer for
  is served as a named `failed` territory entry (see below) rather than dropped or fatal — it
  starts working the day a source for it exists. Membership changes in the LOTL flow in on the
  LOTL's own clock, with hold mode (`TRUST_ACTIVATION_MODE=hold`) available if new anchors must
  wait for an operator. The default stays `LV,EE`.

### Changed

- **One broken national trusted list no longer blocks every other territory.** Until now, a
  territory failing with no previous data to fall back on aborted the whole ingestion cycle — on a
  fresh install or after adding a territory, one unreachable list meant *nothing* was ingested.
  (Measured against the real EU set: five of the twenty-seven national lists fail today, each for a
  different reason, so a wide configuration could never complete a first cycle.) Now every
  configured territory is attempted; one that fails with no previous data appears in the snapshot
  as a **failed entry** — named, with the reason, serving zero anchors — while the healthy
  territories are served. The floor stays loud: the LOTL failing, or every configured territory
  failing with nothing to carry over, still fails the whole cycle and keeps the last good snapshot.
  A failed entry does not move the snapshot id, so consumer ETags change only when trust changes.

  **What changes for you:** `GET /v1/snapshot` territory rows may now carry `"failed": true` +
  `"failureReason"`, and a new gauge `trust_territory_failed{territory}` (0/1) is exported for
  alerting. Existing fields are unchanged.

- **`POST /v1/refresh` now reports what actually happened, per half.** Previously an unreachable
  upstream answered `502` with `"refresh failed; last good snapshot still served"` even when the
  operator's declared-source edit *had* been applied and a *new* snapshot was already being served
  — the response said the opposite of the truth on exactly the action (withdrawing or adding a
  declared anchor during an outage) where that is most expensive. The route now answers `200` with
  a per-half report; the `snapshot` field is always the id being served as it answers:

  ```json
  {
    "snapshot": "7c25d7ad…",
    "changed": true,
    "declared": { "changed": true },
    "cycle": { "ok": false, "error": "ingest: fetch LOTL: …" }
  }
  ```

  On a completed cycle, `cycle.territories` summarizes the per-territory outcomes
  (`{ "ok": 26, "failed": ["DE"], "carriedOver": [] }`). The old `snapshot` and `changed` fields
  keep their meaning. `502` remains only for the case with no lie in it: nothing has ever been
  served and the cycle failed, so no snapshot id exists to report. **If you scripted against the
  old `502`-on-any-cycle-failure behaviour, read `cycle.ok` from the body instead**; monitoring
  should alert on the `trust.refresh_failure` event and the `trust_sync_last_success_*` /
  `trust_territory_failed` gauges, which are unchanged.

- **A refused request now says which check it failed — in this service's log, never in the answer**
  (`go-authbyte` v0.20.2). Until now the inbound gate refused with `401` and one undifferentiated
  line: the error naming an expired token, a wrong audience or issuer, a bad signature or an unknown
  key id was discarded, and four separate DPoP failures — proof did not verify, proof key is not the
  token's key, replayed proof, and a token that is not sender-constrained at all — collapsed into a
  single code. An expired service token and a forged one produced identical evidence.

  **What changes for you:** refusals now carry a `refused a request at the auth gate` line at `warn`
  with a `reason` field and the underlying error. **The response is byte-identical** — same status,
  same body, same `WWW-Authenticate` — because telling a caller which check it failed hands an
  attacker half the answer. Nothing to configure, and a request that was going to be accepted is
  unaffected.

  A `DPoP-Nonce` challenge is not a refusal and is unchanged: it is the protocol's own first-request
  handshake, answered `401` with a fresh nonce and retried by the client.

## 2026-08-30

### Changed

- **A trust-anchor addition or removal is now `warning` severity, not `high`.** If you alert on
  `severity: high` for `trust.anchor_change`, that rule stops matching — move it to `warning`.

  These events were stamped `high` and then had their log level quietly capped at `warn`, so the two
  channels disagreed: the line read `warn` while the `severity` field on the same line said `high`.
  A rule reading severity saw something an operator watching levels never did. An anchor appearing
  or disappearing is noteworthy and worth a human looking — but it is the successful, expected
  outcome of a refresh, not a failure, and `warning` is what was meant all along. Both channels now
  say it.

  Nothing else moves: a metadata change stays `info`, a blocked egress stays `high`/`error`, and
  every failure event keeps the level it had. Tests now pin each of those, so the distinction cannot
  drift back unnoticed.

- **Security events emitted from background work — the refresh Tasker — now take `go-sec-events`'
  own background path** (`go-sec-events` v1.2.0, `go-platform-kit` v1.11.0) instead of this service
  writing the sink's log line itself. The library had no entry point for a caller without a request
  — passing one a nil request was a crash — so five services had each copied its field list, and a
  SIEM selects on exactly those names.

  **What else changes in the log stream:** the line now carries an `operation` field when the event
  sets one. The `security_event` message and the field names are unchanged, and the request path is
  untouched. It also closes a latent hole: with the broker sink configured, background events
  previously had nowhere to go at all. This service uses the log sink, so its delivery is unchanged.

### Notes

- **Dependency maintenance only — nothing observable changed.** The framework moved to
  `azugo.io/azugo` and `azugo.io/core` v0.38.0, and the shared libraries to `go-authbyte` v0.20.1, `go-platform-kit` v1.10.0, `go-sec-events` v1.1.4. No route,
  payload, error, environment variable, default or log field is affected, and the image behaves
  exactly as the previous one.

  The platform-kit release is additive on its own side (a size cap for a JetStream stream), and this
  service does not configure one. Recorded here because a deployment that pins image digests will
  see a new build with no accompanying behaviour note otherwise.

## 2026-08-26

### Added

- **`LICENSE` — the service is released under the MIT License**, copyright SIA "Go Make Bytes".
  Nothing in the code or the image changed; this states the terms it is offered under.
- **`SECURITY.md`** — how to report a vulnerability privately (GitHub private vulnerability
  reporting on this repository), what to expect back, and which classes of problem matter most
  for a trust-anchor service.
- **`CONTRIBUTING.md`** — the build-and-test gate a change must pass, and how to propose one.
- **`.gitleaks.toml`** — the secret-scan configuration used by the repository's own checks, with
  one examined finding recorded as not a secret (see Removed).

### Removed

- `SOURCE-ADAPTER-PLAN.md` — an internal planning note that does not belong in a shipped tree.
  The `source/` interface it described is unchanged.
- `testdata/oj-try.txt` — a stray HTML page (a web-application-firewall challenge captured from a
  blocked download) that was never a fixture and was referenced by no test. Its embedded challenge
  token is what a secret scan flagged; it is a public, single-use value, not a credential.

## 2026-08-21

### Fixed

- **`service.version` in the logs now reports the build that is running.** Every log line
  carries that field, and until now it was the compiled-in development default. The pipeline
  had always computed a `<branch>-<short-sha>` version and passed it to the image build, but
  the Dockerfile never handed it to the linker, so the value was computed and then discarded —
  which meant no log line could tell you which build produced it. Both halves are wired now.
  Expect a real version where the development default used to appear.
- Nothing else about the image changed: same entrypoint, same ports, same healthcheck, same
  configuration, same behaviour.

### Notes

- Line endings for Go, module, script and Docker files are pinned to LF. Nothing in the
  repository changes — those files were already stored that way — but a Windows working copy
  now holds the same bytes the pipeline builds from, so a local formatting or lint run stops
  reporting differences that do not exist in CI.
