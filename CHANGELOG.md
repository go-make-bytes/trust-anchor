# Changelog

Notable changes to this service, newest first. Dated rather than versioned: the image is
published per branch and commit, so what matters is what landed on a given day. This file is
written for whoever runs the service or integrates against it.

## 2026-08-31

### Changed

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
