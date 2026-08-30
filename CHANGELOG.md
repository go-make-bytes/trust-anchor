# Changelog

Notable changes to this service, newest first. Dated rather than versioned: the image is
published per branch and commit, so what matters is what landed on a given day. This file is
written for whoever runs the service or integrates against it.

## 2026-08-30

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
