# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.0

Initial code.

The trust-anchor service as first released: ingests the EU List of Trusted Lists and the
national trusted lists it points to — every list XMLDSig-verified against LOTL-pinned signer
certificates before anything trusts it — and serves the resulting trust anchors over an HTTP
API that consumers cache locally. Per-territory selection including the `EU` group, snapshot
history with per-change writes, and trust-inventory events. MIT.
