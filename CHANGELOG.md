# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.4.0

### Changed — anchors whose key the parser cannot interpret are held, and served on request

v0.3.0 named the twelve German CA/QC services whose certificates this service could not turn
into anchors because their public keys are on a Brainpool curve. This release **holds them**:
when the certificate parser refuses a certificate for that one reason, the certificate body is
read structurally — subject, validity, key algorithm and curve, the raw bytes and their
fingerprint — and the anchor is stored like any other. Nothing this service does with an anchor
needs the key; the key belongs to the consumer that builds a chain. Every other parse failure (a
legacy encoding defect, a broken value) is still a skip.

**What you receive does not change unless you ask.** Both anchor routes gain a `keys` filter:

- `keys=common` — **the default** — serves only anchors whose key every mainstream X.509 stack
  parses: RSA (including keys identified as RSASSA-PSS), ECDSA on the NIST P-curves, Ed25519. This
  is byte-for-byte the bundle v0.3.0 served. A consumer that rejects a bundle on the first
  certificate it cannot parse is safe on the default.
- `keys=all` — adds the held anchors. Ask for it only from a consumer that can verify
  Brainpool-curve chains or skips certificates it cannot parse.
- Any other value answers `422`, like an unknown `use` or `type`.

Every anchor on `/v1/anchors.json` now names its key — `keyAlgorithm` (`rsa`, `rsassa-pss`, `ecdsa`,
`ed25519`, or the dotted OID of anything else) and, for ECDSA, `curve` (`P-256` … `brainpoolP256r1` …).
The six German anchors whose keys are RSASSA-PSS-identified, served all along with a key no Go
consumer can use, are named for what they are. Anchors persisted by an earlier release carry the
fields from their next refresh cycle.

```json
{ "territory": "DE", "tspName": "D-Trust GmbH", "serviceName": "D-Trust remote signature service (sign-me)",
  "fingerprintSha256": "23395de6…", "subject": "CN=D-TRUST …,O=D-Trust GmbH,C=DE",
  "keyAlgorithm": "ecdsa", "curve": "brainpoolP256r1", … }
```

`GET /v1/snapshot` gains `heldCount` per territory (Germany: 12), and its `skipped` list no longer
carries those services — the `reason` set shrinks to `invalid-certificate`, `no-certificate`,
`status-conflict`; `trust_services_skipped` for Germany drops to 0. The trusted-list metadata,
statuses, qualifiers and uses of a held anchor come from the list exactly as for a parsed one.

**Two effects to expect once.** Held anchors are trust content, so the snapshot id — and every
consumer's `ETag` — moves once at the first cycle after this release, and the refresh emits one
`trust.anchor_change` (added) event per held anchor. Both are the change being reported, not a
fault.

The structural reader is exercised on real German certificates (a brainpoolP256r1 CA, an
RSASSA-PSS-keyed CA, and a legacy certificate with a negatively encoded modulus that must stay
refused), checked field for field against the standard library on every recorded anchor, and
fuzzed.

## v0.3.0

### Added — a service the bundle is missing is now reported, not silent

An accepted trust service whose certificate cannot become an anchor used to leave one warning
line in the ingest log and nothing else: the territory reported healthy, its anchor count looked
right, and a certificate authority the member state trusts was simply absent from the bundle.
The known case is Germany, where twelve granted CA/QC services (D-Trust, Deutsche Telekom, DGN,
medisign, Atos) carry Brainpool-curve keys the certificate parser refuses — Germany served 81
anchors and no signal said the list declares 93.

Skipped services are now **data**, in three places:

- **`GET /v1/snapshot`** — every territory carries `skippedCount` and, when non-zero, a `skipped`
  list naming each service: `tspName`, `serviceName`, `reason`, `detail` (the parser's message),
  `fingerprintSha256` (over the certificate bytes as listed), and `keyAlgorithm` / `curve` when the
  certificate's structure could still be read. `reason` is a closed set — `unsupported-key`,
  `invalid-certificate`, `no-certificate`, `status-conflict`. The snapshot id and consumer ETags do
  **not** move for a change in the skipped set (it is health, not trust content — the same rule as
  `failed`), but the served snapshot is updated and persisted when it changes.

  ```json
  { "code": "DE", "tlSequence": 159, "anchorCount": 81, "skippedCount": 12,
    "skipped": [ { "tspName": "D-Trust GmbH",
                   "serviceName": "D-Trust remote signature service (sign-me)",
                   "reason": "unsupported-key",
                   "detail": "invalid X509 digital identity: x509: unsupported elliptic curve",
                   "fingerprintSha256": "23395de6…", "keyAlgorithm": "ecdsa", "curve": "brainpoolP256r1" }, … ] }
  ```

- **`trust_services_skipped{territory,reason}`** — a gauge beside `trust_territory_failed`, counting
  the skipped services per territory and reason; it drops to 0 when they vanish. Alert on a
  *change*: a new value means a curve or encoding has started eating anchors, or the known gap has
  closed.
- **The trust-inventory log line** names each skipped service (`skipped_count`, `skipped_services`).

The per-service ingest log line keeps its text and gains `skip_reason`, `fingerprint`,
`key_algorithm` and `curve` fields. One behaviour change rides along: a service listing several
certificates now loses only the unparseable one, not all of them (no list this service ingests has
such a service today, so nothing served changes). The README's *Known limitations* now states the
unsupported-key limitation; holding those anchors is the next release's work.

### Changed — the default territory set is the whole EU

`TRUST_TERRITORIES` now defaults to `EU`: with the variable unset, the service ingests every
national trusted list the verified List of Trusted Lists points to (the member states, the EEA
countries and the UK today, on the LOTL's own clock). It used to default to `LV,EE`, a choice that
suited one deployment and silently narrowed everyone else's. A deployment that sets the variable
explicitly is unaffected; one that relied on the old default now serves a much larger bundle and
should set `TRUST_TERRITORIES=LV,EE` if it wants the previous behaviour. The first cycle over the
whole group takes about a minute.

### Changed — the upstream User-Agent names the project

List hosts now see `trust-anchor/1.0 (EU trusted-list ingester; +https://github.com/go-make-bytes/trust-anchor)`
on every fetch, so an operator reading their access log can tell what the client is and where it
comes from. The previous string carried the name of the deployment the service was first written
for. Nothing else about fetching changed.

## v0.2.0

### Fixed — the German trusted list verifies

Germany signs its trusted list with an RSASSA-PSS signature method whose parameters are implied
by the algorithm identifier (`…xmldsig-more#sha256-rsa-MGF1`) rather than spelled out in the
signature, and its scheme-operator certificates state their public key as id-RSASSA-PSS. The XML
signature library this service verifies with recognised neither, so `DE` was served as a named
failed territory with zero anchors while the rest of the group ingested normally. It verifies now:
a live EU-group cycle reads Germany's list at sequence 159 and contributes **81 trust anchors**.

Nothing changed in the API or the configuration. Running with `TRUST_TERRITORIES=EU` you get one
more healthy territory and a larger anchor bundle than before. Nothing previously trusted is
withdrawn — a list that cannot be verified never contributed anchors in the first place.

### Changed — stricter RSASSA-PSS conformance

From the same library update: the salt length a signature declares is now enforced, an unknown
parameter digest is refused instead of being treated as SHA-256, and unsupported mask-generation
functions and trailer fields are rejected outright. Every list this service ingests today passes.
A publisher whose signature is non-conformant in one of those ways becomes a named failed
territory rather than being accepted — the same handling any unverifiable list gets.

## v0.1.0

Initial code.

The trust-anchor service as first released: ingests the EU List of Trusted Lists and the
national trusted lists it points to — every list XMLDSig-verified against LOTL-pinned signer
certificates before anything trusts it — and serves the resulting trust anchors over an HTTP
API that consumers cache locally. Per-territory selection including the `EU` group, snapshot
history with per-change writes, and trust-inventory events. MIT.
