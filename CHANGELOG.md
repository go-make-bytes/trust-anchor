# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

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
