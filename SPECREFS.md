# Normative references — pinned editions

The standards and legal acts this service implements or cites, with the exact
edition each claim in the source and docs was checked against. Citations in
comments use the bracket form `[ETSI TS 119 612 V2.4.1 §5.5.9.4]` — document,
edition, clause — and resolve against the editions pinned here. For documents
that exist in a single edition (an IETF RFC), the number is the pin.

| Source | Pinned edition | What it governs here |
|---|---|---|
| ETSI TS 119 612 | **V2.4.1** (2025-08) | The trusted-list format: the LOTL/TL XML schema this service parses, the service-type/status/qualifier URIs it matches (incl. the `additionalServiceInformation` URIs §5.5.9.4), and the TL signature profile (Annex B.1) its XML-DSig verification follows. This is the edition Commission Implementing Decision (EU) 2025/2164 mandates for the EU common trusted-list template (applies from 29 April 2026). |
| ETSI TS 119 615 | **V1.4.1** (2026-05) | Procedures for using and interpreting EU Member States' national trusted lists — the deliverable that defines how a relying implementation is to read a trusted list (the half of the standard pair this service's extraction side answers to). |
| ETSI TS 119 602 | **V1.1.1** (2025-11) | Lists of trusted entities (LoTE) — the data model for the second EU machine-readable trust-publication format alongside trusted lists; the trust model here is kept compatible with anchors arriving from either format. |
| Regulation (EU) No 910/2014 (eIDAS) | as amended by Regulation (EU) 2024/1183 | Article 22: the Member-State trusted-list obligation and the Commission's list of trusted lists — the legal basis for what this service ingests. |
| Commission Implementing Decision (EU) 2015/1505 | as amended by CID (EU) 2025/2164 | The implementing act laying down the trusted-list technical specifications and pinning the ETSI TS 119 612 edition above. |
| IETF RFC 5280 | — | X.509 certificate and CRL profile — certificate parsing and validity handling for extracted anchors and pinned signers. |
| W3C XML Signature (xmldsig-core) | as profiled by ETSI TS 119 612 V2.4.1 Annex B.1 | The enveloped-signature verification applied to every list before any content is trusted. |

When an edition here is superseded (ETSI publishes a new version, or an
implementing act re-pins the template), re-check the citations that name the
old edition before bumping the pin — clause numbering moves between editions.
