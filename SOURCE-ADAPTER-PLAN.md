# P4 — `source_type` adapter migration plan

> Status: **plan + scaffold** (2026-06-15). The interface is defined in
> `source/source.go`; the existing pipeline is **not** migrated yet. This is the
> refactor that turns the LOTL/national-TL ingestion into one adapter model so
> new EUDI sources (P6) are new adapters, not new branches.
> Authoritative design: `TRUST-INFRASTRUCTURE-EVOLUTION-SPEC.md` §5, §14.5.

## Why this is staged (not done blind)

The acceptance bar for P4 is **byte-identical output**: after the refactor, the
LOTL + LV/EE TLs must produce the exact same anchors, snapshot IDs and bundles
as today. That can only be proven against the recorded `testdata/` fixtures with
a build + `go test ./...` loop. It must therefore be done on a machine with the
toolchain — not authored blind. This doc is the runbook for doing it safely.

## Target shape

`source.Source` (see `source/source.go`): `Type() / ID() / Fetch() / Verify() /
Extract()`, plus `source.Type` constants and `source.Raw` (bytes + digest +
sequence for the P2 skip). Registry-shaped sources implement `RegistrySource`
(different verify + an entitlement projection, defined at P6).

```
ingest.Pipeline.Refresh
  └─ for each configured source (by source_type):
       Fetch (digest skip, P2) → Verify (XMLDSig vs pinned signers) → Extract
  └─ assemble snapshot (unchanged)
```

## Migration steps (each independently testable, no behaviour change)

1. **Introduce the interface behind the current code (done — scaffold).** Land
   `source/source.go`. No wiring. `go build ./...` stays green.
2. **National-TL adapter.** Extract today's `fetchTerritory` body into a
   `nationalTLSource` implementing `source.Source` (Type `national-tl`): `Fetch`
   = `AllowURL` + sibling-`.sha2` check (the P2 logic already in `pipeline.go`) +
   `Fetch`; `Verify` = `tsl.VerifyAndParse` vs `ptr.Certificates()`; `Extract` =
   `trust.ExtractAnchors`. Have `ingestTerritory` call the adapter. **Test:**
   `go test ./ingest/...` — anchors/sequences/fixtures unchanged.
3. **LOTL adapter.** Wrap `ingestLOTL` (incl. pivot walking, D2) as an
   `euLOTLSource` (Type `eu-lotl`). This is the delicate one — the signer-set
   precedence and pivot logic (D2/R2) must be preserved exactly; keep
   `walkPivots` as-is and only move the fetch/verify/parse seam. Add the
   LOTL-level `.sha2` skip here **only after** caching the territory pointers
   needed by the territory loop (the deferred half of P2). **Test:** the live
   tag (`go test -tags live ./ingest/`) ingests LOTL seq/pivot unchanged.
4. **Manual overlay + future sources** become `source.Source` /
   `RegistrySource` implementations registered by `source_type`. The pipeline
   iterates a `[]source.Source` instead of hard-coded LOTL+territories.
5. **`source_type` persistence (P4 ↔ P6).** When the multi-source projection
   tables land (spec §4.2 `SOURCE`/`RAW_LIST`), `source_type` becomes a real
   column; until then sources are config-driven and the snapshot stays the
   single serialized blob.

## RP registry (P6, registry-shaped) — open

`rp-registry` (CIR 2025/848) is an **entitlement** registry, not a CA bundle:
RP identity → permitted attributes/purposes, served under `/v1/rp/*`. Its
`Verify`/projection follow the registry's published format (confirm against CIR
2025/848 + the ARF annex before coding). The `Entitlement` type and
`ExtractEntitlements` are intentionally left undefined in the scaffold.

## Acceptance (whole phase)

LOTL + national TLs run through the generic adapter path; `go test ./...` and
`go test -tags live ./ingest/` produce outputs **byte-identical** to
pre-refactor (same anchors, fingerprints, sequences, snapshot IDs). No new
source types are required to pass P4 — they ride on the interface afterwards.
