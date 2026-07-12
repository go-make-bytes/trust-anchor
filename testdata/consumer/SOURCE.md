# Consumer fixture copies

`anchors-pid-lv-v1.json` and `anchors-accessca-eu.json` are byte-for-byte
copies of the go-eudi-trust consumer's recorded mock-contract fixtures:

- Origin: `d:\verifier\repos\go-eudi-trust\testdata\trust\` (that directory
  is READ-ONLY from this repo — never edit it from here; re-copy if the
  consumer's fixtures change).
- Copied: 2026-07-12.

Purpose: field-name conformance (T3, `routes/conformance_test.go`) — every
field NAME present in these fixtures' anchor objects must exist in the
service's serialized `trust.Anchor` JSON, so the consumer's recorded contract
(certDer, fingerprintSha256, tlSequence, etc. — see the consumer repo's own
`testdata/trust/SOURCE.md`) never silently drifts from what this service
actually serves.
