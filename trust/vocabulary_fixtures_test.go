package trust

// untypedOneAnchor declares one card CA with no type — the A2 untyped plane.
const untypedOneAnchor = `anchors:
  - name: "Demo Card CA"
    territory: lv
    certificate: |
      -----BEGIN CERTIFICATE-----
      MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMB8xHTAbBgNVBAMTFEludGVybmFs
      IFRlc3QgQ0EgT25lMB4XDTI0MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowHzEd
      MBsGA1UEAxMUSW50ZXJuYWwgVGVzdCBDQSBPbmUwWTATBgcqhkjOPQIBBggqhkjO
      PQMBBwNCAARJDZ2MSeXpWnjKmKBX+gVXH9G8RLCsuCR6D9xkpMHHOOVdQS/ien8l
      t9ZIcdtDXCOtruMthLFxb/zNtJ2DoKQRMAoGCCqGSM49BAMCA0gAMEUCIGm8VzIq
      3GWAoclhLI6wKjgV3tFsu7faKU4Ou5y44ZXYAiEA9q13QOWzseqWzpX0yRwABd6g
      n/nizS7hefaHu9j6dHQ=
      -----END CERTIFICATE-----
`

// tslCaAliasAnchor uses the explicit alias for the untyped plane.
const tslCaAliasAnchor = `anchors:
  - name: "Demo Card CA"
    type: tsl_ca
    territory: lv
    certificate: |
      -----BEGIN CERTIFICATE-----
      MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMB8xHTAbBgNVBAMTFEludGVybmFs
      IFRlc3QgQ0EgT25lMB4XDTI0MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowHzEd
      MBsGA1UEAxMUSW50ZXJuYWwgVGVzdCBDQSBPbmUwWTATBgcqhkjOPQIBBggqhkjO
      PQMBBwNCAARJDZ2MSeXpWnjKmKBX+gVXH9G8RLCsuCR6D9xkpMHHOOVdQS/ien8l
      t9ZIcdtDXCOtruMthLFxb/zNtJ2DoKQRMAoGCCqGSM49BAMCA0gAMEUCIGm8VzIq
      3GWAoclhLI6wKjgV3tFsu7faKU4Ou5y44ZXYAiEA9q13QOWzseqWzpX0yRwABd6g
      n/nizS7hefaHu9j6dHQ=
      -----END CERTIFICATE-----
`
