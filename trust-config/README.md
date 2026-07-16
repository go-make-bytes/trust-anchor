# trust-config — LOTL signing certificates

The certificates authorised to sign the EU **List of Trusted Lists (LOTL)**. trust-anchor uses them to
validate the LOTL it ingests at first install. They are published in an Official Journal (OJ) notice;
this directory is the operator-managed set that ships with the service.

## Files

- `certs/` — one PEM per authorised signer. The backup, and the source the generator reads.
- `lotl-signers.yaml` — the generated manifest: per signer, `name` / `issuer` / `valid_from` / `valid_to`
  / `sha256_hex` / `sha256_base64` and the embedded PEM. **This is what the service loads.** Generated —
  do not hand-edit.
- `build-lotl-signers.sh` — regenerates `lotl-signers.yaml` from `certs/`.

## How to add or rotate a signer

1. Obtain the signer certificate from the current OJ notice (PEM).
2. **Confirm its SHA-256** against the EU DSS oj-certificates service —
   `https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/oj-certificates`.
   Never trust a certificate whose fingerprint you have not confirmed there.
3. Drop the PEM into `certs/` (one file per signer; remove any the OJ has withdrawn).
4. Regenerate and cross-check:

   ```sh
   ./build-lotl-signers.sh --verify
   ```

   `--verify` re-reads the DSS page and fails if any signer is not present there.
5. Review the diff and commit.

## How the running service picks it up

The image bakes this set in and defaults `LOTL_BOOTSTRAP_CERTS_PATH` to it, so a normal deploy needs no
trust configuration. To apply a newer set *before* a new image is built, mount the updated
`lotl-signers.yaml` and point `LOTL_BOOTSTRAP_CERTS_PATH` at it.

## Provenance of the current set

OJ **C/2026/1944** (retrieved 2026-07-16), 6 signers. Verified two ways: cert #1's SHA-256 matches the
OJ's own published digest (byte-exact), and all six match the DSS oj-certificates service 1:1.
