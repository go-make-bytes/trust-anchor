#!/bin/sh
# Build lotl-signers.yaml from the certificate PEMs in ./certs/.
#
# The LOTL-signing certificates are the certificates authorised to sign the EU
# List of Trusted Lists (LOTL). They are published in an Official Journal (OJ)
# notice; each is kept here as a PEM under certs/ — the backup, and the source
# this script reads. The script derives a human-readable manifest (name, issuer,
# validity, SHA-256 in hex and base64) and embeds each PEM, so the YAML reads
# clearly and never has to be hand-edited.
#
# Usage:
#   ./build-lotl-signers.sh            regenerate lotl-signers.yaml from certs/
#   ./build-lotl-signers.sh --verify   also cross-check each SHA-256 against the
#                                       EU DSS oj-certificates service (best-effort)
#
# Add / rotate a signer: drop its PEM into certs/, re-run, review the diff, commit.
set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
CERTS="$DIR/certs"
OUT="$DIR/lotl-signers.yaml"
OJ_REF="${LOTL_OJ_REF:-C/2026/1944}"
RETRIEVED="${LOTL_RETRIEVED:-$(date +%Y-%m-%d)}"
DSS_URL="https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/oj-certificates"

iso() { date -d "$1" +%Y-%m-%d 2>/dev/null || printf '%s' "$1"; }
yq()  { printf '"%s"' "$(printf '%s' "$1" | sed 's/"/\\"/g')"; }

[ -d "$CERTS" ] || { echo "no certs/ directory at $CERTS" >&2; exit 1; }

tmp="$OUT.tmp"
{
  echo "# LOTL-signing certificates — the certs authorised to sign the EU List of Trusted Lists (LOTL)."
  echo "# Source: Official Journal $OJ_REF. Confirm each cert's SHA-256 against the EU DSS oj-certificates"
  echo "# service before trusting a change. GENERATED from certs/*.pem by build-lotl-signers.sh — do not"
  echo "# hand-edit; to add or rotate a signer, drop its PEM in certs/ and re-run. See README.md."
  echo "oj_reference: $OJ_REF"
  echo "retrieved: $RETRIEVED"
  echo "signers:"
  for c in "$CERTS"/*.pem; do
    [ -e "$c" ] || { echo "no *.pem files in certs/" >&2; exit 1; }
    S=$(openssl x509 -in "$c" -noout -subject -nameopt sep_multiline)
    cn=$(printf '%s\n' "$S" | sed -n 's/^ *CN=//p' | head -1)
    org=$(printf '%s\n' "$S" | sed -n 's/^ *O=//p' | head -1)
    email=$(printf '%s\n' "$S" | sed -n 's/^ *emailAddress=//p' | head -1)
    if [ -n "$org" ] && [ "$cn" = "$org" ] && [ -n "$email" ]; then
      name="$cn (${email%%@*})"
    else
      name="$cn"
    fi
    icn=$(openssl x509 -in "$c" -noout -issuer -nameopt sep_multiline | sed -n 's/^ *CN=//p' | head -1)
    vf=$(iso "$(openssl x509 -in "$c" -noout -startdate | sed 's/notBefore=//')")
    vt=$(iso "$(openssl x509 -in "$c" -noout -enddate  | sed 's/notAfter=//')")
    sha=$(openssl x509 -in "$c" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
    b64=$(openssl x509 -in "$c" -outform DER | openssl dgst -sha256 -binary | openssl base64)
    echo "  - name: $(yq "$name")"
    echo "    issuer: $(yq "$icn")"
    echo "    valid_from: $vf"
    echo "    valid_to: $vt"
    echo "    sha256_hex: $sha"
    echo "    sha256_base64: $b64"
    echo "    certificate: |"
    sed 's/^/      /' "$c"
  done
} > "$tmp"
mv "$tmp" "$OUT"
echo "wrote $OUT ($(grep -c '^  - name:' "$OUT") signers)"

[ "${1:-}" = "--verify" ] || exit 0

echo "cross-checking each signer against DSS ..."
dss=$(curl -fsSL --max-time 30 "$DSS_URL" 2>/dev/null \
      | grep -oiE '([0-9a-f]{2} ){31}[0-9a-f]{2}' | tr -d ' ' | tr 'A-F' 'a-f' | sort -u)
[ -n "$dss" ] || { echo "WARN: DSS page unreadable (network / WAF?) — cross-check skipped" >&2; exit 0; }
miss=0
for c in "$CERTS"/*.pem; do
  sha=$(openssl x509 -in "$c" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
  if printf '%s\n' "$dss" | grep -qx "$sha"; then
    echo "  ok   $sha"
  else
    echo "  MISS $sha  ($(basename "$c")) — not on DSS"; miss=1
  fi
done
[ "$miss" = 0 ] && echo "all signers confirmed on DSS" || { echo "MISMATCH — review before commit" >&2; exit 1; }
