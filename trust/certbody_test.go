package trust

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-make-bytes/trust-anchor/tsl"
)

// Three certificates lifted from the German trusted list (sequence 159,
// fetched 2026-09-03) — the shapes this decoder exists for, in kilobytes:
//
//   - de-caqc-brainpoolp256r1.der: D-Trust GmbH, "D-Trust remote signature
//     service (sign-me)", granted CA/QC, ECDSA on brainpoolP256r1 — the
//     standard library refuses the key; this must be held.
//   - de-caqc-rsassa-pss.der: D-Trust GmbH, "D-Trust qualified signature
//     card", granted CA/QC, SubjectPublicKeyInfo algorithm id-RSASSA-PSS —
//     the standard library parses it (to a nil key); the structural read
//     must agree with it field for field and name the key.
//   - de-legacy-negative-modulus.der: Bundesnetzagentur "3R-CA 1:PN",
//     deprecated national root, RSA modulus encoded as a negative INTEGER,
//     RIPEMD-160 signature — a legacy encoding defect the standard library
//     rightly refuses, for a reason that is NOT the unsupported-curve one;
//     it must stay a skip, never be held.
func readDER(t *testing.T, name string) []byte {
	t.Helper()
	der, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestDecodeCertificateBodyRealBrainpool(t *testing.T) {
	der := readDER(t, "de-caqc-brainpoolp256r1.der")
	_, err := x509.ParseCertificate(der)
	if err == nil || !strings.Contains(err.Error(), unsupportedCurveMessage) {
		t.Fatalf("premise: standard library parse error = %v, want %q", err, unsupportedCurveMessage)
	}
	body, err := decodeCertificateBody(der)
	if err != nil {
		t.Fatal(err)
	}
	if body.KeyAlgorithm != KeyAlgorithmECDSA || body.Curve != "brainpoolP256r1" {
		t.Fatalf("key = (%q, %q)", body.KeyAlgorithm, body.Curve)
	}
	if body.Version != 3 || body.SerialNumber == nil || body.SerialNumber.Sign() <= 0 {
		t.Fatalf("version=%d serial=%v", body.Version, body.SerialNumber)
	}
	if !strings.Contains(body.Subject, "O=D-Trust GmbH") || !strings.Contains(body.Subject, "C=DE") {
		t.Fatalf("subject = %q", body.Subject)
	}
	if body.NotBefore.IsZero() || body.NotAfter.IsZero() || !body.NotAfter.After(body.NotBefore) ||
		body.NotBefore.Before(time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("validity = %s … %s", body.NotBefore, body.NotAfter)
	}
	if fingerprintDER(der) != "23395de6fc5613f3464cc0e430d9adba1b636d58cc50bcdda529c2683c1ca6f0" {
		t.Fatalf("fixture fingerprint drifted: %s", fingerprintDER(der))
	}
}

// The structural read must say exactly what the standard library says for
// every certificate the library parses — subject rendering, validity,
// version, serial — otherwise a held anchor and a parsed anchor would
// describe the same kind of certificate differently. Checked on the
// RSASSA-PSS German anchor and on every anchor certificate of the recorded
// LV and EE lists.
func TestDecodeCertificateBodyAgreesWithParser(t *testing.T) {
	var ders [][]byte
	ders = append(ders, readDER(t, "de-caqc-rsassa-pss.der"))
	for _, name := range []string{"lv-tsl.xml", "ee-tsl.xml"} {
		tl := parseFixture(t, name)
		for _, tsp := range tl.ProviderList.Providers {
			for _, svc := range tsp.Services {
				d, err := svc.Information.DigitalIdentity.CertificateDERs()
				if err != nil {
					t.Fatal(err)
				}
				ders = append(ders, d...)
			}
		}
	}
	if len(ders) < 20 {
		t.Fatalf("only %d certificates to compare", len(ders))
	}
	pss := 0
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("premise: fixture certificate does not parse: %v", err)
		}
		body, err := decodeCertificateBody(der)
		if err != nil {
			t.Fatalf("%s: %v", cert.Subject, err)
		}
		if body.Subject != cert.Subject.String() || body.Issuer != cert.Issuer.String() {
			t.Fatalf("names differ:\n body %q / %q\n x509 %q / %q", body.Subject, body.Issuer, cert.Subject.String(), cert.Issuer.String())
		}
		if !body.NotBefore.Equal(cert.NotBefore) || !body.NotAfter.Equal(cert.NotAfter) {
			t.Fatalf("%s: validity differs: body %s…%s x509 %s…%s", cert.Subject, body.NotBefore, body.NotAfter, cert.NotBefore, cert.NotAfter)
		}
		if body.Version != cert.Version || body.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Fatalf("%s: version/serial differ: body %d/%v x509 %d/%v", cert.Subject, body.Version, body.SerialNumber, cert.Version, cert.SerialNumber)
		}
		if body.KeyAlgorithm == "" {
			t.Fatalf("%s: no key algorithm named", cert.Subject)
		}
		if body.KeyAlgorithm == KeyAlgorithmRSAPSS {
			pss++
			if cert.PublicKey != nil {
				t.Fatalf("premise: the standard library now interprets RSASSA-PSS keys — revisit KeyCommon")
			}
		}
	}
	if pss != 1 {
		t.Fatalf("RSASSA-PSS fixtures seen = %d, want 1", pss)
	}
}

// A legacy encoding defect stays a skip: the parser refuses it for a reason
// other than the curve, so the structural fallback is never consulted and
// the service is reported as invalid-certificate with its key named.
func TestLegacyDefectIsSkippedNotHeld(t *testing.T) {
	der := readDER(t, "de-legacy-negative-modulus.der")
	_, err := x509.ParseCertificate(der)
	if err == nil || strings.Contains(err.Error(), unsupportedCurveMessage) {
		t.Fatalf("premise: parse error = %v, want a non-curve refusal", err)
	}
	// The structural read CAN describe it — that is not the question; the
	// trigger is.
	if body, berr := decodeCertificateBody(der); berr != nil || body.KeyAlgorithm != KeyAlgorithmRSA {
		t.Fatalf("structural read = %+v, %v", body, berr)
	}
	sdi := tsl.ServiceDigitalIdentity{DigitalIDs: []tsl.DigitalID{{X509Certificate: base64.StdEncoding.EncodeToString(der)}}}
	ids, warnings := serviceIdentities("Bundesnetzagentur", "3R-CA 1:PN", sdi)
	if len(ids) != 0 {
		t.Fatalf("held %d identities, want 0", len(ids))
	}
	if len(warnings) != 1 || warnings[0].Code != SkipInvalidCertificate || warnings[0].KeyAlgorithm != KeyAlgorithmRSA ||
		warnings[0].FingerprintSHA256 != fingerprintDER(der) || !strings.Contains(warnings[0].Reason, err.Error()) {
		t.Fatalf("warnings = %+v", warnings)
	}
}

// The synthetic edge shapes real lists do not carry: explicit EC parameters,
// an unknown named curve, a v1 body — and bytes that are not a certificate.
func TestDecodeCertificateBodyEdges(t *testing.T) {
	v1 := syntheticECCertDER(t, "v1", oidBrainpoolP256r1)
	body, err := decodeCertificateBody(v1)
	if err != nil || body.Version != 1 || body.Curve != "brainpoolP256r1" || body.Subject != "CN=v1,O=synthetic fixture" {
		t.Fatalf("v1 body = %+v, %v", body, err)
	}
	odd := syntheticECCertDER(t, "odd", asn1.ObjectIdentifier{1, 2, 3, 4, 5})
	if body, err := decodeCertificateBody(odd); err != nil || body.Curve != "1.2.3.4.5" {
		t.Fatalf("unknown curve body = %+v, %v", body, err)
	}
	for _, bad := range [][]byte{nil, {0x30, 0x03, 0x02, 0x01, 0x01}, v1[:len(v1)/2], append(append([]byte{}, v1...), 0x00)} {
		if _, err := decodeCertificateBody(bad); err == nil {
			t.Fatalf("decoded %d bytes that are not a certificate", len(bad))
		}
	}
}

// FuzzDecodeCertificateBody: the decoder runs on every certificate the
// cryptographic parser refuses — exactly the inputs that already broke one
// parser. It must never panic; a defect is an error, never a crash of the
// ingest cycle. Seeds: the three real German shapes, the synthetic one, a
// truncation.
func FuzzDecodeCertificateBody(f *testing.F) {
	for _, name := range []string{"de-caqc-brainpoolp256r1.der", "de-caqc-rsassa-pss.der", "de-legacy-negative-modulus.der"} {
		der, err := os.ReadFile(filepath.Join("..", "testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(der)
		f.Add(der[:len(der)/3])
	}
	t := &testing.T{}
	f.Add(syntheticECCertDER(t, "seed", oidBrainpoolP256r1))
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = decodeCertificateBody(data)
		_, _ = spkiAlgorithm(data)
	})
}
