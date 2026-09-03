package trust

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// oidBrainpoolP256r1 is the named-curve identifier German qualified
// providers' CA certificates carry [RFC 5639 §4.1] — the curve the standard
// library's certificate parser refuses.
var oidBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}

// syntheticECCertDER assembles a structurally valid, unsigned v1 certificate
// whose SubjectPublicKeyInfo names the given curve. The signature bytes are
// arbitrary — certificate parsing never verifies them — so this needs no key
// on the curve: it exists to hand the parser a well-formed certificate with
// a key it cannot interpret, which no certificate-issuing API in the
// standard library can produce.
func syntheticECCertDER(t *testing.T, cn string, curve asn1.ObjectIdentifier) []byte {
	t.Helper()
	curveParams, err := asn1.Marshal(curve)
	if err != nil {
		t.Fatal(err)
	}
	sigAlg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}} // ecdsa-with-SHA256
	name := pkix.Name{CommonName: cn, Organization: []string{"synthetic fixture"}}.ToRDNSequence()

	point := make([]byte, 65)
	point[0] = 0x04
	for i := 1; i < len(point); i++ {
		point[i] = byte(i)
	}
	tbs := struct {
		SerialNumber *big.Int
		Signature    pkix.AlgorithmIdentifier
		Issuer       pkix.RDNSequence
		Validity     struct{ NotBefore, NotAfter time.Time }
		Subject      pkix.RDNSequence
		PublicKey    struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
	}{
		SerialNumber: big.NewInt(7),
		Signature:    sigAlg,
		Issuer:       name,
		Subject:      name,
	}
	tbs.Validity.NotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tbs.Validity.NotAfter = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	tbs.PublicKey.Algorithm = pkix.AlgorithmIdentifier{Algorithm: oidECPublicKey, Parameters: asn1.RawValue{FullBytes: curveParams}}
	tbs.PublicKey.PublicKey = asn1.BitString{Bytes: point, BitLength: len(point) * 8}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{
		TBS:       asn1.RawValue{FullBytes: tbsDER},
		Algorithm: sigAlg,
		Signature: asn1.BitString{Bytes: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, BitLength: 64},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// brainpoolCertDER is the fixture the skip tests share: a certificate Go
// parses up to the key and then refuses. The premise is asserted, so the day
// the standard library learns the curve this fails loudly instead of the
// skip tests passing vacuously.
func brainpoolCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	der := syntheticECCertDER(t, cn, oidBrainpoolP256r1)
	_, err := x509.ParseCertificate(der)
	if err == nil || !strings.Contains(err.Error(), unsupportedCurveMessage) {
		t.Fatalf("test premise: synthetic brainpool certificate parse error = %v, want %q", err, unsupportedCurveMessage)
	}
	return der
}

func selfSigned(t *testing.T, pub, priv any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "control"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestSPKIAlgorithmNamesKeys: the structural read names the key of a
// certificate Go parses (the controls) and of one it refuses (brainpool) the
// same way — and says nothing at all about bytes that are not a certificate.
func TestSPKIAlgorithmNamesKeys(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		der       []byte
		algorithm string
		curve     string
	}{
		{"brainpoolP256r1", brainpoolCertDER(t, "Brainpool CA"), KeyAlgorithmECDSA, "brainpoolP256r1"},
		{"brainpoolP384r1", syntheticECCertDER(t, "BP384", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}), KeyAlgorithmECDSA, "brainpoolP384r1"},
		{"unknown curve OID", syntheticECCertDER(t, "odd", asn1.ObjectIdentifier{1, 2, 3, 4, 5}), KeyAlgorithmECDSA, "1.2.3.4.5"},
		{"P-384 control", selfSigned(t, &ecKey.PublicKey, ecKey), KeyAlgorithmECDSA, "P-384"},
		{"RSA control", selfSigned(t, &rsaKey.PublicKey, rsaKey), KeyAlgorithmRSA, ""},
		{"Ed25519 control", selfSigned(t, edPub, edPriv), KeyAlgorithmEd25519, ""},
		{"not a certificate", []byte{0x30, 0x03, 0x02, 0x01, 0x01}, "", ""},
		{"empty", nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alg, curve := spkiAlgorithm(tc.der)
			if alg != tc.algorithm || curve != tc.curve {
				t.Fatalf("spkiAlgorithm = (%q, %q), want (%q, %q)", alg, curve, tc.algorithm, tc.curve)
			}
		})
	}
}

// FuzzSPKIAlgorithm: the structural read runs on every certificate the
// cryptographic parser refuses, i.e. on exactly the inputs that already
// broke one parser. It must never panic — a defect yields ("", ""), never a
// crash of the ingest cycle.
func FuzzSPKIAlgorithm(f *testing.F) {
	t := &testing.T{}
	bp := syntheticECCertDER(t, "seed", oidBrainpoolP256r1)
	f.Add(bp)
	f.Add(bp[:len(bp)/2])
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = spkiAlgorithm(data)
	})
}
