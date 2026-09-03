package trust

import (
	"encoding/asn1"
)

// Public-key algorithm names as reported for a skipped service. The
// vocabulary is the one an anchor will carry once anchors themselves are
// annotated with their key kind; an algorithm outside it is reported by its
// dotted OID so the operator still sees WHAT was refused.
const (
	KeyAlgorithmRSA      = "rsa"
	KeyAlgorithmRSAPSS   = "rsassa-pss"
	KeyAlgorithmECDSA    = "ecdsa"
	KeyAlgorithmEd25519  = "ed25519"
	KeyAlgorithmEd448    = "ed448"
	curveExplicitOrNamed = "explicit" // EC parameters given inline rather than as a named-curve OID
)

var (
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSASSAPSS     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidEd25519       = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidEd448         = asn1.ObjectIdentifier{1, 3, 101, 113}
)

// namedCurves maps the named-curve OIDs a trusted list is likely to carry to
// their common names: the NIST curves (SEC 2 / FIPS 186-4) and the ECC
// Brainpool curves [RFC 5639 §4.1] (arc 1.3.36.3.3.2.8.1.1). A curve outside
// the map is reported by its dotted OID.
var namedCurves = map[string]string{
	"1.3.132.0.33":          "P-224",
	"1.2.840.10045.3.1.7":   "P-256",
	"1.3.132.0.34":          "P-384",
	"1.3.132.0.35":          "P-521",
	"1.3.36.3.3.2.8.1.1.1":  "brainpoolP160r1",
	"1.3.36.3.3.2.8.1.1.2":  "brainpoolP160t1",
	"1.3.36.3.3.2.8.1.1.3":  "brainpoolP192r1",
	"1.3.36.3.3.2.8.1.1.4":  "brainpoolP192t1",
	"1.3.36.3.3.2.8.1.1.5":  "brainpoolP224r1",
	"1.3.36.3.3.2.8.1.1.6":  "brainpoolP224t1",
	"1.3.36.3.3.2.8.1.1.7":  "brainpoolP256r1",
	"1.3.36.3.3.2.8.1.1.8":  "brainpoolP256t1",
	"1.3.36.3.3.2.8.1.1.9":  "brainpoolP320r1",
	"1.3.36.3.3.2.8.1.1.10": "brainpoolP320t1",
	"1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
	"1.3.36.3.3.2.8.1.1.12": "brainpoolP384t1",
	"1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
	"1.3.36.3.3.2.8.1.1.14": "brainpoolP512t1",
}

// spkiAlgorithm names the public-key algorithm (and, for an EC key, the
// curve) of a DER certificate by reading its SubjectPublicKeyInfo
// structurally — the algorithm identifier and its parameters, nothing else.
// It never interprets the key, so it can name what the cryptographic parser
// refused; it is what lets a skipped service say "brainpoolP256r1" instead
// of just "unsupported". Any structural defect on the way to the identifier
// yields two empty strings — a certificate this cannot read is reported
// without key detail, never with a guess.
func spkiAlgorithm(der []byte) (algorithm, curve string) {
	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
	var cert asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &cert); err != nil || len(rest) != 0 || !isSequence(cert) {
		return "", ""
	}
	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(cert.Bytes, &tbs); err != nil || !isSequence(tbs) {
		return "", ""
	}

	// TBSCertificate ::= SEQUENCE { version [0] EXPLICIT OPTIONAL, serialNumber,
	//   signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
	rest := tbs.Bytes
	var el asn1.RawValue
	var err error
	if rest, err = asn1.Unmarshal(rest, &el); err != nil {
		return "", ""
	}
	if el.Class == asn1.ClassContextSpecific && el.Tag == 0 {
		// The explicit version; the serial number follows.
		if rest, err = asn1.Unmarshal(rest, &el); err != nil {
			return "", ""
		}
	}
	// el is now the serial number. Skip signature, issuer, validity, subject.
	for range 4 {
		if rest, err = asn1.Unmarshal(rest, &el); err != nil {
			return "", ""
		}
	}
	// el is the subject; the next element is the SubjectPublicKeyInfo.
	var spki asn1.RawValue
	if _, err = asn1.Unmarshal(rest, &spki); err != nil || !isSequence(spki) {
		return "", ""
	}

	// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
	// AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
	var alg asn1.RawValue
	if _, err = asn1.Unmarshal(spki.Bytes, &alg); err != nil || !isSequence(alg) {
		return "", ""
	}
	var oid asn1.ObjectIdentifier
	params, err := asn1.Unmarshal(alg.Bytes, &oid)
	if err != nil {
		return "", ""
	}

	switch {
	case oid.Equal(oidRSAEncryption):
		return KeyAlgorithmRSA, ""
	case oid.Equal(oidRSASSAPSS):
		return KeyAlgorithmRSAPSS, ""
	case oid.Equal(oidEd25519):
		return KeyAlgorithmEd25519, ""
	case oid.Equal(oidEd448):
		return KeyAlgorithmEd448, ""
	case oid.Equal(oidECPublicKey):
		return KeyAlgorithmECDSA, ecCurveName(params)
	default:
		return oid.String(), ""
	}
}

// ecCurveName names the curve from the EC AlgorithmIdentifier parameters:
// a named-curve OID (the only form the trusted lists carry) maps through
// namedCurves or is reported as its dotted OID; inline (explicit) parameters
// are reported as such; missing or unreadable parameters yield "".
func ecCurveName(params []byte) string {
	if len(params) == 0 {
		return ""
	}
	var curveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &curveOID); err == nil {
		if name, ok := namedCurves[curveOID.String()]; ok {
			return name
		}
		return curveOID.String()
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(params, &raw); err == nil && isSequence(raw) {
		return curveExplicitOrNamed
	}
	return ""
}

func isSequence(v asn1.RawValue) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSequence && v.IsCompound
}
