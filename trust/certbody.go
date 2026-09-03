package trust

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// certificateBody is the structural view of an X.509 certificate: the
// fields of the TBSCertificate this service actually uses, read with the
// standard ASN.1 decoder and without interpreting the public key. It is how
// an anchor can be held when the cryptographic parser refuses the key — a
// trust anchor is bytes, a fingerprint, a subject, a validity window and
// list metadata; the key belongs to the consumer that builds a chain.
type certificateBody struct {
	Version      int // 1, 2 or 3 as in RFC 5280 (v1 when the field is absent)
	SerialNumber *big.Int
	Issuer       string
	Subject      string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyAlgorithm string
	Curve        string
}

var errNotACertificate = errors.New("trust: not a DER X.509 certificate")

// decodeCertificateBody reads the TBSCertificate structurally: outer
// SEQUENCE, the TBS, then version, serial, signature algorithm, issuer,
// validity, subject and SubjectPublicKeyInfo in RFC 5280 order. Every step
// checks the tag it expects; anything else is an error, never a guess.
// Extensions and the signature are not read — the list's XML signature, not
// the certificate's, is what vouches for an anchor here.
func decodeCertificateBody(der []byte) (*certificateBody, error) {
	var cert asn1.RawValue
	rest, err := asn1.Unmarshal(der, &cert)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNotACertificate, err)
	}
	if len(rest) != 0 || !isSequence(cert) {
		return nil, fmt.Errorf("%w: trailing bytes or not a SEQUENCE", errNotACertificate)
	}
	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(cert.Bytes, &tbs); err != nil || !isSequence(tbs) {
		return nil, fmt.Errorf("%w: tbsCertificate", errNotACertificate)
	}

	body := &certificateBody{Version: 1}
	rest = tbs.Bytes
	var el asn1.RawValue
	if rest, err = asn1.Unmarshal(rest, &el); err != nil {
		return nil, fmt.Errorf("%w: version/serial: %w", errNotACertificate, err)
	}
	if el.Class == asn1.ClassContextSpecific && el.Tag == 0 {
		var v int
		if _, err := asn1.Unmarshal(el.Bytes, &v); err != nil || v < 0 || v > 2 {
			return nil, fmt.Errorf("%w: version", errNotACertificate)
		}
		body.Version = v + 1
		if rest, err = asn1.Unmarshal(rest, &el); err != nil {
			return nil, fmt.Errorf("%w: serial: %w", errNotACertificate, err)
		}
	}
	// el is the serial number.
	body.SerialNumber = new(big.Int)
	if _, err := asn1.Unmarshal(el.FullBytes, &body.SerialNumber); err != nil {
		return nil, fmt.Errorf("%w: serial: %w", errNotACertificate, err)
	}
	// signature AlgorithmIdentifier — skipped, not used.
	if rest, err = asn1.Unmarshal(rest, &el); err != nil || !isSequence(el) {
		return nil, fmt.Errorf("%w: signature algorithm", errNotACertificate)
	}
	// issuer Name
	if rest, err = asn1.Unmarshal(rest, &el); err != nil || !isSequence(el) {
		return nil, fmt.Errorf("%w: issuer", errNotACertificate)
	}
	if body.Issuer, err = rdnString(el.FullBytes); err != nil {
		return nil, fmt.Errorf("%w: issuer: %w", errNotACertificate, err)
	}
	// validity
	if rest, err = asn1.Unmarshal(rest, &el); err != nil || !isSequence(el) {
		return nil, fmt.Errorf("%w: validity", errNotACertificate)
	}
	var validity struct{ NotBefore, NotAfter time.Time }
	if _, err := asn1.Unmarshal(el.FullBytes, &validity); err != nil {
		return nil, fmt.Errorf("%w: validity: %w", errNotACertificate, err)
	}
	body.NotBefore, body.NotAfter = validity.NotBefore.UTC(), validity.NotAfter.UTC()
	// subject Name
	if rest, err = asn1.Unmarshal(rest, &el); err != nil || !isSequence(el) {
		return nil, fmt.Errorf("%w: subject", errNotACertificate)
	}
	if body.Subject, err = rdnString(el.FullBytes); err != nil {
		return nil, fmt.Errorf("%w: subject: %w", errNotACertificate, err)
	}
	// subjectPublicKeyInfo
	var spki asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &spki); err != nil || !isSequence(spki) {
		return nil, fmt.Errorf("%w: subjectPublicKeyInfo", errNotACertificate)
	}
	var alg asn1.RawValue
	if _, err := asn1.Unmarshal(spki.Bytes, &alg); err != nil || !isSequence(alg) {
		return nil, fmt.Errorf("%w: key algorithm", errNotACertificate)
	}
	var oid asn1.ObjectIdentifier
	params, err := asn1.Unmarshal(alg.Bytes, &oid)
	if err != nil {
		return nil, fmt.Errorf("%w: key algorithm: %w", errNotACertificate, err)
	}
	body.KeyAlgorithm, body.Curve = keyAlgorithmName(oid, params)
	return body, nil
}

// rdnString renders a DER Name the way the standard library renders a parsed
// certificate's Subject, so a held anchor's subject reads exactly like a
// parsed one's.
func rdnString(der []byte) (string, error) {
	var rdn pkix.RDNSequence
	rest, err := asn1.Unmarshal(der, &rdn)
	if err != nil {
		return "", err
	}
	if len(rest) != 0 {
		return "", errors.New("trailing bytes after Name")
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdn)
	return name.String(), nil
}
