package tsl

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
)

var b64WhiteSpace = regexp.MustCompile(`\s+`)

// Parse unmarshals a TrustServiceStatusList document.
//
// Production callers must only pass bytes returned by Verify — Parse performs
// no signature validation itself. Direct use is for tests and tooling.
func Parse(raw []byte) (*TrustedList, error) {
	var tl TrustedList
	if err := xml.Unmarshal(raw, &tl); err != nil {
		return nil, fmt.Errorf("tsl: parse trusted list: %w", err)
	}
	if tl.SchemeInformation.TSLSequenceNumber == 0 {
		return nil, fmt.Errorf("tsl: document has no TSLSequenceNumber")
	}
	return &tl, nil
}

// Certificates decodes the X509Certificate digital identities, skipping
// non-X509 identity forms (X509SubjectName, X509SKI, KeyValue, …).
func (s ServiceDigitalIdentity) Certificates() ([]*x509.Certificate, error) {
	ders, err := s.CertificateDERs()
	if err != nil {
		return nil, err
	}
	out := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("tsl: parse X509Certificate digital identity: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}

// CertificateDERs decodes the X509Certificate digital identities to their
// DER bytes without parsing them, so a caller can still fingerprint and
// describe a certificate the certificate parser refuses. Non-X509 identity
// forms are skipped as in Certificates.
func (s ServiceDigitalIdentity) CertificateDERs() ([][]byte, error) {
	var out [][]byte
	for _, id := range s.DigitalIDs {
		if id.X509Certificate == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(b64WhiteSpace.ReplaceAllString(id.X509Certificate, ""))
		if err != nil {
			return nil, fmt.Errorf("tsl: decode X509Certificate digital identity: %w", err)
		}
		out = append(out, der)
	}
	return out, nil
}

// PointerFor returns the XML trusted-list pointer for the given territory.
func (tl *TrustedList) PointerFor(territory string) (*TSLPointer, error) {
	for i := range tl.SchemeInformation.PointersToOtherTSL {
		p := &tl.SchemeInformation.PointersToOtherTSL[i]
		if p.Territory() == territory && p.MimeType() == MimeTypeTSLXML {
			return p, nil
		}
	}
	return nil, ErrNoXMLPointer(territory)
}

// ErrNoXMLPointer is the error PointerFor returns for a territory the list
// publishes no XML trusted-list pointer for — exported so a caller holding a
// projection of the pointer set reports the same absence in the same words.
func ErrNoXMLPointer(territory string) error {
	return fmt.Errorf("tsl: no XML trusted-list pointer for territory %q", territory)
}

// Territories returns the territory codes this list publishes XML
// trusted-list pointers for, the list's own self-pointer excluded — for the
// LOTL, that is every country whose trusted list it vouches for. Sorted,
// de-duplicated. Note the codes are the publisher's own (Greece is EL).
func (tl *TrustedList) Territories() []string {
	seen := map[string]struct{}{}
	var out []string
	for i := range tl.SchemeInformation.PointersToOtherTSL {
		p := &tl.SchemeInformation.PointersToOtherTSL[i]
		if p.MimeType() != MimeTypeTSLXML || p.TSLType() == TSLTypeEUListOfTheLists {
			continue
		}
		code := p.Territory()
		if code == "" {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

// SelfPointer returns the LOTL's pointer to itself (TSLType EUlistofthelists),
// which carries the current LOTL signer certificate set.
func (tl *TrustedList) SelfPointer() (*TSLPointer, error) {
	for i := range tl.SchemeInformation.PointersToOtherTSL {
		p := &tl.SchemeInformation.PointersToOtherTSL[i]
		if p.TSLType() == TSLTypeEUListOfTheLists && p.MimeType() == MimeTypeTSLXML {
			return p, nil
		}
	}
	return nil, fmt.Errorf("tsl: LOTL self pointer (TSLType EUlistofthelists) not found")
}
