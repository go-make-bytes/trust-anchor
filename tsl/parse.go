package tsl

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"regexp"
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
	var out []*x509.Certificate
	for _, id := range s.DigitalIDs {
		if id.X509Certificate == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(b64WhiteSpace.ReplaceAllString(id.X509Certificate, ""))
		if err != nil {
			return nil, fmt.Errorf("tsl: decode X509Certificate digital identity: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("tsl: parse X509Certificate digital identity: %w", err)
		}
		out = append(out, cert)
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
	return nil, fmt.Errorf("tsl: no XML trusted-list pointer for territory %q", territory)
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
