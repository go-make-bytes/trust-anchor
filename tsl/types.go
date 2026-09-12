// Package tsl parses and verifies ETSI TS 119 612 trusted lists (the EU LOTL
// and national TLs).
//
// Verification model: XML signatures are validated against a pinned set of
// expected signer certificates (OJEU bootstrap + pivot accumulation for the
// LOTL, LOTL pointer certs for national TLs) — never via arbitrary chain
// building. Production code must only parse bytes returned by Verify.
package tsl

import (
	"crypto/x509"
	"encoding/xml"
	"time"
)

// Namespace URIs used by trusted lists.
const (
	NS           = "http://uri.etsi.org/02231/v2#"
	NSAdditional = "http://uri.etsi.org/02231/v2/additionaltypes#"
	NSSie        = "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"
)

// Well-known TSL identifier URIs (ETSI TS 119 612).
const (
	TSLTypeEUListOfTheLists = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
	TSLTypeEUGeneric        = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"

	MimeTypeTSLXML = "application/vnd.etsi.tsl+xml"

	ServiceTypeCAQC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"

	StatusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"

	QualifierQCWithQSCD = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"
	// QualifierQCQSCDManagedOnBehalf marks a QSCD managed on the subscriber's
	// behalf (remote/cloud qualified signing) — QSCD-positive in the QSCD
	// determination exactly like QCWithQSCD.
	QualifierQCQSCDManagedOnBehalf = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf"

	ASIForeSignatures           = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures"
	ASIForeSeals                = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals"
	ASIForWebSiteAuthentication = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication"
)

// TrustedList is the parsed TrustServiceStatusList document (LOTL, pivot or
// national TL — all share the schema).
type TrustedList struct {
	XMLName           xml.Name          `xml:"http://uri.etsi.org/02231/v2# TrustServiceStatusList"`
	SchemeInformation SchemeInformation `xml:"SchemeInformation"`
	ProviderList      *ProviderList     `xml:"TrustServiceProviderList"`
}

type SchemeInformation struct {
	TSLVersionIdentifier int           `xml:"TSLVersionIdentifier"`
	TSLSequenceNumber    uint64        `xml:"TSLSequenceNumber"`
	TSLType              string        `xml:"TSLType"`
	SchemeTerritory      string        `xml:"SchemeTerritory"`
	SchemeInformationURI URIList       `xml:"SchemeInformationURI"`
	ListIssueDateTime    time.Time     `xml:"ListIssueDateTime"`
	NextUpdate           NextUpdate    `xml:"NextUpdate"`
	PointersToOtherTSL   []TSLPointer  `xml:"PointersToOtherTSL>OtherTSLPointer"`
	SchemeOperatorName   LocalizedText `xml:"SchemeOperatorName"`
}

type NextUpdate struct {
	DateTime *time.Time `xml:"dateTime"`
}

type URIList struct {
	URI []string `xml:"URI"`
}

// TSLPointer is an OtherTSLPointer entry: the location of another trusted
// list plus the certificates it is expected to be signed with.
type TSLPointer struct {
	ServiceDigitalIdentities []ServiceDigitalIdentity `xml:"ServiceDigitalIdentities>ServiceDigitalIdentity"`
	TSLLocation              string                   `xml:"TSLLocation"`
	AdditionalInformation    []OtherInformation       `xml:"AdditionalInformation>OtherInformation"`
}

type OtherInformation struct {
	TSLType         string `xml:"TSLType"`
	SchemeTerritory string `xml:"SchemeTerritory"`
	MimeType        string `xml:"http://uri.etsi.org/02231/v2/additionaltypes# MimeType"`
}

type ServiceDigitalIdentity struct {
	DigitalIDs []DigitalID `xml:"DigitalId"`
}

type DigitalID struct {
	X509Certificate string `xml:"X509Certificate"`
	X509SubjectName string `xml:"X509SubjectName"`
	X509SKI         string `xml:"X509SKI"`
}

type ProviderList struct {
	Providers []Provider `xml:"TrustServiceProvider"`
}

type Provider struct {
	Information ProviderInformation `xml:"TSPInformation"`
	Services    []Service           `xml:"TSPServices>TSPService"`
}

type ProviderInformation struct {
	Name      LocalizedText `xml:"TSPName"`
	TradeName LocalizedText `xml:"TSPTradeName"`
}

type Service struct {
	Information ServiceInformation `xml:"ServiceInformation"`
}

type ServiceInformation struct {
	TypeIdentifier     string                 `xml:"ServiceTypeIdentifier"`
	Name               LocalizedText          `xml:"ServiceName"`
	DigitalIdentity    ServiceDigitalIdentity `xml:"ServiceDigitalIdentity"`
	Status             string                 `xml:"ServiceStatus"`
	StatusStartingTime time.Time              `xml:"StatusStartingTime"`
	Extensions         []Extension            `xml:"ServiceInformationExtensions>Extension"`
}

type Extension struct {
	Critical                     bool            `xml:"Critical,attr"`
	AdditionalServiceInformation *ASI            `xml:"AdditionalServiceInformation"`
	Qualifications               *Qualifications `xml:"http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/# Qualifications"`
}

type ASI struct {
	URI string `xml:"URI"`
}

type Qualifications struct {
	Elements []QualificationElement `xml:"QualificationElement"`
}

type QualificationElement struct {
	Qualifiers []Qualifier `xml:"Qualifiers>Qualifier"`
}

type Qualifier struct {
	URI string `xml:"uri,attr"`
}

// LocalizedText is a multilingual name list.
type LocalizedText struct {
	Names []LocalizedName `xml:"Name"`
}

type LocalizedName struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}

// String returns the English name when present, otherwise the first one.
func (t LocalizedText) String() string {
	for _, n := range t.Names {
		if n.Lang == "en" {
			return n.Value
		}
	}
	if len(t.Names) > 0 {
		return t.Names[0].Value
	}
	return ""
}

// Certificates decodes all X509Certificate digital identities of the pointer.
func (p TSLPointer) Certificates() ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, sdi := range p.ServiceDigitalIdentities {
		certs, err := sdi.Certificates()
		if err != nil {
			return nil, err
		}
		out = append(out, certs...)
	}
	return out, nil
}

// CertificateDERs decodes the pointer's X509Certificate digital identities to
// DER without parsing them (see ServiceDigitalIdentity.CertificateDERs), for a
// caller that carries the expected signer set across cycles and parses it
// only where it is used.
func (p TSLPointer) CertificateDERs() ([][]byte, error) {
	var out [][]byte
	for _, sdi := range p.ServiceDigitalIdentities {
		ders, err := sdi.CertificateDERs()
		if err != nil {
			return nil, err
		}
		out = append(out, ders...)
	}
	return out, nil
}

// Territory returns the SchemeTerritory advertised in AdditionalInformation.
func (p TSLPointer) Territory() string {
	for _, oi := range p.AdditionalInformation {
		if oi.SchemeTerritory != "" {
			return oi.SchemeTerritory
		}
	}
	return ""
}

// MimeType returns the list MIME type advertised in AdditionalInformation.
func (p TSLPointer) MimeType() string {
	for _, oi := range p.AdditionalInformation {
		if oi.MimeType != "" {
			return oi.MimeType
		}
	}
	return ""
}

// TSLType returns the pointer's advertised TSLType.
func (p TSLPointer) TSLType() string {
	for _, oi := range p.AdditionalInformation {
		if oi.TSLType != "" {
			return oi.TSLType
		}
	}
	return ""
}
