package trust

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-make-bytes/trust-anchor/tsl"
)

// statusBase is the prefix of TS 119 612 service-status URIs; shorthand
// configuration values ("granted") are expanded against it.
const statusBase = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/"

// NormalizeStatus expands a shorthand status name to its full URI.
func NormalizeStatus(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "://") {
		return s
	}
	return statusBase + s
}

// ExtractionWarning records a service that was skipped during extraction.
type ExtractionWarning struct {
	TSPName     string
	ServiceName string
	Reason      string
}

// ExtractAnchors pulls the qualified CA anchors out of a verified national
// trusted list: every TSPService with ServiceTypeIdentifier CA/QC and a
// current status in acceptedStatuses (full URIs). Services whose digital
// identity carries no X.509 certificate are skipped and reported.
func ExtractAnchors(tl *tsl.TrustedList, territory string, acceptedStatuses []string, now time.Time) ([]Anchor, []ExtractionWarning, error) {
	accepted := make(map[string]struct{}, len(acceptedStatuses))
	for _, s := range acceptedStatuses {
		accepted[NormalizeStatus(s)] = struct{}{}
	}

	var anchors []Anchor
	var warnings []ExtractionWarning

	if tl.ProviderList == nil {
		return nil, nil, fmt.Errorf("trust: %s trusted list has no provider list", territory)
	}

	for _, tsp := range tl.ProviderList.Providers {
		tspName := tsp.Information.Name.String()
		for _, svc := range tsp.Services {
			info := svc.Information
			if info.TypeIdentifier != tsl.ServiceTypeCAQC {
				continue
			}
			if _, ok := accepted[info.Status]; !ok {
				continue
			}

			certs, err := info.DigitalIdentity.Certificates()
			if err != nil {
				warnings = append(warnings, ExtractionWarning{TSPName: tspName, ServiceName: info.Name.String(), Reason: "invalid X509 digital identity: " + err.Error()})
				continue
			}
			if len(certs) == 0 {
				warnings = append(warnings, ExtractionWarning{TSPName: tspName, ServiceName: info.Name.String(), Reason: "no X509Certificate digital identity"})
				continue
			}

			qualifiers, uses, qscd := serviceQualifications(info.Extensions)

			for _, cert := range certs {
				anchors = append(anchors, Anchor{
					Territory:          territory,
					Source:             SourceTL,
					TSPName:            tspName,
					ServiceName:        info.Name.String(),
					ServiceType:        info.TypeIdentifier,
					Status:             info.Status,
					StatusStartingTime: info.StatusStartingTime,
					CertDER:            cert.Raw,
					FingerprintSHA256:  Fingerprint(cert),
					Subject:            cert.Subject.String(),
					NotBefore:          cert.NotBefore,
					NotAfter:           cert.NotAfter,
					Qualifiers:         qualifiers,
					QCWithQSCD:         qscd,
					Uses:               uses,
				})
			}
		}
	}

	// Deterministic order: TSP, service, fingerprint.
	sort.Slice(anchors, func(i, j int) bool {
		a, b := anchors[i], anchors[j]
		if a.TSPName != b.TSPName {
			return a.TSPName < b.TSPName
		}
		if a.ServiceName != b.ServiceName {
			return a.ServiceName < b.ServiceName
		}
		return a.FingerprintSHA256 < b.FingerprintSHA256
	})

	// Drop duplicate certificates (the same cert may appear under several
	// service entries); first occurrence wins.
	seen := make(map[string]struct{}, len(anchors))
	dedup := anchors[:0]
	for _, a := range anchors {
		if _, ok := seen[a.FingerprintSHA256]; ok {
			continue
		}
		seen[a.FingerprintSHA256] = struct{}{}
		dedup = append(dedup, a)
	}

	_ = now // reserved for future validity-window filtering; anchors are served as listed
	return dedup, warnings, nil
}

// serviceQualifications maps the service-information extensions to bundle
// metadata: qualification URIs, derived uses and the QCWithQSCD flag.
func serviceQualifications(exts []tsl.Extension) (qualifiers []string, uses []string, qscd bool) {
	addUse := func(u string) {
		for _, e := range uses {
			if e == u {
				return
			}
		}
		uses = append(uses, u)
	}

	for _, ext := range exts {
		if ext.AdditionalServiceInformation != nil {
			switch ext.AdditionalServiceInformation.URI {
			case tsl.ASIForeSignatures:
				addUse(UseSignature)
			case tsl.ASIForeSeals:
				addUse(UseSeal)
			case tsl.ASIForWebSiteAuthentication:
				addUse(UseWebsite)
			}
		}
		if ext.Qualifications != nil {
			for _, qe := range ext.Qualifications.Elements {
				for _, q := range qe.Qualifiers {
					qualifiers = append(qualifiers, q.URI)
					if q.URI == tsl.QualifierQCWithQSCD {
						qscd = true
					}
				}
			}
		}
	}
	sort.Strings(qualifiers)
	return qualifiers, uses, qscd
}
