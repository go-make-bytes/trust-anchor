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

// ExtractAnchors pulls the trust anchors out of a verified national trusted
// list: every TSPService whose ServiceTypeIdentifier is in acceptedTypes
// (registered Svctype URIs; empty means CA/QC only) and whose current status
// is accepted. Statuses follow the type's plane: acceptedStatuses names the
// EU-qualified vocabulary (granted/withdrawn, full URIs or shorthand), and a
// national-level service type is matched against the national counterparts
// of the same set — a national-level service never carries granted, so
// admitting the type without translating the statuses would silently drop
// every one of its services. Services of unaccepted types are counted and
// reported, never silently dropped; services whose digital identity carries
// no X.509 certificate are skipped and reported.
func ExtractAnchors(tl *tsl.TrustedList, territory string, acceptedStatuses, acceptedTypes []string, now time.Time) ([]Anchor, []ExtractionWarning, error) {
	accepted := make(map[string]struct{}, len(acceptedStatuses))
	acceptedNational := make(map[string]struct{}, len(acceptedStatuses))
	for _, s := range acceptedStatuses {
		full := NormalizeStatus(s)
		accepted[full] = struct{}{}
		if nat, ok := nationalStatusEquivalent[full]; ok {
			acceptedNational[nat] = struct{}{}
		}
	}
	types := make(map[string]struct{}, len(acceptedTypes))
	for _, st := range acceptedTypes {
		types[st] = struct{}{}
	}
	if len(types) == 0 {
		types[tsl.ServiceTypeCAQC] = struct{}{}
	}

	var anchors []Anchor
	var warnings []ExtractionWarning
	skippedTypes := map[string]int{}

	if tl.ProviderList == nil {
		return nil, nil, fmt.Errorf("trust: %s trusted list has no provider list", territory)
	}

	// Statuses seen per certificate across ALL entries of admitted types
	// (before the acceptance filter): one certificate listed under entries
	// with conflicting statuses is a duplication error in the reading
	// standard — such an anchor must fail closed, not be served on whichever
	// status happens to pass the filter.
	statusesByCert := map[string]map[string]struct{}{}
	for _, tsp := range tl.ProviderList.Providers {
		for _, svc := range tsp.Services {
			info := svc.Information
			if _, ok := types[info.TypeIdentifier]; !ok {
				continue
			}
			certs, err := info.DigitalIdentity.Certificates()
			if err != nil || len(certs) == 0 {
				continue
			}
			for _, cert := range certs {
				fp := Fingerprint(cert)
				if statusesByCert[fp] == nil {
					statusesByCert[fp] = map[string]struct{}{}
				}
				statusesByCert[fp][info.Status] = struct{}{}
			}
		}
	}

	for _, tsp := range tl.ProviderList.Providers {
		tspName := tsp.Information.Name.String()
		for _, svc := range tsp.Services {
			info := svc.Information
			if _, ok := types[info.TypeIdentifier]; !ok {
				skippedTypes[info.TypeIdentifier]++
				continue
			}
			statusOK := false
			if _, ok := accepted[info.Status]; ok {
				statusOK = true
			} else if !qualifiedSvctypes[info.TypeIdentifier] {
				_, statusOK = acceptedNational[info.Status]
			}
			if !statusOK {
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
					// The taxonomy key is DERIVED from the identifier (one
					// type dimension): CA/QC and unkeyed types land on the
					// untyped plane, a keyed identifier lands in its type's
					// bundle exactly like a declared anchor of that type.
					Type: TypeKey(info.TypeIdentifier),
				})
			}
		}
	}

	// Unaccepted service types are reported in aggregate — one warning per
	// distinct type with its count — so a configured set that misses what a
	// list actually carries is visible instead of a silent drop.
	skipped := make([]string, 0, len(skippedTypes))
	for st := range skippedTypes {
		skipped = append(skipped, st)
	}
	sort.Strings(skipped)
	for _, st := range skipped {
		warnings = append(warnings, ExtractionWarning{
			Reason: fmt.Sprintf("skipped %d service(s) with unaccepted service type %s", skippedTypes[st], st),
		})
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

	// One certificate under several service entries is first-class in the
	// reading standard, which classifies the duplication instead of
	// collapsing it: entries that AGREE on status merge (uses, qualifiers
	// and the QSCD flag are unioned — a second entry's metadata is never
	// silently dropped), while conflicting statuses fail the anchor closed
	// with a report — the friendlier half is never served on its own.
	seen := make(map[string]int, len(anchors)) // fingerprint -> index in dedup
	conflicted := map[string]bool{}
	dedup := anchors[:0]
	for _, a := range anchors {
		if len(statusesByCert[a.FingerprintSHA256]) > 1 {
			if !conflicted[a.FingerprintSHA256] {
				conflicted[a.FingerprintSHA256] = true
				warnings = append(warnings, ExtractionWarning{
					TSPName:     a.TSPName,
					ServiceName: a.ServiceName,
					Reason:      fmt.Sprintf("conflicting statuses across duplicate service entries for certificate %s — anchor dropped (fail closed)", a.FingerprintSHA256),
				})
			}
			continue
		}
		if i, ok := seen[a.FingerprintSHA256]; ok {
			dedup[i] = mergeDuplicateAnchor(dedup[i], a)
			continue
		}
		seen[a.FingerprintSHA256] = len(dedup)
		dedup = append(dedup, a)
	}

	_ = now // reserved for future validity-window filtering; anchors are served as listed
	return dedup, warnings, nil
}

// mergeDuplicateAnchor unions the filter-relevant metadata of a duplicate
// service entry into the kept anchor: uses and qualifiers accumulate
// (first-occurrence order, no re-sort — existing single-entry anchors keep
// their serialized shape), and the QSCD flag is an OR.
func mergeDuplicateAnchor(kept, dup Anchor) Anchor {
	for _, u := range dup.Uses {
		found := false
		for _, e := range kept.Uses {
			if e == u {
				found = true
			}
		}
		if !found {
			kept.Uses = append(kept.Uses, u)
		}
	}
	for _, q := range dup.Qualifiers {
		found := false
		for _, e := range kept.Qualifiers {
			if e == q {
				found = true
			}
		}
		if !found {
			kept.Qualifiers = append(kept.Qualifiers, q)
		}
	}
	kept.QCWithQSCD = kept.QCWithQSCD || dup.QCWithQSCD
	return kept
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
					// Both qualifiers sit in the QSCD-positive column of the
					// QSCD determination [ETSI TS 119 615 V1.4.1 §4.5.4]:
					// managed-on-behalf is the remote/cloud-signing shape of
					// "the private key resides in a QSCD".
					if q.URI == tsl.QualifierQCWithQSCD || q.URI == tsl.QualifierQCQSCDManagedOnBehalf {
						qscd = true
					}
				}
			}
		}
	}
	sort.Strings(qualifiers)
	return qualifiers, uses, qscd
}
