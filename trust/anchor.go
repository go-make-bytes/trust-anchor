// Package trust holds the domain model of the trust-anchor service: extracted
// CA anchors, versioned snapshots, diffs and bundle filtering. It has no
// HTTP, storage or ingestion dependencies.
package trust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Anchor sources.
const (
	SourceTL      = "tl"
	SourceOverlay = "manual-overlay"
)

// Use names accepted by bundle filters. `authentication` is served as an
// alias of `signature`: eID authentication certificates chain to the same
// CA/QC services as signature certificates and TS 119 612 defines no
// authentication qualifier (see DECISIONS.md). `website` maps
// ForeWebSiteAuthentication (QWACs).
const (
	UseSignature      = "signature"
	UseAuthentication = "authentication"
	UseSeal           = "seal"
	UseWebsite        = "website"
)

// Anchor is one trusted CA certificate extracted from a trusted list (or the
// manual overlay) together with the metadata consumers filter on.
type Anchor struct {
	Territory          string    `json:"territory"`
	Source             string    `json:"source"`
	TSPName            string    `json:"tspName"`
	ServiceName        string    `json:"serviceName"`
	ServiceType        string    `json:"serviceType"`
	Status             string    `json:"status"`
	StatusStartingTime time.Time `json:"statusStartingTime"`

	CertDER           []byte    `json:"certDer"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	Subject           string    `json:"subject"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`

	// Qualifiers are the qualification-extension URIs carried by the service
	// (e.g. QCWithQSCD). QCWithQSCD is also surfaced as a boolean.
	Qualifiers []string `json:"qualifiers,omitempty"`
	QCWithQSCD bool     `json:"qcWithQscd"`
	// Uses lists the uses derived from AdditionalServiceInformation Fore*
	// qualifiers (signature, seal, website). Empty means the service carries
	// no Fore* qualifier and the anchor is included in ALL uses.
	Uses []string `json:"uses,omitempty"`
}

// MatchesUse reports whether the anchor belongs in a bundle filtered by use.
func (a Anchor) MatchesUse(use string) bool {
	if use == "" || len(a.Uses) == 0 {
		return true
	}
	if use == UseAuthentication {
		use = UseSignature
	}
	for _, u := range a.Uses {
		if u == use {
			return true
		}
	}
	return false
}

// Fingerprint computes the lowercase hex SHA-256 of a certificate.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Territory is the per-territory part of a snapshot.
type Territory struct {
	Code       string     `json:"code"`
	TLSequence uint64     `json:"tlSequence"`
	IssueTime  time.Time  `json:"issueTime"`
	NextUpdate *time.Time `json:"nextUpdate,omitempty"`

	// CarriedOver marks fail-safe reuse: this territory's data could not be
	// refreshed and was carried over from the previous snapshot.
	CarriedOver       bool   `json:"carriedOver,omitempty"`
	CarriedOverReason string `json:"carriedOverReason,omitempty"`

	Anchors []Anchor `json:"anchors"`
}

// StaleAt reports whether the territory data is past NextUpdate + grace.
func (t *Territory) StaleAt(now time.Time, grace time.Duration) bool {
	if t.NextUpdate == nil {
		return false
	}
	return now.After(t.NextUpdate.Add(grace))
}

// PendingAnchor is a hold-mode addition awaiting approval.
type PendingAnchor struct {
	Anchor    Anchor    `json:"anchor"`
	FirstSeen time.Time `json:"firstSeen"`
}

// Bootstrap is the active, operator-approved LOTL bootstrap certificate set
// (the OJEU-published trust root of the whole tree).
type Bootstrap struct {
	Version     int       `json:"version"`
	OJReference string    `json:"ojReference"`
	CertsDER    [][]byte  `json:"certsDer"`
	ActivatedAt time.Time `json:"activatedAt"`
	// Seeded marks the install-time seed from LOTL_BOOTSTRAP_CERTS_PATH (as
	// opposed to an approved staged update).
	Seeded bool `json:"seeded,omitempty"`
}

// Certificates parses the bootstrap DER set.
func (b *Bootstrap) Certificates() ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(b.CertsDER))
	for _, der := range b.CertsDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("trust: parse bootstrap certificate: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}

// Fingerprints returns the SHA-256 fingerprints of the bootstrap set.
func (b *Bootstrap) Fingerprints() []string {
	out := make([]string, 0, len(b.CertsDER))
	for _, der := range b.CertsDER {
		sum := sha256.Sum256(der)
		out = append(out, hex.EncodeToString(sum[:]))
	}
	sort.Strings(out)
	return out
}

// PendingBootstrap is a staged (detected + fetched, NOT yet active) OJ
// bootstrap update awaiting out-of-band fingerprint review and approval.
type PendingBootstrap struct {
	OJReference  string    `json:"ojReference"`
	CertsDER     [][]byte  `json:"certsDer"`
	Subjects     []string  `json:"subjects"`
	Fingerprints []string  `json:"fingerprints"`
	DetectedAt   time.Time `json:"detectedAt"`
	// Added/Removed are fingerprint diffs against the active bootstrap set.
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// Snapshot is one versioned, content-addressed trust-anchor state. The active
// snapshot is held in memory and persisted to the snapshot store.
type Snapshot struct {
	ID          string    `json:"id"`
	PrevID      string    `json:"prevId,omitempty"`
	GeneratedAt time.Time `json:"generatedAt"`

	LOTLSequence   uint64     `json:"lotlSequence"`
	LOTLIssueTime  time.Time  `json:"lotlIssueTime"`
	LOTLNextUpdate *time.Time `json:"lotlNextUpdate,omitempty"`
	// LOTLSignersDER is the accumulated LOTL signer set after pivot
	// processing — persisted so restarts don't re-walk pivots.
	LOTLSignersDER [][]byte `json:"lotlSignersDer"`
	// LOTLPivotSeq is the sequence number of the last processed pivot.
	LOTLPivotSeq uint64 `json:"lotlPivotSeq"`
	// AdvertisedOJ is the OJ reference the LOTL scheme information advertises.
	AdvertisedOJ string `json:"advertisedOj,omitempty"`
	// BootstrapOJRef/BootstrapVersion reference the active bootstrap set used.
	BootstrapOJRef   string `json:"bootstrapOjRef,omitempty"`
	BootstrapVersion int    `json:"bootstrapVersion,omitempty"`

	Territories []*Territory `json:"territories"`
	Overlay     []Anchor     `json:"overlay,omitempty"`

	Pending          []PendingAnchor   `json:"pending,omitempty"`
	PendingBootstrap *PendingBootstrap `json:"pendingBootstrap,omitempty"`

	Diff *Diff `json:"diff,omitempty"`
}

// Territory returns the territory entry with the given code, or nil.
func (s *Snapshot) Territory(code string) *Territory {
	for _, t := range s.Territories {
		if t.Code == code {
			return t
		}
	}
	return nil
}

// LOTLSigners parses the persisted LOTL signer set.
func (s *Snapshot) LOTLSigners() ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(s.LOTLSignersDER))
	for _, der := range s.LOTLSignersDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("trust: parse persisted LOTL signer: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}

// EarliestNextUpdate returns the earliest NextUpdate across the LOTL and all
// territories (zero time when none is known). The refresh job honors it.
func (s *Snapshot) EarliestNextUpdate() time.Time {
	var earliest time.Time
	consider := func(t *time.Time) {
		if t == nil || t.IsZero() {
			return
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = *t
		}
	}
	consider(s.LOTLNextUpdate)
	for _, t := range s.Territories {
		consider(t.NextUpdate)
	}
	return earliest
}

// idContent is the deterministic projection of a snapshot that defines its
// content hash: everything that can change what consumers receive. Timestamps
// of generation and stale flags (serve-time derived) are excluded so an
// unchanged refresh keeps the same ID/ETag.
type idContent struct {
	LOTLSequence uint64           `json:"lotlSequence"`
	Territories  []idTerritory    `json:"territories"`
	Overlay      []idAnchor       `json:"overlay,omitempty"`
	Pending      []string         `json:"pending,omitempty"`
}

type idTerritory struct {
	Code       string     `json:"code"`
	TLSequence uint64     `json:"tlSequence"`
	Anchors    []idAnchor `json:"anchors"`
}

type idAnchor struct {
	Fingerprint string   `json:"fp"`
	Status      string   `json:"status"`
	QSCD        bool     `json:"qscd"`
	Uses        []string `json:"uses,omitempty"`
	Source      string   `json:"source"`
}

// ComputeID computes and assigns the snapshot's content hash.
func (s *Snapshot) ComputeID() string {
	content := idContent{LOTLSequence: s.LOTLSequence}
	for _, t := range s.Territories {
		it := idTerritory{Code: t.Code, TLSequence: t.TLSequence}
		for _, a := range t.Anchors {
			it.Anchors = append(it.Anchors, idAnchor{Fingerprint: a.FingerprintSHA256, Status: a.Status, QSCD: a.QCWithQSCD, Uses: a.Uses, Source: a.Source})
		}
		sort.Slice(it.Anchors, func(i, j int) bool { return it.Anchors[i].Fingerprint < it.Anchors[j].Fingerprint })
		content.Territories = append(content.Territories, it)
	}
	sort.Slice(content.Territories, func(i, j int) bool { return content.Territories[i].Code < content.Territories[j].Code })
	for _, a := range s.Overlay {
		content.Overlay = append(content.Overlay, idAnchor{Fingerprint: a.FingerprintSHA256, Status: a.Status, QSCD: a.QCWithQSCD, Uses: a.Uses, Source: a.Source})
	}
	sort.Slice(content.Overlay, func(i, j int) bool { return content.Overlay[i].Fingerprint < content.Overlay[j].Fingerprint })
	for _, p := range s.Pending {
		content.Pending = append(content.Pending, p.Anchor.FingerprintSHA256)
	}
	sort.Strings(content.Pending)

	b, err := json.Marshal(content)
	if err != nil {
		// Marshalling a value of plain structs cannot fail.
		panic(err)
	}
	sum := sha256.Sum256(b)
	s.ID = hex.EncodeToString(sum[:])
	return s.ID
}
