// Package response holds the trust-anchor API response DTOs.
package response

import (
	"time"

	"github.com/gmb-sig/trust-anchor/trust"
)

// Anchors is the /v1/anchors.json response.
type Anchors struct {
	Snapshot    string         `json:"snapshot"`
	GeneratedAt time.Time      `json:"generatedAt"`
	Stale       bool           `json:"stale"`
	Anchors     []trust.Anchor `json:"anchors"`
}

// NewAnchors builds the JSON bundle response.
func NewAnchors(snap *trust.Snapshot, anchors []trust.Anchor, stale bool) *Anchors {
	if anchors == nil {
		anchors = []trust.Anchor{}
	}
	return &Anchors{
		Snapshot:    snap.ID,
		GeneratedAt: snap.GeneratedAt,
		Stale:       stale,
		Anchors:     anchors,
	}
}

// TerritorySummary summarizes one territory in the snapshot response.
type TerritorySummary struct {
	Code              string     `json:"code"`
	TLSequence        uint64     `json:"tlSequence"`
	IssueTime         time.Time  `json:"issueTime"`
	NextUpdate        *time.Time `json:"nextUpdate,omitempty"`
	Stale             bool       `json:"stale"`
	CarriedOver       bool       `json:"carriedOver,omitempty"`
	CarriedOverReason string     `json:"carriedOverReason,omitempty"`
	AnchorCount       int        `json:"anchorCount"`
}

// BootstrapSummary describes the active OJEU bootstrap set.
type BootstrapSummary struct {
	Version      int       `json:"version"`
	OJReference  string    `json:"ojReference"`
	ActivatedAt  time.Time `json:"activatedAt"`
	Fingerprints []string  `json:"fingerprints"`
	Seeded       bool      `json:"seeded,omitempty"`
}

// Snapshot is the /v1/snapshot response.
type Snapshot struct {
	ID               string                `json:"id"`
	PrevID           string                `json:"prevId,omitempty"`
	GeneratedAt      time.Time             `json:"generatedAt"`
	LOTLSequence     uint64                `json:"lotlSequence"`
	LOTLIssueTime    time.Time             `json:"lotlIssueTime"`
	LOTLNextUpdate   *time.Time            `json:"lotlNextUpdate,omitempty"`
	LOTLPivotSeq     uint64                `json:"lotlPivotSeq"`
	AdvertisedOJ     string                `json:"advertisedOj,omitempty"`
	Territories      []TerritorySummary    `json:"territories"`
	OverlayCount     int                   `json:"overlayCount"`
	InternalCount    int                   `json:"internalCount"`
	Diff      *trust.Diff           `json:"diff,omitempty"`
	Pending   []trust.PendingAnchor `json:"pending,omitempty"`
	Bootstrap *BootstrapSummary     `json:"bootstrap,omitempty"`
}

// NewSnapshot builds the snapshot summary response.
func NewSnapshot(snap *trust.Snapshot, boot *trust.Bootstrap, now time.Time, grace time.Duration) *Snapshot {
	out := &Snapshot{
		ID:             snap.ID,
		PrevID:         snap.PrevID,
		GeneratedAt:    snap.GeneratedAt,
		LOTLSequence:   snap.LOTLSequence,
		LOTLIssueTime:  snap.LOTLIssueTime,
		LOTLNextUpdate: snap.LOTLNextUpdate,
		LOTLPivotSeq:   snap.LOTLPivotSeq,
		AdvertisedOJ:   snap.AdvertisedOJ,
		OverlayCount:   len(snap.Overlay),
		InternalCount:  len(snap.Internal),
		Diff:           snap.Diff,
		Pending:        snap.Pending,
	}
	for _, t := range snap.Territories {
		out.Territories = append(out.Territories, TerritorySummary{
			Code:              t.Code,
			TLSequence:        t.TLSequence,
			IssueTime:         t.IssueTime,
			NextUpdate:        t.NextUpdate,
			Stale:             t.StaleAt(now, grace),
			CarriedOver:       t.CarriedOver,
			CarriedOverReason: t.CarriedOverReason,
			AnchorCount:       len(t.Anchors),
		})
	}
	if boot != nil {
		out.Bootstrap = &BootstrapSummary{
			Version:      boot.Version,
			OJReference:  boot.OJReference,
			ActivatedAt:  boot.ActivatedAt,
			Fingerprints: boot.Fingerprints(),
			Seeded:       boot.Seeded,
		}
	}
	return out
}

// Refresh is the /v1/refresh response.
type Refresh struct {
	Snapshot string `json:"snapshot"`
	Changed  bool   `json:"changed"`
}

// Approved is the pending-anchor approval endpoint's response.
type Approved struct {
	Snapshot    string `json:"snapshot,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}
