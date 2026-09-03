// Package response holds the trust-anchor API response DTOs.
package response

import (
	"time"

	"github.com/go-make-bytes/trust-anchor/trust"
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
	Failed            bool       `json:"failed,omitempty"`
	FailureReason     string     `json:"failureReason,omitempty"`
	AnchorCount       int        `json:"anchorCount"`
	// SkippedCount and Skipped name the accepted services of this list whose
	// certificate did not become an anchor — how far the served set is
	// narrower than the list, and why. Health, not content: never part of
	// the snapshot id.
	SkippedCount int                    `json:"skippedCount"`
	Skipped      []trust.SkippedService `json:"skipped,omitempty"`
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
	ID             string                `json:"id"`
	PrevID         string                `json:"prevId,omitempty"`
	GeneratedAt    time.Time             `json:"generatedAt"`
	LOTLSequence   uint64                `json:"lotlSequence"`
	LOTLIssueTime  time.Time             `json:"lotlIssueTime"`
	LOTLNextUpdate *time.Time            `json:"lotlNextUpdate,omitempty"`
	LOTLPivotSeq   uint64                `json:"lotlPivotSeq"`
	AdvertisedOJ   string                `json:"advertisedOj,omitempty"`
	Territories    []TerritorySummary    `json:"territories"`
	InternalCount  int                   `json:"internalCount"`
	Diff           *trust.Diff           `json:"diff,omitempty"`
	Pending        []trust.PendingAnchor `json:"pending,omitempty"`
	Bootstrap      *BootstrapSummary     `json:"bootstrap,omitempty"`
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
			Failed:            t.Failed,
			FailureReason:     t.FailureReason,
			AnchorCount:       len(t.Anchors),
			SkippedCount:      len(t.Skipped),
			Skipped:           t.Skipped,
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

// RefreshDeclared reports the operator-declared half of a refresh: whether
// the declared set changed what is served, and whether its load failed (the
// previous set carried over) with the load error.
type RefreshDeclared struct {
	Changed     bool   `json:"changed"`
	CarriedOver bool   `json:"carriedOver,omitempty"`
	Error       string `json:"error,omitempty"`
}

// RefreshTerritories summarizes the per-territory outcomes of a completed
// ingestion cycle.
type RefreshTerritories struct {
	OK          int      `json:"ok"`
	Failed      []string `json:"failed,omitempty"`
	CarriedOver []string `json:"carriedOver,omitempty"`
}

// RefreshCycle reports the upstream half of a refresh. Territories is
// present only when the cycle completed — a failed cycle produced no
// per-territory outcomes of its own.
type RefreshCycle struct {
	OK          bool                `json:"ok"`
	Error       string              `json:"error,omitempty"`
	Territories *RefreshTerritories `json:"territories,omitempty"`
}

// Refresh is the /v1/refresh response: the two halves of the trigger
// reported separately, so neither outcome can hide the other. Snapshot is
// always the id being served as the route answers.
type Refresh struct {
	Snapshot string          `json:"snapshot"`
	Changed  bool            `json:"changed"`
	Declared RefreshDeclared `json:"declared"`
	Cycle    RefreshCycle    `json:"cycle"`
}

// NewRefresh builds the refresh report. served is the snapshot being served
// as the response is written; cycleErr nil means the cycle completed and the
// per-territory summary is drawn from served.
func NewRefresh(served *trust.Snapshot, changed, declaredChanged, declaredCarriedOver bool, declaredErr string, cycleErr error) *Refresh {
	out := &Refresh{
		Snapshot: served.ID,
		Changed:  changed,
		Declared: RefreshDeclared{Changed: declaredChanged, CarriedOver: declaredCarriedOver, Error: declaredErr},
		Cycle:    RefreshCycle{OK: cycleErr == nil},
	}
	if cycleErr != nil {
		out.Cycle.Error = cycleErr.Error()
		return out
	}
	terr := &RefreshTerritories{}
	for _, t := range served.Territories {
		switch {
		case t.Failed:
			terr.Failed = append(terr.Failed, t.Code)
		case t.CarriedOver:
			terr.CarriedOver = append(terr.CarriedOver, t.Code)
		default:
			terr.OK++
		}
	}
	out.Cycle.Territories = terr
	return out
}

// Approved is the pending-anchor approval endpoint's response.
type Approved struct {
	Snapshot    string `json:"snapshot,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}
