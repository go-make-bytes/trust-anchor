package response

import (
	"testing"
	"time"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// TestNewSnapshotInternalCount proves the internal anchor count wiring
// (INTERNAL_TRUST_SOURCE, alongside the existing OverlayCount) reaches the
// /v1/snapshot response DTO.
func TestNewSnapshotInternalCount(t *testing.T) {
	snap := &trust.Snapshot{
		Internal: []trust.Anchor{
			{Source: trust.SourceInternal, FingerprintSHA256: "aaaa"},
			{Source: trust.SourceInternal, FingerprintSHA256: "bbbb"},
		},
	}
	snap.ComputeID()

	out := NewSnapshot(snap, nil, time.Now().UTC(), time.Hour)
	if out.InternalCount != 2 {
		t.Errorf("InternalCount = %d, want 2", out.InternalCount)
	}
	if out.OverlayCount != 0 {
		t.Errorf("OverlayCount = %d, want 0 (no overlay configured)", out.OverlayCount)
	}
}
