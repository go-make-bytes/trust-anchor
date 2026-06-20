//go:build live

package ingest

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/gmb-sig/trust-anchor/events"
)

// TestLiveRefresh runs a full ingestion cycle against the real EU LOTL and
// national TLs over the network. Guarded behind the `live` build tag — CI
// runs fixtures only.
//
//	go test -tags live./ingest/ -run TestLiveRefresh -v
func TestLiveRefresh(t *testing.T) {
	fetcher := NewFetcher(60*time.Second, 20*1024*1024)
	cfg := Config{
		LOTLURL:          "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
		Territories:      []string{"LV", "EE"},
		AcceptedStatuses: []string{"granted"},
		ActivationMode:   ModeAuto,
		StaleGrace:       24 * time.Hour,
	}
	log, _ := zap.NewDevelopment()
	p := NewPipeline(cfg, fetcher, events.New(log), log)

	// Bootstrap from the recorded newest pivot's signer set: a stale seed is
	// fine — the pipeline walks any newer pivots automatically.
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("snapshot %s: LOTL seq %d, pivot %d", snap.ID, snap.LOTLSequence, snap.LOTLPivotSeq)
	for _, tt := range snap.Territories {
		t.Logf("  %s: TL seq %d, %d anchors", tt.Code, tt.TLSequence, len(tt.Anchors))
		if len(tt.Anchors) == 0 {
			t.Errorf("territory %s has no anchors", tt.Code)
		}
	}
}
