//go:build live

package ingest

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/go-make-bytes/trust-anchor/events"
)

// TestLiveEUEnumeration ingests the whole EU territory group against the real
// LOTL and national lists and reports every territory's outcome — the
// enumeration that sizes how many of the published lists this verifier can
// actually consume today. Live-tagged: network, real upstreams, no assertions
// on other countries' infrastructure being up — the test fails only if the
// cycle itself fails or nothing at all ingests.
//
//	go test -tags live ./ingest/ -run TestLiveEUEnumeration -v
func TestLiveEUEnumeration(t *testing.T) {
	fetcher := NewFetcher(60*time.Second, 20*1024*1024)
	cfg := Config{
		LOTLURL:              "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
		Territories:          []string{"EU"},
		AllowHTTPTerritories: []string{"SK"},
		AcceptedStatuses:     []string{"granted"},
		ActivationMode:       ModeAuto,
		StaleGrace:           24 * time.Hour,
	}
	log, _ := zap.NewDevelopment()
	p := NewPipeline(cfg, fetcher, events.New(log), log)

	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	healthy, failed := 0, 0
	for _, tt := range snap.Territories {
		if tt.Failed {
			failed++
			t.Logf("FAILED %s: %s", tt.Code, tt.FailureReason)
			continue
		}
		healthy++
		t.Logf("ok     %s: TL seq %d, %d anchors", tt.Code, tt.TLSequence, len(tt.Anchors))
	}
	t.Logf("EU group: %d territories, %d healthy, %d failed", len(snap.Territories), healthy, failed)
	if healthy == 0 {
		t.Fatal("no territory ingested at all")
	}
}
