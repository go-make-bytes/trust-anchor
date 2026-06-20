package ingest

import (
	"context"
	"testing"
	"time"
)

// P2 input-side change detection (spec §6, §14.3). These exercise the sibling
// ".sha2" skip in fetchTerritory: the fixtureTransport serves each TL's ".sha2"
// (via digestURL) with the SHA-256 of that TL fixture — exactly what the
// publisher serves. NextUpdate is set explicitly on the previous snapshot so the
// freshness gate does not depend on the recorded fixture dates.

func futureT() *time.Time { t := time.Now().Add(365 * 24 * time.Hour); return &t }
func pastT() *time.Time   { t := time.Now().Add(-365 * 24 * time.Hour); return &t }

// serveMatchingDigests answers each TL's sibling ".sha2" with the SHA-256 of
// that TL fixture (== what the live publisher serves).
func serveMatchingDigests(t *testing.T, ft *fixtureTransport) {
	t.Helper()
	ft.body[digestURL(lvURL)] = []byte(sha256hex(readTestdata(t, "lv-tsl.xml")))
	ft.body[digestURL(eeURL)] = []byte(sha256hex(readTestdata(t, "ee-tsl.xml")))
}

func TestRefreshSkipsUnchangedTerritoryViaDigest(t *testing.T) {
	ft := newFixtureTransport()
	serveMatchingDigests(t, ft)
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256hex(readTestdata(t, "lv-tsl.xml"))
	if got := snap1.Territory("LV").SourceDigest; got != wantDigest {
		t.Fatalf("LV SourceDigest = %q, want the TL's SHA-256 %q", got, wantDigest)
	}

	// Make the previous territories explicitly fresh, then count only cycle 2.
	prev, err := cloneSnapshot(snap1)
	if err != nil {
		t.Fatal(err)
	}
	prev.Territory("LV").NextUpdate = futureT()
	prev.Territory("EE").NextUpdate = futureT()
	ft.counts = map[string]int{}

	snap2, err := p.Refresh(context.Background(), prev, boot)
	if err != nil {
		t.Fatal(err)
	}

	if ft.counts[lvURL] != 0 {
		t.Errorf("LV TL was re-downloaded (%d) despite a matching .sha2", ft.counts[lvURL])
	}
	if ft.counts[digestURL(lvURL)] == 0 {
		t.Error("LV .sha2 was not fetched (change-detection did not run)")
	}
	lv := snap2.Territory("LV")
	if lv == nil || lv.CarriedOver || len(lv.Anchors) != 5 {
		t.Fatalf("LV not cleanly reused: carriedOver=%v anchors=%d", lv != nil && lv.CarriedOver, len(lv.Anchors))
	}
	if snap2.ID != snap1.ID {
		t.Error("unchanged territories produced a different snapshot ID")
	}
	if !snap2.Diff.Empty() {
		t.Errorf("unchanged cycle produced diff entries: %+v", snap2.Diff.Entries)
	}
}

func TestRefreshRefetchesOnDigestChange(t *testing.T) {
	ft := newFixtureTransport()
	serveMatchingDigests(t, ft)
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := cloneSnapshot(snap1)
	if err != nil {
		t.Fatal(err)
	}
	prev.Territory("LV").NextUpdate = futureT()
	prev.Territory("EE").NextUpdate = futureT()

	// LV now publishes a different.sha2 → the full TL must be re-fetched + verified.
	ft.body[digestURL(lvURL)] = []byte("0000000000000000000000000000000000000000000000000000000000000000")
	ft.counts = map[string]int{}

	snap2, err := p.Refresh(context.Background(), prev, boot)
	if err != nil {
		t.Fatal(err)
	}
	if ft.counts[lvURL] == 0 {
		t.Error("LV TL was not re-downloaded after its .sha2 changed")
	}
	if lv := snap2.Territory("LV"); lv.CarriedOver || len(lv.Anchors) != 5 {
		t.Fatalf("LV after re-fetch: carriedOver=%v anchors=%d", lv.CarriedOver, len(lv.Anchors))
	}
}

func TestRefreshRefetchesPastNextUpdate(t *testing.T) {
	ft := newFixtureTransport()
	serveMatchingDigests(t, ft) // .sha2 matches — but LV is past NextUpdate
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := cloneSnapshot(snap1)
	if err != nil {
		t.Fatal(err)
	}
	prev.Territory("LV").NextUpdate = pastT() // stale → must re-fetch despite matching .sha2
	prev.Territory("EE").NextUpdate = futureT()
	ft.counts = map[string]int{}

	if _, err := p.Refresh(context.Background(), prev, boot); err != nil {
		t.Fatal(err)
	}
	if ft.counts[lvURL] == 0 {
		t.Error("stale LV (past NextUpdate) was not re-fetched despite a matching .sha2 (anti-freeze)")
	}
}
