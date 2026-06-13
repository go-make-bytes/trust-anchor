package ingest

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/gmb-sig/trust-anchor/events"
	"github.com/gmb-sig/trust-anchor/trust"
	"github.com/gmb-sig/trust-anchor/tsl"
)

// Live URLs as recorded in the fixtures.
const (
	lotlURL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
	lvURL   = "https://trustlist.gov.lv/tsl/latvian-tsl.xml"
	eeURL   = "https://sr.riik.ee/tsl/estonian-tsl.xml"
)

// fixtureTransport serves recorded fixtures for the real URLs — the pipeline
// runs hermetically against genuine signed content.
type fixtureTransport struct {
	files  map[string]string // URL -> testdata file
	body   map[string][]byte // URL -> raw body override
	status map[string]int    // URL -> status override
	counts map[string]int    // URL -> number of fetches observed
}

func newFixtureTransport() *fixtureTransport {
	return &fixtureTransport{
		files: map[string]string{
			lotlURL: "eu-lotl.xml",
			lvURL:   "lv-tsl.xml",
			eeURL:   "ee-tsl.xml",
			"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-282.xml": "eu-lotl-pivot-282.xml",
			"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-300.xml": "eu-lotl-pivot-300.xml",
			"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-335.xml": "eu-lotl-pivot-335.xml",
			"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-341.xml": "eu-lotl-pivot-341.xml",
			"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-378.xml": "eu-lotl-pivot-378.xml",
		},
		body:   map[string][]byte{},
		status: map[string]int{},
		counts: map[string]int{},
	}
}

// pivotFetches returns the total number of pivot-file fetches observed.
func (t *fixtureTransport) pivotFetches() int {
	n := 0
	for url, c := range t.counts {
		if strings.Contains(url, "eu-lotl-pivot-") {
			n += c
		}
	}
	return n
}

func (t *fixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	t.counts[url]++
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: req}

	if code, ok := t.status[url]; ok {
		resp.StatusCode = code
		resp.Body = io.NopCloser(strings.NewReader("error"))
		return resp, nil
	}
	if body, ok := t.body[url]; ok {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}
	if file, ok := t.files[url]; ok {
		b, err := os.ReadFile(filepath.Join("..", "testdata", file))
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(b))
		return resp, nil
	}
	resp.StatusCode = http.StatusNotFound
	resp.Body = io.NopCloser(strings.NewReader("not found"))
	return resp, nil
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixtureBootstrap builds a bootstrap from the signer set a recorded pivot
// publishes (its EU self-pointer).
func fixtureBootstrap(t *testing.T, pivotFile string) *trust.Bootstrap {
	t.Helper()
	tl, err := tsl.Parse(readTestdata(t, pivotFile))
	if err != nil {
		t.Fatal(err)
	}
	self, err := tl.SelfPointer()
	if err != nil {
		t.Fatal(err)
	}
	certs, err := self.Certificates()
	if err != nil {
		t.Fatal(err)
	}
	b := &trust.Bootstrap{Version: 1, OJReference: "C/2026/1944", ActivatedAt: time.Now().UTC(), Seeded: true}
	for _, c := range certs {
		b.CertsDER = append(b.CertsDER, c.Raw)
	}
	return b
}

func testPipeline(t *testing.T, ft *fixtureTransport, mode string) *Pipeline {
	t.Helper()
	fetcher := NewFetcher(10*time.Second, 20*1024*1024)
	fetcher.SetTransport(ft)
	cfg := Config{
		LOTLURL:          lotlURL,
		Territories:      []string{"LV", "EE"},
		AcceptedStatuses: []string{"granted"},
		ActivationMode:   mode,
		HoldAutoRelease:  72 * time.Hour,
		StaleGrace:       24 * time.Hour,
	}
	return NewPipeline(cfg, fetcher, events.New(zap.NewNop()), zap.NewNop())
}

func TestRefreshFullCycle(t *testing.T) {
	p := testPipeline(t, newFixtureTransport(), ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}

	if snap.LOTLSequence != 388 {
		t.Errorf("LOTL sequence = %d, want 388", snap.LOTLSequence)
	}
	if snap.LOTLPivotSeq != 378 {
		t.Errorf("pivot seq = %d, want 378", snap.LOTLPivotSeq)
	}
	if snap.AdvertisedOJ != "C/2026/1944" {
		t.Errorf("advertised OJ = %q", snap.AdvertisedOJ)
	}
	if snap.PendingBootstrap != nil {
		t.Error("unexpected staged bootstrap (advertised OJ matches active)")
	}

	lv := snap.Territory("LV")
	ee := snap.Territory("EE")
	if lv == nil || ee == nil {
		t.Fatal("missing territory data")
	}
	if len(lv.Anchors) != 5 {
		t.Errorf("LV anchors = %d, want 5", len(lv.Anchors))
	}
	if len(ee.Anchors) != 11 {
		t.Errorf("EE anchors = %d, want 11", len(ee.Anchors))
	}
	if lv.TLSequence != 51 || ee.TLSequence != 73 {
		t.Errorf("TL sequences LV=%d EE=%d, want 51/73", lv.TLSequence, ee.TLSequence)
	}
	if snap.ID == "" {
		t.Error("snapshot has no content hash")
	}
	if d := snap.Diff; d.Empty() || len(d.Entries) != 16 {
		t.Errorf("first-snapshot diff entries = %d, want 16 additions", len(snap.Diff.Entries))
	}

	// Second cycle with unchanged upstream: identical content hash.
	snap2, err := p.Refresh(context.Background(), snap, boot)
	if err != nil {
		t.Fatal(err)
	}
	if snap2.ID != snap.ID {
		t.Error("unchanged upstream produced a different snapshot ID")
	}
	if !snap2.Diff.Empty() {
		t.Errorf("unchanged upstream produced diff entries: %+v", snap2.Diff.Entries)
	}
}

// TestRefreshWalksPivotChain seeds the persisted signer state with the
// output set of the OLDEST pivot (as if pivot 282 was the last one
// processed); the pipeline must walk 300→378 and then verify the LOTL.
// On first run with no LV/EE history, territory ingestion must still work.
func TestRefreshWalksPivotChain(t *testing.T) {
	p := testPipeline(t, newFixtureTransport(), ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-282.xml")
	prev := &trust.Snapshot{LOTLSequence: 282, LOTLPivotSeq: 282, LOTLSignersDER: boot.CertsDER}

	snap, err := p.Refresh(context.Background(), prev, boot)
	if err != nil {
		t.Fatal(err)
	}
	if snap.LOTLSequence != 388 || snap.LOTLPivotSeq != 378 {
		t.Errorf("sequence=%d pivotSeq=%d, want 388/378", snap.LOTLSequence, snap.LOTLPivotSeq)
	}
}

func TestRefreshFailSafeOnTerritoryError(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	good, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}

	// Upstream LV starts failing: 500, then garbage, then tampered content —
	// the last good LV data must be carried over each time.
	cases := []func(){
		func() { ft.status[lvURL] = 500 },
		func() { delete(ft.status, lvURL); ft.body[lvURL] = []byte("<garbage") },
		func() {
			raw := readTestdata(t, "lv-tsl.xml")
			ft.body[lvURL] = bytes.Replace(raw, []byte("granted"), []byte("granteX"), 1)
		},
	}
	for i, mutate := range cases {
		mutate()
		snap, err := p.Refresh(context.Background(), good, boot)
		if err != nil {
			t.Fatalf("case %d: cycle failed instead of carrying over: %v", i, err)
		}
		lv := snap.Territory("LV")
		if lv == nil || !lv.CarriedOver {
			t.Fatalf("case %d: LV not carried over", i)
		}
		if len(lv.Anchors) != 5 {
			t.Fatalf("case %d: carried LV anchors = %d, want 5", i, len(lv.Anchors))
		}
		if ee := snap.Territory("EE"); ee.CarriedOver {
			t.Fatalf("case %d: EE unexpectedly carried over", i)
		}
	}
}

func TestRefreshFailsWhenLOTLUnavailableAndNoPrev(t *testing.T) {
	ft := newFixtureTransport()
	ft.status[lotlURL] = 500
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	if _, err := p.Refresh(context.Background(), nil, boot); err == nil {
		t.Fatal("cycle succeeded with LOTL unavailable")
	}
}

func TestRefreshFailsOnFirstRunTerritoryError(t *testing.T) {
	ft := newFixtureTransport()
	ft.status[lvURL] = 500
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	// No previous data to fall back on — a partial first snapshot must never
	// be produced.
	if _, err := p.Refresh(context.Background(), nil, boot); err == nil {
		t.Fatal("cycle produced a partial first snapshot")
	}
}

func TestRefreshRejectsSequenceRegression(t *testing.T) {
	p := testPipeline(t, newFixtureTransport(), ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	good, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}

	// LOTL regression: previous snapshot claims a newer LOTL.
	prev, err := cloneSnapshot(good)
	if err != nil {
		t.Fatal(err)
	}
	prev.LOTLSequence = 999
	if _, err := p.Refresh(context.Background(), prev, boot); err == nil {
		t.Fatal("LOTL sequence regression accepted")
	}

	// National TL regression: carried over (fail-safe), not accepted.
	prev2, err := cloneSnapshot(good)
	if err != nil {
		t.Fatal(err)
	}
	prev2.Territory("LV").TLSequence = 999
	snap, err := p.Refresh(context.Background(), prev2, boot)
	if err != nil {
		t.Fatal(err)
	}
	if lv := snap.Territory("LV"); !lv.CarriedOver || lv.TLSequence != 999 {
		t.Fatal("TL sequence regression was accepted instead of carried over")
	}
}

func TestRefreshHoldMode(t *testing.T) {
	p := testPipeline(t, newFixtureTransport(), ModeHold)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	// First snapshot is the baseline — no held additions.
	base, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Pending) != 0 {
		t.Fatalf("baseline has %d pending anchors", len(base.Pending))
	}

	// Simulate one LV anchor being new: remove it from the previous active
	// set. In hold mode it must land in pending, not in the bundle.
	prev, err := cloneSnapshot(base)
	if err != nil {
		t.Fatal(err)
	}
	lv := prev.Territory("LV")
	removedFP := lv.Anchors[0].FingerprintSHA256
	lv.Anchors = lv.Anchors[1:]

	snap, err := p.Refresh(context.Background(), prev, boot)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Pending) != 1 || snap.Pending[0].Anchor.FingerprintSHA256 != removedFP {
		t.Fatalf("pending = %+v, want exactly %s", snap.Pending, removedFP)
	}
	if len(snap.Territory("LV").Anchors) != 4 {
		t.Fatalf("held anchor still in bundle: %d LV anchors", len(snap.Territory("LV").Anchors))
	}

	// Auto-release: pending entry older than the hold window is promoted.
	aged, err := cloneSnapshot(snap)
	if err != nil {
		t.Fatal(err)
	}
	aged.Pending[0].FirstSeen = time.Now().Add(-100 * time.Hour)
	released, err := p.Refresh(context.Background(), aged, boot)
	if err != nil {
		t.Fatal(err)
	}
	if len(released.Pending) != 0 {
		t.Fatal("aged pending anchor was not auto-released")
	}
	if len(released.Territory("LV").Anchors) != 5 {
		t.Fatalf("auto-released anchor missing from bundle: %d LV anchors", len(released.Territory("LV").Anchors))
	}
}

func TestRefreshRemovalAppliesImmediatelyInHoldMode(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeHold)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	base, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate an upstream removal: previous active set claims an extra
	// anchor that the fresh TL no longer lists.
	prev, err := cloneSnapshot(base)
	if err != nil {
		t.Fatal(err)
	}
	extra := prev.Territory("EE").Anchors[0]
	extra.Territory = "LV"
	prev.Territory("LV").Anchors = append(prev.Territory("LV").Anchors, extra)

	snap, err := p.Refresh(context.Background(), prev, boot)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(snap.Territory("LV").Anchors); got != 5 {
		t.Fatalf("removal did not apply immediately: %d LV anchors, want 5", got)
	}
	var removed bool
	for _, e := range snap.Diff.Entries {
		if e.Kind == trust.DiffRemoved && e.Fingerprint == extra.FingerprintSHA256 {
			removed = true
		}
	}
	if !removed {
		t.Fatal("removal missing from diff")
	}
}

func TestRefreshOverlay(t *testing.T) {
	dir := t.TempDir()

	// Write one of the fixture LOTL signer certs as the overlay PEM.
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	certs, err := boot.Certificates()
	if err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(dir, "demo.pem")
	if err := os.WriteFile(pemPath, pemEncode(certs[0].Raw), 0o600); err != nil {
		t.Fatal(err)
	}

	p := testPipeline(t, newFixtureTransport(), ModeAuto)
	p.cfg.ExtraAnchorsPath = pemPath

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Overlay) != 1 {
		t.Fatalf("overlay anchors = %d, want 1", len(snap.Overlay))
	}
	if snap.Overlay[0].Source != trust.SourceOverlay {
		t.Errorf("overlay source = %q", snap.Overlay[0].Source)
	}
	// Overlay appears in the diff like any other anchor.
	var inDiff bool
	for _, e := range snap.Diff.Entries {
		if e.Territory == "overlay" && e.Source == trust.SourceOverlay {
			inDiff = true
		}
	}
	if !inDiff {
		t.Error("overlay anchor missing from diff")
	}
}

// TestRefreshNewBootstrapSupersedesPreviousSigners covers D13/R2: bootstrap
// re-approval is the disaster-recovery path — when the operator activates a
// NEWER bootstrap, the cycle must start from it (and reset the pivot
// position) instead of continuing from the previous snapshot's signer set.
//
// Setup: the previous snapshot carries an obsolete signer set (pivot 282's)
// while claiming the pivot chain is fully processed (seq 378) — so the
// pre-R2 code path (prefer prev signers, no pivots left to walk) cannot
// verify the LOTL at all and the cycle would fail. With R2, the newly
// approved bootstrap (pivot 378's set, version 2) takes precedence and the
// cycle succeeds.
func TestRefreshNewBootstrapSupersedesPreviousSigners(t *testing.T) {
	p := testPipeline(t, newFixtureTransport(), ModeAuto)

	obsolete := fixtureBootstrap(t, "eu-lotl-pivot-282.xml") // version 1
	prev := &trust.Snapshot{
		LOTLSequence:     388,
		LOTLPivotSeq:     378, // chain "fully processed" — nothing left to walk
		LOTLSignersDER:   obsolete.CertsDER,
		BootstrapVersion: obsolete.Version,
	}

	bootNew := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	bootNew.Version = 2 // operator re-approved a newer OJ bootstrap

	snap, err := p.Refresh(context.Background(), prev, bootNew)
	if err != nil {
		t.Fatalf("cycle must succeed via the newly approved bootstrap: %v", err)
	}
	if snap.BootstrapVersion != 2 {
		t.Errorf("snapshot bootstrap version = %d, want 2", snap.BootstrapVersion)
	}
	if snap.LOTLSequence != 388 {
		t.Errorf("LOTL sequence = %d, want 388", snap.LOTLSequence)
	}
	// Pivot position was reset to 0 and re-converged: direct verification with
	// the new set succeeds, so all advertised pivots are marked processed.
	if snap.LOTLPivotSeq != 378 {
		t.Errorf("pivot seq = %d, want 378", snap.LOTLPivotSeq)
	}
}

// TestRefreshSameBootstrapVersionKeepsPreviousSigners is the negative control
// for R2: with an UNCHANGED bootstrap version, the cycle must keep using the
// previous snapshot's signer set — proven by observing zero pivot fetches
// (the prev set verifies the LOTL directly; if the obsolete same-version
// bootstrap had wrongly taken precedence, the pipeline would have had to walk
// the pivot chain).
func TestRefreshSameBootstrapVersionKeepsPreviousSigners(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)

	current := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	prev := &trust.Snapshot{
		LOTLSequence:     388,
		LOTLPivotSeq:     378,
		LOTLSignersDER:   current.CertsDER, // prev signers = the current set
		BootstrapVersion: 1,
	}

	obsoleteSameVersion := fixtureBootstrap(t, "eu-lotl-pivot-282.xml") // version 1 == prev

	snap, err := p.Refresh(context.Background(), prev, obsoleteSameVersion)
	if err != nil {
		t.Fatalf("cycle must succeed via the previous snapshot's signers: %v", err)
	}
	if got := ft.pivotFetches(); got != 0 {
		t.Errorf("pivot fetches = %d, want 0 (prev signers must be used directly; "+
			"a same-version bootstrap must NOT supersede them)", got)
	}
	if snap.LOTLPivotSeq != 378 {
		t.Errorf("pivot seq = %d, want 378", snap.LOTLPivotSeq)
	}
}

func pemEncode(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
