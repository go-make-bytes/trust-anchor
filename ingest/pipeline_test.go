package ingest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/go-make-bytes/trust-anchor/events"
	"github.com/go-make-bytes/trust-anchor/trust"
	"github.com/go-make-bytes/trust-anchor/tsl"
)

// Live URLs as recorded in the fixtures.
const (
	lotlURL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
	lvURL   = "https://trustlist.gov.lv/tsl/latvian-tsl.xml"
	eeURL   = "https://sr.riik.ee/tsl/estonian-tsl.xml"
	// The LOTL's SK pointer is plain http — the real published location.
	skURL = "http://tl.nbu.gov.sk/kca/tsl/tsl.xml"
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
			skURL:   "sk-tsl.xml",
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

// testClock is the pinned cycle time for fixture-driven pipeline tests: a
// date at which every recorded list is within its NextUpdate (the recorded
// LOTL's is 2026-11-18). Without the pin, the expired-LOTL check
// (PRO-4.1.4-13) would make the whole fixture suite start failing the day
// the wall clock passes the fixture's NextUpdate.
var testClock = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

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
	p := NewPipeline(cfg, fetcher, events.New(zap.NewNop()), zap.NewNop())
	p.clock = func() time.Time { return testClock }
	return p
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
	// Every TL-sourced anchor is stamped with its territory's TLSequence
	// (T1: additive Anchor.TLSequence field).
	for _, a := range lv.Anchors {
		if a.TLSequence != 51 {
			t.Errorf("LV anchor %s TLSequence = %d, want 51", a.FingerprintSHA256, a.TLSequence)
		}
	}
	for _, a := range ee.Anchors {
		if a.TLSequence != 73 {
			t.Errorf("EE anchor %s TLSequence = %d, want 73", a.FingerprintSHA256, a.TLSequence)
		}
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

// TestRefreshPartialFirstSnapshot: a territory failing with no previous data
// is recorded as a failed entry and the rest of the cycle completes — the
// healthy territories are served, the broken one is named.
func TestRefreshPartialFirstSnapshot(t *testing.T) {
	ft := newFixtureTransport()
	ft.status[lvURL] = 500
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatalf("one broken territory failed the whole first cycle: %v", err)
	}

	lv := snap.Territory("LV")
	if lv == nil {
		t.Fatal("failed territory missing from the snapshot entirely")
	}
	if !lv.Failed || lv.FailureReason == "" {
		t.Fatalf("LV not recorded as failed: %+v", lv)
	}
	if len(lv.Anchors) != 0 || lv.CarriedOver {
		t.Fatalf("failed territory carries data: %+v", lv)
	}
	ee := snap.Territory("EE")
	if ee == nil || ee.Failed || len(ee.Anchors) != 11 {
		t.Fatalf("healthy territory suppressed by the broken one: %+v", ee)
	}
}

// TestRefreshAllTerritoriesFailedFirstRunFails: the floor — when every
// configured territory failed and nothing has data, no snapshot forms.
func TestRefreshAllTerritoriesFailedFirstRunFails(t *testing.T) {
	ft := newFixtureTransport()
	ft.status[lvURL] = 500
	ft.status[eeURL] = 500
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	if _, err := p.Refresh(context.Background(), nil, boot); err == nil {
		t.Fatal("cycle produced a snapshot with zero verified territories")
	}
}

// TestRefreshAllTerritoriesCarriedOverStillSucceeds pins the floor's
// boundary: with previous data everywhere, an all-territories outage is a
// carry-over cycle, not a floor failure (serving slightly old data beats
// serving nothing).
func TestRefreshAllTerritoriesCarriedOverStillSucceeds(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	good, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}

	ft.status[lvURL] = 500
	ft.status[eeURL] = 500
	snap, err := p.Refresh(context.Background(), good, boot)
	if err != nil {
		t.Fatalf("all-carry-over cycle failed: %v", err)
	}
	for _, code := range []string{"LV", "EE"} {
		tr := snap.Territory(code)
		if tr == nil || !tr.CarriedOver || tr.Failed {
			t.Fatalf("%s not carried over: %+v", code, tr)
		}
	}
}

// TestRefreshFailedTerritoryStaysFailedThenRecovers: a failed entry is not
// "previous data" — while the upstream stays broken the territory stays a
// failed entry (never a carry-over of nothing), and the snapshot id does not
// move; when the upstream heals, the territory ingests normally.
func TestRefreshFailedTerritoryStaysFailedThenRecovers(t *testing.T) {
	ft := newFixtureTransport()
	ft.status[lvURL] = 500
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	first, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}

	second, err := p.Refresh(context.Background(), first, boot)
	if err != nil {
		t.Fatal(err)
	}
	lv := second.Territory("LV")
	if lv == nil || !lv.Failed || lv.CarriedOver || len(lv.Anchors) != 0 {
		t.Fatalf("still-broken territory not a failed entry: %+v", lv)
	}
	if second.ID != first.ID {
		t.Error("snapshot id moved on an unchanged failed territory")
	}

	delete(ft.status, lvURL)
	healed, err := p.Refresh(context.Background(), second, boot)
	if err != nil {
		t.Fatal(err)
	}
	lv = healed.Territory("LV")
	if lv == nil || lv.Failed || len(lv.Anchors) != 5 {
		t.Fatalf("healed territory did not ingest: %+v", lv)
	}
	if healed.ID == second.ID {
		t.Error("snapshot id unchanged after a territory gained anchors")
	}
}

// TestRefreshEUTerritoryGroup: TRUST_TERRITORIES=EU expands, per cycle, to
// every territory the verified LOTL publishes an XML pointer for. The
// fixtures serve only LV and EE, so those two ingest and every other
// expanded territory becomes a named failed entry — the expansion and the
// tolerance proven together.
func TestRefreshEUTerritoryGroup(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)
	p.cfg.Territories = []string{"EU"}
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}

	// The recorded LOTL publishes 31 territories (pinned in the tsl package).
	if len(snap.Territories) != 31 {
		t.Fatalf("territories = %d, want 31", len(snap.Territories))
	}
	healthy := 0
	for _, tr := range snap.Territories {
		if !tr.Failed {
			healthy++
		}
	}
	if healthy != 2 {
		t.Fatalf("healthy territories = %d, want 2 (LV, EE — the fixtures)", healthy)
	}
	if lv := snap.Territory("LV"); lv == nil || lv.Failed || len(lv.Anchors) != 5 {
		t.Fatalf("LV not ingested under the EU group: %+v", lv)
	}
	if de := snap.Territory("DE"); de == nil || !de.Failed {
		t.Fatalf("DE not a failed entry under the EU group: %+v", de)
	}
	if el := snap.Territory("EL"); el == nil {
		t.Fatal("EL (Greece's publisher code) missing from the expansion")
	}
	if snap.Territory("EU") != nil {
		t.Fatal("the LOTL self-pointer leaked into the territory set")
	}
}

// TestRefreshEUGroupDedupesAndKeepsExplicitCodes: explicit codes combine with
// the group without duplication, and a code the LOTL has no pointer for (UA)
// is a named failed entry rather than an error — it starts working the day
// its declared source exists.
func TestRefreshEUGroupDedupesAndKeepsExplicitCodes(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)
	p.cfg.Territories = []string{"EU", "LV", "UA"}
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Territories) != 32 {
		t.Fatalf("territories = %d, want 32 (31 from the LOTL + UA)", len(snap.Territories))
	}
	seen := map[string]int{}
	for _, tr := range snap.Territories {
		seen[tr.Code]++
	}
	if seen["LV"] != 1 {
		t.Fatalf("LV appears %d times, want 1 (dedupe)", seen["LV"])
	}
	ua := snap.Territory("UA")
	if ua == nil || !ua.Failed || !strings.Contains(ua.FailureReason, "no XML trusted-list pointer") {
		t.Fatalf("UA not a named failed entry: %+v", ua)
	}
}

// TestRefreshRejectsExpiredLOTL: an expired LOTL no longer authenticates
// (TS 119 615 PRO-4.1.4-13) — the cycle fails with the named reason and the
// caller keeps serving the previous snapshot. The same fixture accepted an
// hour before its NextUpdate pins the boundary.
func TestRefreshRejectsExpiredLOTL(t *testing.T) {
	pre, err := tsl.Parse(readTestdata(t, "eu-lotl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	nu := pre.SchemeInformation.NextUpdate.DateTime
	if nu == nil {
		t.Fatal("fixture LOTL has no NextUpdate")
	}

	p := testPipeline(t, newFixtureTransport(), ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	p.clock = func() time.Time { return nu.Add(-time.Hour) }
	if _, err := p.Refresh(context.Background(), nil, boot); err != nil {
		t.Fatalf("unexpired LOTL refused: %v", err)
	}

	p.clock = func() time.Time { return nu.Add(time.Hour) }
	_, err = p.Refresh(context.Background(), nil, boot)
	if err == nil {
		t.Fatal("an expired LOTL still authenticated")
	}
	if !strings.Contains(err.Error(), "LOTL_NEXTUPDATE_PASSED") {
		t.Fatalf("expiry refusal does not carry the named reason: %v", err)
	}
}

// TestLOTLSignerSelfConsistency: the certificate that signed the LOTL must
// be in the LOTL's own EU self-pointer set (TS 119 615 PRO-4.1.4-10(a)). The
// real fixture is self-consistent (positive leg proves the extracted signer
// is the true one); a foreign certificate fails with the named reason.
func TestLOTLSignerSelfConsistency(t *testing.T) {
	raw := readTestdata(t, "eu-lotl.xml")
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	signers, err := boot.Certificates()
	if err != nil {
		t.Fatal(err)
	}
	verified, signer, err := tsl.Verify(raw, signers)
	if err != nil {
		t.Fatal(err)
	}
	lotl, err := tsl.Parse(verified)
	if err != nil {
		t.Fatal(err)
	}

	if err := lotlSignerSelfConsistent(signer, lotl); err != nil {
		t.Fatalf("the real LOTL read as self-inconsistent: %v", err)
	}

	foreign := testCertificate(t, "not-the-lotl-signer")
	err = lotlSignerSelfConsistent(foreign, lotl)
	if err == nil {
		t.Fatal("a foreign signer passed the self-consistency check")
	}
	if !strings.Contains(err.Error(), "LOTL_SIGNER_CERT_NOT_AUTHENTICATED_BY_LOTL") {
		t.Fatalf("refusal does not carry the named reason: %v", err)
	}
}

// testCertificate generates a throwaway self-signed certificate — a signer
// that is deliberately NOT in any fixture's pointer sets.
func testCertificate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestRefreshHTTPTerritoryOptIn: a territory named in AllowHTTPTerritories
// may be fetched over its published plain-http pointer (SK's real shape) —
// the list still passes the same XMLDSig verification against the
// LOTL-pinned signers, which is where integrity actually comes from.
func TestRefreshHTTPTerritoryOptIn(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)
	p.cfg.Territories = []string{"LV", "SK"}
	p.cfg.AllowHTTPTerritories = []string{"SK"}
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	sk := snap.Territory("SK")
	if sk == nil || sk.Failed {
		t.Fatalf("opted-in http territory did not ingest: %+v", sk)
	}
	if len(sk.Anchors) == 0 {
		t.Fatal("SK ingested but extracted no anchors")
	}
}

// TestRefreshHTTPBlockedWithoutOptIn pins the default: an http pointer for a
// territory NOT named in the opt-in stays refused by the egress policy and
// becomes a named failed entry.
func TestRefreshHTTPBlockedWithoutOptIn(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)
	p.cfg.Territories = []string{"LV", "SK"}
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	sk := snap.Territory("SK")
	if sk == nil || !sk.Failed || !strings.Contains(sk.FailureReason, "not https") {
		t.Fatalf("http territory without opt-in not refused: %+v", sk)
	}
	if lv := snap.Territory("LV"); lv == nil || lv.Failed {
		t.Fatalf("LV suppressed: %+v", lv)
	}
}

// TestRefreshLOTLNeverHTTP: the opt-in is per national territory and can
// never make an http LOTL acceptable — nothing on the LOTL path registers a
// plain-http host.
func TestRefreshLOTLNeverHTTP(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)
	p.cfg.LOTLURL = "http://ec.europa.eu/tools/lotl/eu-lotl.xml"
	p.cfg.AllowHTTPTerritories = []string{"LV", "EE", "SK", "EU"}
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	if _, err := p.Refresh(context.Background(), nil, boot); err == nil {
		t.Fatal("an http LOTL was accepted")
	}
}

// TestComputeIDExcludesFailedTerritories: a failed entry is a process
// outcome, not trust content — the id of a snapshot with a failed territory
// equals the id of the same snapshot without that entry.
func TestComputeIDExcludesFailedTerritories(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	full, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}

	withFailed, err := cloneSnapshot(full)
	if err != nil {
		t.Fatal(err)
	}
	withFailed.Territories = append(withFailed.Territories, &trust.Territory{
		Code: "DE", Failed: true, FailureReason: "unreachable", Anchors: []trust.Anchor{},
	})
	if withFailed.ComputeID() != full.ID {
		t.Error("a failed territory entry moved the content id")
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
	aged.Pending[0].FirstSeen = testClock.Add(-100 * time.Hour)
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

// internalYAMLFixture is a self-contained (inline PEM, no certificateFile
// dependency) single-entry INTERNAL_TRUST_SOURCE file for ingest-level
// tests. The certificate is a throwaway ECDSA P-256 self-signed test cert
// (NotAfter 2035), never production trust material.
const internalYAMLFixture = `anchors:
  - name: "Ingest Test CA"
    type: access_ca
    territory: LV
    certificate: |
      -----BEGIN CERTIFICATE-----
      MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMB8xHTAbBgNVBAMTFEludGVybmFs
      IFRlc3QgQ0EgT25lMB4XDTI0MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowHzEd
      MBsGA1UEAxMUSW50ZXJuYWwgVGVzdCBDQSBPbmUwWTATBgcqhkjOPQIBBggqhkjO
      PQMBBwNCAARJDZ2MSeXpWnjKmKBX+gVXH9G8RLCsuCR6D9xkpMHHOOVdQS/ien8l
      t9ZIcdtDXCOtruMthLFxb/zNtJ2DoKQRMAoGCCqGSM49BAMCA0gAMEUCIGm8VzIq
      3GWAoclhLI6wKjgV3tFsu7faKU4Ou5y44ZXYAiEA9q13QOWzseqWzpX0yRwABd6g
      n/nizS7hefaHu9j6dHQ=
      -----END CERTIFICATE-----
`

// internalYAMLBad declares an unknown taxonomy type — a fail-closed
// rejection of the whole file.
const internalYAMLBad = "anchors:\n  - name: bad\n    type: not_a_type\n    territory: LV\n"

func TestRefreshInternal(t *testing.T) {
	p := testPipeline(t, newFixtureTransport(), ModeAuto)
	p.cfg.InternalTrustSource = filepath.Join("..", "testdata", "internal-trust-valid.yaml")
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Internal) != 2 {
		t.Fatalf("internal anchors = %d, want 2", len(snap.Internal))
	}
	for _, a := range snap.Internal {
		if a.Source != trust.SourceInternal {
			t.Errorf("internal anchor source = %q, want %q", a.Source, trust.SourceInternal)
		}
	}
}

// TestRefreshInternalCarriesOverOnError: a bad operator edit to
// INTERNAL_TRUST_SOURCE must never adopt a partial/absent internal set — the
// previous internal set is carried over and the cycle still succeeds.
func TestRefreshInternalCarriesOverOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "internal.yaml")
	if err := os.WriteFile(path, []byte(internalYAMLFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	p := testPipeline(t, newFixtureTransport(), ModeAuto)
	p.cfg.InternalTrustSource = path
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	good, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	if len(good.Internal) != 1 {
		t.Fatalf("internal anchors = %d, want 1", len(good.Internal))
	}

	// Operator typo: an unknown type rejects the whole file.
	if err := os.WriteFile(path, []byte(internalYAMLBad), 0o600); err != nil {
		t.Fatal(err)
	}

	next, err := p.Refresh(context.Background(), good, boot)
	if err != nil {
		t.Fatalf("cycle failed instead of carrying over the internal set: %v", err)
	}
	if len(next.Internal) != 1 || next.Internal[0].FingerprintSHA256 != good.Internal[0].FingerprintSHA256 {
		t.Fatalf("internal set not carried over: got %+v, want %+v", next.Internal, good.Internal)
	}
}

// TestRefreshInternalErrorNoPreviousData: unlike a territory failure on the
// very first run (which fails the whole cycle — no partial first snapshot
// is ever served), an internal-source failure never blocks the cycle: there
// is simply nothing to carry over yet, so the snapshot proceeds with no
// internal anchors.
func TestRefreshInternalErrorNoPreviousData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "internal.yaml")
	if err := os.WriteFile(path, []byte(internalYAMLBad), 0o600); err != nil {
		t.Fatal(err)
	}

	p := testPipeline(t, newFixtureTransport(), ModeAuto)
	p.cfg.InternalTrustSource = path
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatalf("cycle failed on first-run internal source error: %v", err)
	}
	if len(snap.Internal) != 0 {
		t.Errorf("internal anchors = %d, want 0", len(snap.Internal))
	}
}

// TestRefreshPrefersPreviousSnapshotSigners: when a previous snapshot carries
// a signer set, the cycle continues from it (no pivot re-walk) rather than
// re-deriving from the pinned bootstrap — proven by observing zero pivot
// fetches (the prev set verifies the LOTL directly).
func TestRefreshPrefersPreviousSnapshotSigners(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)

	current := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	prev := &trust.Snapshot{
		LOTLSequence:   388,
		LOTLPivotSeq:   378,
		LOTLSignersDER: current.CertsDER, // prev signers = the current set
	}

	snap, err := p.Refresh(context.Background(), prev, current)
	if err != nil {
		t.Fatalf("cycle must succeed via the previous snapshot's signers: %v", err)
	}
	if got := ft.pivotFetches(); got != 0 {
		t.Errorf("pivot fetches = %d, want 0 (previous snapshot signers must be used directly)", got)
	}
	if snap.LOTLPivotSeq != 378 {
		t.Errorf("pivot seq = %d, want 378", snap.LOTLPivotSeq)
	}
}

// TestComputeIDExcludesSkippedServices: a skipped service is a declared
// absence — health, not trust content — so a snapshot that differs only in
// what it reports as skipped keeps its id, and every consumer's ETag with it.
func TestComputeIDExcludesSkippedServices(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	full, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Territories) == 0 {
		t.Fatal("fixture cycle produced no territories")
	}

	withSkipped, err := cloneSnapshot(full)
	if err != nil {
		t.Fatal(err)
	}
	withSkipped.Territories[0].Skipped = append(withSkipped.Territories[0].Skipped, trust.SkippedService{
		TSPName: "D-Trust GmbH", ServiceName: "D-Trust remote signature service (sign-me)",
		Reason: trust.SkipUnsupportedKey, FingerprintSHA256: "23395de6", KeyAlgorithm: trust.KeyAlgorithmECDSA, Curve: "brainpoolP256r1",
	})
	if withSkipped.ComputeID() != full.ID {
		t.Error("a skipped-service entry moved the content id")
	}
}
