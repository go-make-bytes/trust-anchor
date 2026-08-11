package ingest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/go-make-bytes/trust-anchor/events"
	"github.com/go-make-bytes/trust-anchor/store"
	"github.com/go-make-bytes/trust-anchor/trust"
)

// internalOneAnchor is a valid single-entry internal trust source (the first
// entry of the recorded fixture, inline certificate only).
const internalOneAnchor = `anchors:
  - name: "Internal Test CA One"
    type: pid_provider
    territory: lv
    useCases:
      - pid-issuance
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

// declaredPipeline builds a hermetic pipeline with declared-source paths set.
func declaredPipeline(t *testing.T, ft *fixtureTransport, internalPath string, log *zap.Logger) *Pipeline {
	t.Helper()
	fetcher := NewFetcher(10*time.Second, 20*1024*1024)
	fetcher.SetTransport(ft)
	cfg := Config{
		LOTLURL:             lotlURL,
		Territories:         []string{"LV"},
		AcceptedStatuses:    []string{"granted"},
		ActivationMode:      ModeAuto,
		InternalTrustSource: internalPath,
		StaleGrace:          24 * time.Hour,
	}
	return NewPipeline(cfg, fetcher, events.New(log), log)
}

// deadTransport serves nothing: every fetch is a 404, and counts prove
// whether anything was fetched at all.
func deadTransport() *fixtureTransport {
	return &fixtureTransport{
		files:  map[string]string{},
		body:   map[string][]byte{},
		status: map[string]int{},
		counts: map[string]int{},
	}
}

// eventObserved reports whether a background security event of the given
// type was written to the observed logger.
func eventObserved(logs *observer.ObservedLogs, eventType string) bool {
	for _, e := range logs.All() {
		if e.Message != "security_event" {
			continue
		}
		for _, f := range e.Context {
			if f.Key == "event_type" && f.String == eventType {
				return true
			}
		}
	}
	return false
}

// An unchanged declared configuration reconciles to no new snapshot.
func TestRefreshDeclaredNoChange(t *testing.T) {
	dir := t.TempDir()
	internal := filepath.Join(dir, "internal-trust.yaml")
	if err := os.WriteFile(internal, []byte(internalOneAnchor), 0o600); err != nil {
		t.Fatal(err)
	}

	p := declaredPipeline(t, newFixtureTransport(), internal, zap.NewNop())
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	s1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}

	next, changed, _, err := p.RefreshDeclared(s1, time.Now().UTC())
	if err != nil || changed || next != nil {
		t.Fatalf("unchanged declared sources reported a change: next=%v changed=%v err=%v", next, changed, err)
	}
}

// An edited internal trust source reconciles into a new snapshot without any
// upstream fetch: the trusted-list data is preserved verbatim, only the
// declared set and the identity move.
func TestRefreshDeclaredActivatesEditedInternal(t *testing.T) {
	dir := t.TempDir()
	internal := filepath.Join(dir, "internal-trust.yaml")

	// Build the previous snapshot with the two-anchor fixture file.
	if err := os.WriteFile(internal, readTestdata(t, "internal-trust-valid.yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "internal-ca-two.pem"), readTestdata(t, "internal-ca-two.pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	p1 := declaredPipeline(t, newFixtureTransport(), internal, zap.NewNop())
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	s1, err := p1.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	if len(s1.Internal) != 2 {
		t.Fatalf("internal anchors = %d, want 2", len(s1.Internal))
	}

	// Edit the file down to one anchor; the upstream is now unreachable.
	if err := os.WriteFile(internal, []byte(internalOneAnchor), 0o600); err != nil {
		t.Fatal(err)
	}
	dead := deadTransport()
	p2 := declaredPipeline(t, dead, internal, zap.NewNop())

	next, changed, _, err := p2.RefreshDeclared(s1, time.Now().UTC())
	if err != nil || !changed || next == nil {
		t.Fatalf("edited declared source not reconciled: changed=%v err=%v", changed, err)
	}
	if len(dead.counts) != 0 {
		t.Fatalf("declared reconcile fetched from upstream: %v", dead.counts)
	}
	if len(next.Internal) != 1 {
		t.Fatalf("internal anchors = %d, want 1", len(next.Internal))
	}
	if next.ID == s1.ID || next.PrevID != s1.ID {
		t.Fatalf("snapshot identity not advanced: id=%s prev=%s", next.ID, next.PrevID)
	}
	if len(next.Territories) != len(s1.Territories) {
		t.Fatalf("territories changed by a declared reconcile: %d != %d", len(next.Territories), len(s1.Territories))
	}
	for i, tr := range next.Territories {
		if tr.TLSequence != s1.Territories[i].TLSequence || len(tr.Anchors) != len(s1.Territories[i].Anchors) {
			t.Fatalf("territory %s data not preserved verbatim", tr.Code)
		}
	}
	for _, e := range next.Diff.Entries {
		if e.Territory != "internal" {
			t.Fatalf("diff entry outside the internal set: %+v", e)
		}
	}
}

// A bad edit reconciles to no change: the previous set is carried over and
// the source's event is emitted, exactly like during a full cycle.
func TestRefreshDeclaredCarriesOverBadEdit(t *testing.T) {
	dir := t.TempDir()
	internal := filepath.Join(dir, "internal-trust.yaml")
	if err := os.WriteFile(internal, []byte(internalOneAnchor), 0o600); err != nil {
		t.Fatal(err)
	}

	core, logs := observer.New(zap.InfoLevel)
	p := declaredPipeline(t, newFixtureTransport(), internal, zap.New(core))
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	s1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(internal, []byte("anchors: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	next, changed, _, err := p.RefreshDeclared(s1, time.Now().UTC())
	if err != nil || changed || next != nil {
		t.Fatalf("bad edit produced a change: next=%v changed=%v err=%v", next, changed, err)
	}
	if !eventObserved(logs, events.EventInternalSourceError) {
		t.Fatal("trust.internal_source_error not emitted on the reconcile path")
	}
}

// The boot property, at the manager: a restored snapshot is reconciled
// against the declared file as it is NOW, persisted and activated — with the
// upstream unreachable end to end.
func TestManagerReconcileDeclaredActivatesEditedFile(t *testing.T) {
	dir := t.TempDir()
	internal := filepath.Join(dir, "internal-trust.yaml")
	if err := os.WriteFile(internal, []byte(internalOneAnchor), 0o600); err != nil {
		t.Fatal(err)
	}

	p := declaredPipeline(t, deadTransport(), internal, zap.NewNop())
	st := store.NewMemory()
	m := NewManager(p, st, events.New(zap.NewNop()), zap.NewNop())
	seedBootstrap(t, st)

	// The persisted snapshot predates the edit: it carries a different
	// internal set than the file now declares.
	s1 := managerSnapshot(t)
	s1.Internal = []trust.Anchor{{
		Territory: "EU", Source: trust.SourceInternal, TSPName: "internal",
		ServiceName: "Old CA", Status: trust.NormalizeStatus("granted"),
		FingerprintSHA256: "oldfp", CertDER: []byte{9},
	}}
	s1.ComputeID()
	if err := st.SaveSnapshot(context.Background(), s1); err != nil {
		t.Fatal(err)
	}

	if err := m.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if m.Active().ID != s1.ID {
		t.Fatal("Initialize must restore verbatim — the reconcile is a separate step")
	}

	if !m.ReconcileDeclared(context.Background()) {
		t.Fatal("edited declared file not detected at boot reconcile")
	}
	act := m.Active()
	if len(act.Internal) != 1 || act.Internal[0].FingerprintSHA256 == "oldfp" {
		t.Fatalf("declared set not re-read: %+v", act.Internal)
	}
	if act.ID == s1.ID {
		t.Fatal("snapshot identity unchanged after reconcile")
	}
	persisted, err := st.LoadLatestSnapshot(context.Background())
	if err != nil || persisted == nil || persisted.ID != act.ID {
		t.Fatalf("reconciled snapshot not persisted: %v %v", persisted, err)
	}

	if m.ReconcileDeclared(context.Background()) {
		t.Fatal("second reconcile with an unchanged file reported a change")
	}
}

// The on-demand property: a triggered refresh applies a declared edit even
// when the upstream cycle fails — the caller sees changed=true and the new
// set is active, alongside the cycle error.
func TestManagerRefreshAppliesDeclaredWhenCycleFails(t *testing.T) {
	s1 := managerSnapshot(t)

	s2 := managerSnapshot(t)
	s2.Internal = []trust.Anchor{{
		Territory: "EU", Source: trust.SourceInternal, TSPName: "internal",
		ServiceName: "New CA", Status: trust.NormalizeStatus("granted"),
		FingerprintSHA256: "newfp", CertDER: []byte{7},
	}}
	s2.ComputeID()

	fake := &fakeRefresher{err: errors.New("upstream down"), declared: s2}
	m, st := managerForTest(t, fake)
	seedBootstrap(t, st)
	if err := st.SaveSnapshot(context.Background(), s1); err != nil {
		t.Fatal(err)
	}
	if err := m.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}

	got, changed, err := m.Refresh(context.Background())
	if err == nil {
		t.Fatal("cycle error swallowed")
	}
	if !changed {
		t.Fatal("declared change not reported through a failing refresh")
	}
	if got == nil || got.ID != s2.ID || m.Active().ID != s2.ID {
		t.Fatal("declared reconcile result not active after a failing refresh")
	}
	persisted, perr := st.LoadLatestSnapshot(context.Background())
	if perr != nil || persisted == nil || persisted.ID != s2.ID {
		t.Fatalf("reconciled snapshot not persisted: %v %v", persisted, perr)
	}
}
