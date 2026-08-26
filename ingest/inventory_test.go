package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/go-make-bytes/trust-anchor/events"
	"github.com/go-make-bytes/trust-anchor/store"
	"github.com/go-make-bytes/trust-anchor/trust"
)

// inventoryEntries returns the observed "trust inventory" log entries.
func inventoryEntries(logs *observer.ObservedLogs) []observer.LoggedEntry {
	var out []observer.LoggedEntry
	for _, e := range logs.All() {
		if e.Message == "trust inventory" {
			out = append(out, e)
		}
	}
	return out
}

// inventoryField returns a named field from a logged inventory entry.
func inventoryField(t *testing.T, e observer.LoggedEntry, key string) any {
	t.Helper()
	m := e.ContextMap()
	v, ok := m[key]
	if !ok {
		t.Fatalf("inventory entry missing field %q (have %v)", key, m)
	}
	return v
}

// metricValue extracts one series value from the process metrics output.
// Returns (0, false) when the series is absent.
func metricValue(buf []byte, series string) (float64, bool) {
	for _, line := range strings.Split(string(buf), "\n") {
		if !strings.HasPrefix(line, series+" ") {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, series+" ")), 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

func gatherMetrics() []byte {
	var buf bytes.Buffer
	metrics.WritePrometheus(&buf, false)
	return buf.Bytes()
}

// The trap the inventory exists to expose: a broken declared file at boot
// means the previous set is carried over — which from outside looks exactly
// like a successful edit. The boot inventory must say so, and must name the
// carried-over anchors: an operator-declared anchor has no other record.
func TestBootInventoryNamesCarriedOverAnchors(t *testing.T) {
	dir := t.TempDir()
	internal := filepath.Join(dir, "internal-trust.yaml")
	if err := os.WriteFile(internal, []byte("anchors: ["), 0o600); err != nil {
		t.Fatal(err)
	}

	core, logs := observer.New(zap.InfoLevel)
	p := declaredPipeline(t, deadTransport(), internal, zap.New(core))
	st := store.NewMemory()
	m := NewManager(p, st, events.New(zap.NewNop()), zap.New(core))
	seedBootstrap(t, st)

	s1 := managerSnapshot(t)
	s1.Internal = []trust.Anchor{{
		Territory: "EU", Source: trust.SourceInternal, TSPName: "Legacy Internal CA",
		ServiceName: "Legacy Internal CA", Status: trust.NormalizeStatus("granted"),
		FingerprintSHA256: "feedbeef", CertDER: []byte{9}, Type: "pid_provider",
		NotAfter: time.Now().UTC().Add(365 * 24 * time.Hour),
	}}
	s1.ComputeID()
	if err := st.SaveSnapshot(context.Background(), s1); err != nil {
		t.Fatal(err)
	}
	if err := m.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}

	m.ReconcileDeclared(context.Background())

	entries := inventoryEntries(logs)
	if len(entries) != 1 {
		t.Fatalf("boot inventory entries = %d, want exactly 1", len(entries))
	}
	e := entries[0]
	if got := inventoryField(t, e, "internal_state"); got != "carried_over" {
		t.Fatalf("internal_state = %v, want carried_over", got)
	}
	if got := inventoryField(t, e, "internal_count"); got != int64(1) {
		t.Fatalf("internal_count = %v, want 1", got)
	}
	if got, _ := inventoryField(t, e, "internal_error").(string); got == "" {
		t.Fatal("internal_error empty — the carried-over case must say why")
	}
	anchors := fmt.Sprintf("%v", inventoryField(t, e, "internal_anchors"))
	if !strings.Contains(anchors, "Legacy Internal CA") || !strings.Contains(anchors, "feedbeef") {
		t.Fatalf("carried-over anchor not named in full: %s", anchors)
	}
}

// The other two negative cases must stay distinguishable from each other and
// from carry-over: a file that parses to zero anchors is state ok / count 0;
// an unset path is not_configured.
func TestBootInventoryDistinguishesZeroAnchorsFromUnset(t *testing.T) {
	// (a) configured, parses, zero anchors.
	dir := t.TempDir()
	internal := filepath.Join(dir, "internal-trust.yaml")
	if err := os.WriteFile(internal, []byte("anchors: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.InfoLevel)
	p := declaredPipeline(t, deadTransport(), internal, zap.New(core))
	st := store.NewMemory()
	m := NewManager(p, st, events.New(zap.NewNop()), zap.New(core))
	seedBootstrap(t, st)
	s1 := managerSnapshot(t)
	s1.Internal = []trust.Anchor{{
		Territory: "EU", Source: trust.SourceInternal, TSPName: "Gone CA",
		Status: trust.NormalizeStatus("granted"), FingerprintSHA256: "gonefp", CertDER: []byte{7},
	}}
	s1.ComputeID()
	if err := st.SaveSnapshot(context.Background(), s1); err != nil {
		t.Fatal(err)
	}
	if err := m.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	m.ReconcileDeclared(context.Background())
	entries := inventoryEntries(logs)
	if len(entries) != 1 {
		t.Fatalf("inventory entries = %d, want 1", len(entries))
	}
	if got := inventoryField(t, entries[0], "internal_state"); got != "ok" {
		t.Fatalf("zero-anchor file: internal_state = %v, want ok", got)
	}
	if got := inventoryField(t, entries[0], "internal_count"); got != int64(0) {
		t.Fatalf("zero-anchor file: internal_count = %v, want 0", got)
	}

	// (b) not configured at all.
	core2, logs2 := observer.New(zap.InfoLevel)
	p2 := declaredPipeline(t, deadTransport(), "", zap.New(core2))
	st2 := store.NewMemory()
	m2 := NewManager(p2, st2, events.New(zap.NewNop()), zap.New(core2))
	seedBootstrap(t, st2)
	s2 := managerSnapshot(t)
	if err := st2.SaveSnapshot(context.Background(), s2); err != nil {
		t.Fatal(err)
	}
	if err := m2.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	m2.ReconcileDeclared(context.Background())
	entries2 := inventoryEntries(logs2)
	if len(entries2) != 1 {
		t.Fatalf("inventory entries = %d, want 1", len(entries2))
	}
	if got := inventoryField(t, entries2[0], "internal_state"); got != "not_configured" {
		t.Fatalf("unset path: internal_state = %v, want not_configured", got)
	}
}

// Freshness and volume are metrics (alerting layer): a successful cycle
// stamps the last-success timestamp, volume gauges follow the active
// snapshot, and a declared-source load failure raises its 0/1 gauge without
// touching health semantics.
func TestRefreshSetsFreshnessAndVolumeGauges(t *testing.T) {
	dir := t.TempDir()
	internal := filepath.Join(dir, "internal-trust.yaml")
	if err := os.WriteFile(internal, []byte(internalOneAnchor), 0o600); err != nil {
		t.Fatal(err)
	}

	core, logs := observer.New(zap.InfoLevel)
	p := declaredPipeline(t, newFixtureTransport(), internal, zap.New(core))
	st := store.NewMemory()
	m := NewManager(p, st, events.New(zap.NewNop()), zap.New(core))
	if err := st.SaveBootstrap(context.Background(), fixtureBootstrap(t, "eu-lotl-pivot-378.xml")); err != nil {
		t.Fatal(err)
	}
	if err := m.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC().Add(-time.Second)
	if _, _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	buf := gatherMetrics()
	ts, ok := metricValue(buf, "trust_sync_last_success_timestamp_seconds")
	if !ok || ts < float64(before.Unix()) {
		t.Fatalf("trust_sync_last_success_timestamp_seconds = %v (present=%v), want >= %d", ts, ok, before.Unix())
	}
	age, ok := metricValue(buf, "trust_snapshot_age_seconds")
	if !ok || age < 0 || age > 300 {
		t.Fatalf("trust_snapshot_age_seconds = %v (present=%v), want small non-negative", age, ok)
	}
	got, ok := metricValue(buf, `trust_anchors_total{source="internal",territory="LV",type="pid_provider"}`)
	if !ok || got != 1 {
		t.Fatalf(`trust_anchors_total internal/LV/pid_provider = %v (present=%v), want 1`, got, ok)
	}
	tl, ok := metricValue(buf, `trust_anchors_total{source="tl",territory="LV",type=""}`)
	if !ok || tl <= 0 {
		t.Fatalf("trust_anchors_total tl/LV = %v (present=%v), want > 0", tl, ok)
	}
	failed, ok := metricValue(buf, `trust_declared_source_failed{source="internal"}`)
	if !ok || failed != 0 {
		t.Fatalf("trust_declared_source_failed internal = %v (present=%v), want 0", failed, ok)
	}

	// The very first activation logs the inventory: the declared set went
	// from nothing to something and there is no other record of it.
	if n := len(inventoryEntries(logs)); n != 1 {
		t.Fatalf("inventory entries after first activation = %d, want 1", n)
	}

	// Break the declared file: the next cycle carries over and raises the
	// source's failed gauge — alerting without a health flip.
	if err := os.WriteFile(internal, []byte("anchors: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	failed, ok = metricValue(gatherMetrics(), `trust_declared_source_failed{source="internal"}`)
	if !ok || failed != 1 {
		t.Fatalf("trust_declared_source_failed internal after bad edit = %v (present=%v), want 1", failed, ok)
	}
}

// A series that existed for the previous snapshot but not the current one
// must read 0, not its stale last value — a vanished territory or type is
// zero anchors.
func TestAnchorGaugeSeriesZeroedWhenGone(t *testing.T) {
	a := &trust.Snapshot{Internal: []trust.Anchor{{
		Source: trust.SourceInternal, Territory: "LV", Type: "pid_provider", FingerprintSHA256: "z1",
	}}}
	b := &trust.Snapshot{Internal: []trust.Anchor{{
		Source: trust.SourceInternal, Territory: "EE", Type: "wallet_provider", FingerprintSHA256: "z2",
	}}}

	setAnchorGauges(a)
	if v, ok := metricValue(gatherMetrics(), `trust_anchors_total{source="internal",territory="LV",type="pid_provider"}`); !ok || v != 1 {
		t.Fatalf("series for snapshot a = %v (present=%v), want 1", v, ok)
	}
	setAnchorGauges(b)
	buf := gatherMetrics()
	if v, ok := metricValue(buf, `trust_anchors_total{source="internal",territory="LV",type="pid_provider"}`); !ok || v != 0 {
		t.Fatalf("vanished series = %v (present=%v), want 0", v, ok)
	}
	if v, ok := metricValue(buf, `trust_anchors_total{source="internal",territory="EE",type="wallet_provider"}`); !ok || v != 1 {
		t.Fatalf("series for snapshot b = %v (present=%v), want 1", v, ok)
	}
}

// A declared anchor whose type's mandated channel is an unpublished EU LoTE
// is marked in the inventory — the declaration stands in for a list, and
// the marker is what keeps that gap visible.
func TestInventoryMarksDeclaredPendingLoTE(t *testing.T) {
	anchors := inventoryAnchors([]trust.Anchor{
		{TSPName: "PID CA", Type: "pid_provider", FingerprintSHA256: "aa"},
		{TSPName: "QEAA CA", Type: "qeaa_provider", FingerprintSHA256: "bb"},
		{TSPName: "Card CA", Type: "", FingerprintSHA256: "cc"},
	})
	b, err := json.Marshal(anchors)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"name":"PID CA","type":"pid_provider"`) || !strings.Contains(s, `"declaredPendingLote":true`) {
		t.Fatalf("pid_provider anchor not marked declaredPendingLote: %s", s)
	}
	if strings.Count(s, `"declaredPendingLote":true`) != 1 {
		t.Fatalf("only the LoTE-borne type may carry the marker: %s", s)
	}
}
