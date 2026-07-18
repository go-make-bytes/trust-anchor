package ingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/gmb-sig/trust-anchor/events"
	"github.com/gmb-sig/trust-anchor/store"
	"github.com/gmb-sig/trust-anchor/trust"
)

// fakeRefresher returns canned snapshots/errors.
type fakeRefresher struct {
	snap *trust.Snapshot
	err  error
}

func (f *fakeRefresher) Refresh(_ context.Context, prev *trust.Snapshot, _ *trust.Bootstrap) (*trust.Snapshot, error) {
	if f.err != nil {
		return nil, f.err
	}
	snap := f.snap
	if prev != nil {
		snap.PrevID = prev.ID
	}
	snap.Diff = trust.ComputeDiff(prev, snap)
	return snap, nil
}

func managerForTest(t *testing.T, r Refresher) (*Manager, *store.Memory) {
	t.Helper()
	st := store.NewMemory()
	m := NewManager(r, st, events.New(zap.NewNop()), zap.NewNop())
	return m, st
}

func seedBootstrap(t *testing.T, st *store.Memory) *trust.Bootstrap {
	t.Helper()
	b := &trust.Bootstrap{Version: 1, OJReference: "C/2026/1944", ActivatedAt: time.Now().UTC(), Seeded: true}
	if err := st.SaveBootstrap(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	return b
}

func managerSnapshot(t *testing.T) *trust.Snapshot {
	t.Helper()
	snap := &trust.Snapshot{
		GeneratedAt:  time.Now().UTC(),
		LOTLSequence: 388,
		Territories: []*trust.Territory{
			{Code: "LV", TLSequence: 51, Anchors: []trust.Anchor{{
				Territory: "LV", Source: trust.SourceTL, TSPName: "LVRTC", ServiceName: "ICA",
				Status: trust.NormalizeStatus("granted"), FingerprintSHA256: "aa11", CertDER: []byte{1},
			}}},
		},
	}
	snap.ComputeID()
	return snap
}

func TestManagerRefreshAdoptsAndPersists(t *testing.T) {
	snap := managerSnapshot(t)
	m, st := managerForTest(t, &fakeRefresher{snap: snap})
	seedBootstrap(t, st)
	if err := m.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}

	got, changed, err := m.Refresh(context.Background())
	if err != nil || !changed {
		t.Fatalf("refresh: changed=%v err=%v", changed, err)
	}
	if m.Active().ID != got.ID {
		t.Fatal("active snapshot not swapped")
	}

	persisted, err := st.LoadLatestSnapshot(context.Background())
	if err != nil || persisted == nil || persisted.ID != snap.ID {
		t.Fatalf("snapshot not persisted: %v %v", persisted, err)
	}
}

func TestManagerFailSafeKeepsLastGood(t *testing.T) {
	snap := managerSnapshot(t)
	fake := &fakeRefresher{snap: snap}
	m, st := managerForTest(t, fake)
	seedBootstrap(t, st)
	if err := m.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	fake.err = errors.New("upstream exploded")
	prev, changed, err := m.Refresh(context.Background())
	if err == nil || changed {
		t.Fatal("failed cycle reported success")
	}
	if prev == nil || prev.ID != snap.ID || m.Active().ID != snap.ID {
		t.Fatal("last good snapshot not kept after failure")
	}
}

func TestManagerInitializeRestoresFromStore(t *testing.T) {
	snap := managerSnapshot(t)
	m, st := managerForTest(t, &fakeRefresher{err: errors.New("network down")})
	seedBootstrap(t, st)
	if err := st.SaveSnapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}

	if err := m.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if m.Active() == nil || m.Active().ID != snap.ID {
		t.Fatal("snapshot not restored from store")
	}
}

func TestManagerInitializeRequiresBootstrap(t *testing.T) {
	m, _ := managerForTest(t, &fakeRefresher{})
	if err := m.Initialize(context.Background(), ""); err == nil {
		t.Fatal("Initialize succeeded without bootstrap")
	}
}

func TestManagerApprovePending(t *testing.T) {
	snap := managerSnapshot(t)
	held := trust.Anchor{
		Territory: "LV", Source: trust.SourceTL, TSPName: "LVRTC", ServiceName: "New ICA",
		Status: trust.NormalizeStatus("granted"), FingerprintSHA256: "bb22", CertDER: []byte{2},
	}
	snap.Pending = []trust.PendingAnchor{{Anchor: held, FirstSeen: time.Now().UTC()}}
	snap.ComputeID()

	m, st := managerForTest(t, &fakeRefresher{snap: snap})
	seedBootstrap(t, st)
	if err := m.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := m.ApprovePending(nil, "nope", "ops"); err == nil {
		t.Fatal("approving unknown fingerprint succeeded")
	}

	next, err := m.ApprovePending(nil, "bb22", "ops")
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Pending) != 0 {
		t.Fatal("approved anchor still pending")
	}
	var found bool
	for _, a := range next.Territory("LV").Anchors {
		if a.FingerprintSHA256 == "bb22" {
			found = true
		}
	}
	if !found {
		t.Fatal("approved anchor not in bundle")
	}
	if next.ID == snap.ID {
		t.Fatal("snapshot ID unchanged after approval")
	}
	if m.Active().ID != next.ID {
		t.Fatal("approved snapshot not active")
	}
}
