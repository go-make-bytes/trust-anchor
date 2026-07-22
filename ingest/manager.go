package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/go-make-bytes/trust-anchor/events"
	"github.com/go-make-bytes/trust-anchor/store"
	"github.com/go-make-bytes/trust-anchor/trust"
)

// Refresher runs one ingestion cycle (implemented by Pipeline; faked in
// tests).
type Refresher interface {
	Refresh(ctx context.Context, prev *trust.Snapshot, boot *trust.Bootstrap) (*trust.Snapshot, error)
}

// Manager owns the active snapshot and bootstrap state: startup bootstrap
// from the store, refresh cycles (fail-safe: a failed cycle never replaces
// the last good snapshot), hold-mode approvals and bootstrap activation.
// Reads are lock-free (atomic pointers); mutations are serialized.
type Manager struct {
	mu        sync.Mutex
	active    atomic.Pointer[trust.Snapshot]
	bootstrap atomic.Pointer[trust.Bootstrap]

	pipeline Refresher
	store    store.Store
	events   *events.Emitter
	log      *zap.Logger

	// kick wakes the refresh task for an immediate cycle (admin /v1/refresh).
	kick chan struct{}
}

// NewManager builds a Manager.
func NewManager(pipeline Refresher, st store.Store, ev *events.Emitter, log *zap.Logger) *Manager {
	return &Manager{
		pipeline: pipeline,
		store:    st,
		events:   ev,
		log:      log,
		kick:     make(chan struct{}, 1),
	}
}

// Initialize loads the persisted bootstrap + snapshot. When the store has no
// bootstrap yet, the operator-pinned seed (LOTL_BOOTSTRAP_CERTS_PATH — a signer
// manifest that carries its own OJ reference, or a PEM/DER path) is required
// and persisted as version 1; afterwards the store is authoritative and the
// path is ignored.
func (m *Manager) Initialize(ctx context.Context, seedPath string) error {
	boot, err := m.store.LoadLatestBootstrap(ctx)
	if err != nil {
		return fmt.Errorf("ingest: load bootstrap from store: %w", err)
	}
	if boot == nil {
		if seedPath == "" {
			return fmt.Errorf("ingest: no bootstrap in store and no LOTL_BOOTSTRAP_CERTS_PATH configured — the operator-pinned signer set is required at first install")
		}
		// Operator-pinned signer set: seed from the pinned manifest/PEM path.
		boot, err = trust.SeedBootstrap(seedPath, time.Now().UTC())
		if err != nil {
			return err
		}
		m.log.Info("seeded LOTL bootstrap from pinned certs (LOTL_BOOTSTRAP_CERTS_PATH)",
			zap.String("oj_reference", boot.OJReference),
			zap.Strings("fingerprints", boot.Fingerprints()))
		if err := m.store.SaveBootstrap(ctx, boot); err != nil {
			return fmt.Errorf("ingest: persist seeded bootstrap: %w", err)
		}
	}
	m.bootstrap.Store(boot)

	snap, err := m.store.LoadLatestSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("ingest: load snapshot from store: %w", err)
	}
	if snap != nil {
		m.active.Store(snap)
		m.log.Info("restored snapshot from store",
			zap.String("snapshot", snap.ID), logUint("lotl_sequence", snap.LOTLSequence))
	}
	return nil
}

// Active returns the served snapshot (nil until the first successful cycle
// or store restore). Readiness gates on it.
func (m *Manager) Active() *trust.Snapshot { return m.active.Load() }

// Bootstrap returns the active bootstrap set.
func (m *Manager) Bootstrap() *trust.Bootstrap { return m.bootstrap.Load() }

// TriggerRefresh requests an immediate refresh cycle from the refresh task
// (non-blocking; coalesces with an already-pending trigger).
func (m *Manager) TriggerRefresh() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Kick exposes the refresh trigger channel to the refresh task.
func (m *Manager) Kick() <-chan struct{} { return m.kick }

// SetRefresher swaps the ingestion implementation. Test use only.
func (m *Manager) SetRefresher(r Refresher) {
	m.mu.Lock()
	m.pipeline = r
	m.mu.Unlock()
}

// Refresh runs one ingestion cycle. On failure the previous snapshot stays
// active and a security event is raised — the one unacceptable failure mode
// is serving unverified or partial data, not serving slightly old data.
func (m *Manager) Refresh(ctx context.Context) (*trust.Snapshot, bool, error) {
	// Detach: ctx may be (derived from) a pooled request context, and
	// persistence must not be cancelled halfway by a disconnecting client.
	ctx = context.WithoutCancel(ctx)

	m.mu.Lock()
	defer m.mu.Unlock()

	prev := m.active.Load()
	boot := m.bootstrap.Load()

	next, err := m.pipeline.Refresh(ctx, prev, boot)
	if err != nil {
		m.events.RefreshFailure(nil, "cycle", err.Error())
		m.log.Error("refresh cycle failed — keeping last good snapshot", zap.Error(err))
		return prev, false, err
	}

	changed := prev == nil ||
		next.ID != prev.ID ||
		!pendingEqual(prev.Pending, next.Pending) ||
		carriedOverChanged(prev, next)

	if changed {
		if err := m.store.SaveSnapshot(ctx, next); err != nil {
			// Serving fresh verified data beats failing the cycle; the next
			// cycle retries persistence.
			m.events.RefreshFailure(nil, "persist", err.Error())
			m.log.Error("snapshot persistence failed — serving from memory", zap.Error(err))
		}
	}
	m.active.Store(next)

	if changed && !next.Diff.Empty() {
		for _, e := range next.Diff.Entries {
			m.events.AnchorChange(nil, e.Kind, e.Territory, e.Fingerprint, e.TSPName, e.ServiceName, e.Status, e.Detail, false)
		}
	}

	m.log.Info("refresh cycle complete",
		zap.String("snapshot", next.ID),
		zap.Bool("changed", changed),
		logUint("lotl_sequence", next.LOTLSequence),
		logInt("pending", len(next.Pending)))
	return next, changed, nil
}

// ApprovePending approves a held addition by certificate fingerprint: the
// anchor moves from the pending set into its territory's served anchors in a
// new persisted snapshot.
func (m *Manager) ApprovePending(ctx *azugo.Context, fingerprint, actor string) (*trust.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur := m.active.Load()
	if cur == nil {
		return nil, fmt.Errorf("ingest: no active snapshot")
	}

	idx := -1
	for i, pa := range cur.Pending {
		if pa.Anchor.FingerprintSHA256 == fingerprint {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("ingest: no pending anchor with fingerprint %s", fingerprint)
	}

	next, err := cloneSnapshot(cur)
	if err != nil {
		return nil, err
	}
	approved := next.Pending[idx]
	next.Pending = append(next.Pending[:idx], next.Pending[idx+1:]...)

	t := next.Territory(approved.Anchor.Territory)
	if t == nil {
		t = &trust.Territory{Code: approved.Anchor.Territory}
		next.Territories = append(next.Territories, t)
		sort.Slice(next.Territories, func(i, j int) bool { return next.Territories[i].Code < next.Territories[j].Code })
	}
	t.Anchors = append(t.Anchors, approved.Anchor)
	sort.Slice(t.Anchors, func(i, j int) bool {
		a, b := t.Anchors[i], t.Anchors[j]
		if a.TSPName != b.TSPName {
			return a.TSPName < b.TSPName
		}
		if a.ServiceName != b.ServiceName {
			return a.ServiceName < b.ServiceName
		}
		return a.FingerprintSHA256 < b.FingerprintSHA256
	})

	next.GeneratedAt = time.Now().UTC()
	next.ComputeID()
	next.PrevID = cur.ID
	next.Diff = trust.ComputeDiff(cur, next)

	if err := m.store.SaveSnapshot(detach(ctx), next); err != nil {
		return nil, fmt.Errorf("ingest: persist approved snapshot: %w", err)
	}
	m.active.Store(next)

	m.events.PendingApproved(ctx, fingerprint, actor, "api")
	a := approved.Anchor
	m.events.AnchorChange(ctx, trust.DiffAdded, a.Territory, a.FingerprintSHA256, a.TSPName, a.ServiceName, a.Status, "approved from pending", false)
	return next, nil
}

// detach derives a cancellation-free context from a (possibly nil, possibly
// pooled) request context — persistence must never be cancelled by a
// disconnecting client, and timeout watchers must not race pooled contexts.
func detach(ctx *azugo.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}

// cloneSnapshot deep-copies a snapshot via JSON (snapshots are small — tens
// of certificates) so the served copy is never mutated in place.
func cloneSnapshot(s *trust.Snapshot) (*trust.Snapshot, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var out trust.Snapshot
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func pendingEqual(a, b []trust.PendingAnchor) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Anchor.FingerprintSHA256 != b[i].Anchor.FingerprintSHA256 || a[i].Anchor.Territory != b[i].Anchor.Territory {
			return false
		}
	}
	return true
}

func carriedOverChanged(prev, next *trust.Snapshot) bool {
	for _, t := range next.Territories {
		pt := prev.Territory(t.Code)
		if pt == nil || pt.CarriedOver != t.CarriedOver || pt.TLSequence != t.TLSequence {
			return true
		}
	}
	return false
}
