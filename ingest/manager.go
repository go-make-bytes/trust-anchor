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

// Refresher runs ingestion work (implemented by Pipeline; faked in tests):
// Refresh is one full upstream cycle; RefreshDeclared rebuilds a snapshot
// from freshly loaded operator-declared sources only, with no upstream
// fetch.
type Refresher interface {
	Refresh(ctx context.Context, prev *trust.Snapshot, boot *trust.Bootstrap) (*trust.Snapshot, error)
	RefreshDeclared(prev *trust.Snapshot, now time.Time) (*trust.Snapshot, bool, trust.DeclaredReport, error)
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

	// kick wakes the refresh task for an immediate cycle (TriggerRefresh).
	kick chan struct{}
	// refreshed is signalled at the end of every Refresh call (see Refreshed).
	refreshed chan struct{}

	// retention is how long a stored version is kept after a newer version
	// replaced it; the end of every completed cycle sweeps with it.
	retention time.Duration
	// storeTimeout bounds every store call the manager makes while it holds
	// its lock, so a store that stops answering cannot hang the refresh loop.
	storeTimeout time.Duration
	// persistOwed is set when a save failed and nothing has been saved
	// since: the next cycle saves even if nothing moved. Guarded by mu.
	persistOwed bool
	// now is the clock the sweep's cutoff is read from.
	now func() time.Time
}

// storeCallTimeout is the longest one snapshot save or sweep may take; a call
// that runs out of time is a failure like any other.
const storeCallTimeout = time.Minute

// DefaultSnapshotRetention is how long a replaced stored version is kept
// unless SetRetention says otherwise: 90 days.
const DefaultSnapshotRetention = 90 * 24 * time.Hour

// SetRetention sets how long a stored version is kept after a newer version
// replaced it (TRUST_SNAPSHOT_RETENTION).
func (m *Manager) SetRetention(d time.Duration) {
	m.mu.Lock()
	m.retention = d
	m.mu.Unlock()
}

// NewManager builds a Manager and points the freshness gauges at it.
func NewManager(pipeline Refresher, st store.Store, ev *events.Emitter, log *zap.Logger) *Manager {
	m := &Manager{
		pipeline: pipeline,
		store:    st,
		events:   ev,
		log:      log,
		kick:     make(chan struct{}, 1),

		refreshed: make(chan struct{}, 1),

		retention:    DefaultSnapshotRetention,
		storeTimeout: storeCallTimeout,
		now:          time.Now,
	}
	registerAgeGauge()
	activeSnapshotFn.Store((func() *trust.Snapshot)(m.Active))
	return m
}

// activate makes next the served snapshot and recomputes the volume gauges
// from it. Every activation site goes through here so the gauges can never
// lag what is actually served.
func (m *Manager) activate(next *trust.Snapshot) {
	m.active.Store(next)
	setAnchorGauges(next)
	setTerritoryFailedGauges(next)
	setSkippedGauges(next)
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
		m.activate(snap)
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

// Refreshed exposes a signal sent at the end of every Refresh call, completed
// or failed, whoever made it: the admin route runs its cycle in the request
// by calling Refresh directly, and the refresh task uses the signal to count
// its wait again from the snapshot now served. The signal coalesces (one slot).
func (m *Manager) Refreshed() <-chan struct{} { return m.refreshed }

func (m *Manager) signalRefreshed() {
	select {
	case m.refreshed <- struct{}{}:
	default:
	}
}

// SetRefresher swaps the ingestion implementation. Test use only.
func (m *Manager) SetRefresher(r Refresher) {
	m.mu.Lock()
	m.pipeline = r
	m.mu.Unlock()
}

// ReconcileDeclared re-reads the operator-declared sources (overlay +
// internal) against the active snapshot and activates the result when they
// changed — no upstream fetch, so it works with the LOTL unreachable. The
// server runs it at boot right after Initialize, so a restart activates an
// edited declaration immediately; Refresh runs the same reconcile before
// every cycle. Reports whether anything changed.
func (m *Manager) ReconcileDeclared(ctx context.Context) bool {
	ctx = context.WithoutCancel(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	_, changed, rep := m.reconcileDeclared(ctx, m.active.Load())
	// Boot inventory: logged unconditionally, changed or not — a restart is
	// the moment an operator most needs the served declared set named, and
	// an "unchanged" result can hide a failed load whose carry-over
	// reproduced the previous set.
	if active := m.active.Load(); active != nil {
		logInventory(m.log, active, rep)
	}
	return changed
}

// reconcileDeclared re-reads the declared sources against prev and, when
// they changed, persists and activates the rebuilt snapshot. Returns the
// snapshot subsequent work should build on, whether anything changed, and
// the per-source load report. The caller holds m.mu.
func (m *Manager) reconcileDeclared(ctx context.Context, prev *trust.Snapshot) (*trust.Snapshot, bool, trust.DeclaredReport) {
	if prev == nil {
		// Nothing restored or served yet — first activation belongs to the
		// full cycle.
		return nil, false, trust.DeclaredReport{}
	}
	next, changed, rep, err := m.pipeline.RefreshDeclared(prev, time.Now().UTC())
	if err != nil {
		m.log.Error("declared-source reconcile failed — keeping current snapshot", zap.Error(err))
		return prev, false, rep
	}
	if !changed {
		return prev, false, rep
	}
	// Serving fresh declared data beats failing the reconcile; a failed save
	// is owed and the next cycle saves again.
	m.persist(ctx, next)
	m.activate(next)
	if !next.Diff.Empty() {
		for _, e := range next.Diff.Entries {
			m.events.AnchorChange(nil, e.Kind, e.Territory, e.Fingerprint, e.Type, e.TSPName, e.ServiceName, e.Status, e.Detail, false)
		}
	}
	m.log.Info("operator-declared sources reconciled into a new snapshot",
		zap.String("snapshot", next.ID), zap.String("previous", prev.ID))
	return next, true, rep
}

// RefreshOutcome reports one refresh trigger's two independent halves — the
// operator-declared reconcile and the upstream ingestion cycle — so a caller
// can state each outcome truthfully instead of collapsing them into one
// status. Snapshot is what is being served when the call returns; it is nil
// only when nothing has ever been served and the cycle failed.
type RefreshOutcome struct {
	Snapshot        *trust.Snapshot
	Changed         bool // either half changed what is served
	DeclaredChanged bool
	Declared        trust.DeclaredSourceState
	CycleErr        error // nil when the cycle produced a snapshot
}

// Refresh runs one ingestion cycle. On failure the previous snapshot stays
// active and a security event is raised — the one unacceptable failure mode
// is serving unverified or partial data, not serving slightly old data. The
// outcome reports the declared and cycle halves separately: a declared edit
// applies (and is reported as applied) even when the cycle fails.
func (m *Manager) Refresh(ctx context.Context) RefreshOutcome {
	// Detach: ctx may be (derived from) a pooled request context, and
	// persistence must not be cancelled halfway by a disconnecting client.
	ctx = context.WithoutCancel(ctx)

	// Registered first so it runs last, after the lock is released: whoever
	// waits on Refreshed sees the snapshot this call leaves behind.
	defer m.signalRefreshed()

	m.mu.Lock()
	defer m.mu.Unlock()

	prev := m.active.Load()
	boot := m.bootstrap.Load()

	// Declared sources first: an operator edit takes effect on this trigger
	// even when the upstream fetch below fails — that error path would
	// otherwise return before the cycle's own declared load ever runs.
	prev, declaredChanged, declRep := m.reconcileDeclared(ctx, prev)
	if declaredChanged {
		logInventory(m.log, prev, declRep)
	}
	out := RefreshOutcome{
		Snapshot:        prev,
		Changed:         declaredChanged,
		DeclaredChanged: declaredChanged,
		Declared:        declRep.Internal,
	}

	next, err := m.pipeline.Refresh(ctx, prev, boot)
	if err != nil {
		m.events.RefreshFailure(nil, "cycle", err.Error())
		m.log.Error("refresh cycle failed — keeping last good snapshot", zap.Error(err))
		out.CycleErr = err
		return out
	}
	// The cycle reloads the declared source itself; its report is the
	// fresher of the two.
	if next.DeclaredLoad != nil {
		out.Declared = next.DeclaredLoad.Internal
	}

	cycleChanged := prev == nil ||
		next.ID != prev.ID ||
		!pendingEqual(prev.Pending, next.Pending) ||
		territoryStateChanged(prev, next)

	// Persist whatever a restart would restore differently: a served change,
	// the inputs the next cycle's download skip rests on, the dates and
	// digests of the lists (restoreStateMoved) — those reach the store without
	// being reported as a change to what is served — and a save that failed
	// before, which stays owed until one succeeds. A cycle that moved nothing
	// does not call the store. Serving fresh verified data beats failing the
	// cycle: a failed save is raised and the next cycle tries again.
	if m.persistOwed || cycleChanged || lotlInputChanged(prev, next) || restoreStateMoved(prev, next) {
		m.persist(ctx, next)
	}
	m.activate(next)
	setLastSyncSuccess(time.Now().UTC())
	if prev == nil {
		// First activation: the declared set went from nothing to something
		// and there is no other record of it — log the inventory from the
		// cycle's own load report.
		rep := trust.DeclaredReport{}
		if next.DeclaredLoad != nil {
			rep = *next.DeclaredLoad
		}
		logInventory(m.log, next, rep)
	}

	if cycleChanged && !next.Diff.Empty() {
		for _, e := range next.Diff.Entries {
			m.events.AnchorChange(nil, e.Kind, e.Territory, e.Fingerprint, e.Type, e.TSPName, e.ServiceName, e.Status, e.Detail, false)
		}
	}

	out.Snapshot = next
	out.Changed = declaredChanged || cycleChanged
	m.log.Info("refresh cycle complete",
		zap.String("snapshot", next.ID),
		zap.Bool("changed", out.Changed),
		logUint("lotl_sequence", next.LOTLSequence),
		logInt("pending", len(next.Pending)))

	m.sweep(ctx)
	return out
}

// persist saves snap. A failure is raised as a refresh-failure event and
// logged, and the save is owed: the next cycle saves again even when nothing
// moved, until a save succeeds. The caller holds m.mu.
func (m *Manager) persist(ctx context.Context, snap *trust.Snapshot) {
	// Bounded: the lock is held, so a store that stops answering must not
	// hang the refresh loop; running out of time is a failure like any other.
	sctx, cancel := context.WithTimeout(ctx, m.storeTimeout)
	defer cancel()
	if err := m.store.SaveSnapshot(sctx, snap); err != nil {
		m.persistOwed = true
		m.events.RefreshFailure(nil, "persist", err.Error())
		m.log.Error("snapshot persistence failed — serving from memory", zap.Error(err))
		return
	}
	m.persistOwed = false
}

// sweep removes the stored versions that a newer version replaced longer ago
// than the retention. It runs at the end of every completed cycle, saved or
// not, because versions age without saves. A failure never fails the cycle and
// never changes what is served: it is logged and raised as a refresh failure of
// its own stage. The caller holds m.mu.
func (m *Manager) sweep(ctx context.Context) {
	before := m.now().UTC().Add(-m.retention)
	sctx, cancel := context.WithTimeout(ctx, m.storeTimeout)
	defer cancel()
	removed, err := m.store.SweepSnapshots(sctx, before)
	if err != nil {
		m.events.RefreshFailure(nil, "sweep", err.Error())
		m.log.Error("stored-version sweep failed — what is served is unchanged", zap.Error(err))
		return
	}
	if removed > 0 {
		// A removal of stored history leaves a record.
		m.events.SnapshotsSwept(nil, removed, before)
		m.log.Info("stored versions swept",
			zap.Int("removed", removed), zap.Time("replaced_before", before))
	}
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

	sctx, cancel := context.WithTimeout(detach(ctx), m.storeTimeout)
	defer cancel()
	if err := m.store.SaveSnapshot(sctx, next); err != nil {
		return nil, fmt.Errorf("ingest: persist approved snapshot: %w", err)
	}
	m.persistOwed = false
	m.activate(next)

	m.events.PendingApproved(ctx, fingerprint, actor, "api")
	a := approved.Anchor
	m.events.AnchorChange(ctx, trust.DiffAdded, a.Territory, a.FingerprintSHA256, a.Type, a.TSPName, a.ServiceName, a.Status, "approved from pending", false)
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

// territoryStateChanged reports whether any territory's health, sequence or
// skipped-service set moved between two snapshots. Health (carried-over,
// failed, skipped) is deliberately outside the content id, so this check is
// what makes a health flip still persist and activate a new snapshot.
func territoryStateChanged(prev, next *trust.Snapshot) bool {
	for _, t := range next.Territories {
		pt := prev.Territory(t.Code)
		if pt == nil || pt.CarriedOver != t.CarriedOver || pt.TLSequence != t.TLSequence ||
			pt.Failed != t.Failed || pt.FailureReason != t.FailureReason ||
			!skippedEqual(pt.Skipped, t.Skipped) {
			return true
		}
	}
	return false
}

// lotlInputChanged reports whether the list-of-the-lists inputs the next
// cycle's download skip rests on — the published digest, and with it the
// carried pointer set — moved between two snapshots. They are not trust
// content, so they are outside the id and outside "changed"; but without
// persisting them a snapshot stored before the digest existed would force a
// full download after every restart, forever. With this it happens once. A
// digest change with an unchanged id is otherwise rare: the list's sequence
// number, which is in the id, moves with every publication. prev is never
// nil here: a first cycle persists on cycleChanged before this is consulted.
func lotlInputChanged(prev, next *trust.Snapshot) bool {
	return prev.LOTLDigest != next.LOTLDigest
}

// restoreStateMoved reports whether anything a restart restores — beyond what
// the id, the health check and the list-of-the-lists digest already cover —
// differs between two snapshots: a territory's next-update, issue time or
// source digest, a territory that is gone, and the list of the lists' own
// next-update or issue time. None of these is trust content or a served
// change, so none moves the id or the reported "changed"; without storing
// them a restart would bring back dates and digests weeks old. The free-text
// failure reasons are left out on purpose: their text differs on every failure.
func restoreStateMoved(prev, next *trust.Snapshot) bool {
	if !sameInstant(prev.LOTLNextUpdate, next.LOTLNextUpdate) || !prev.LOTLIssueTime.Equal(next.LOTLIssueTime) {
		return true
	}
	if len(prev.Territories) != len(next.Territories) {
		return true
	}
	for _, t := range next.Territories {
		pt := prev.Territory(t.Code)
		if pt == nil || !sameInstant(pt.NextUpdate, t.NextUpdate) || !pt.IssueTime.Equal(t.IssueTime) ||
			pt.SourceDigest != t.SourceDigest {
			return true
		}
	}
	return false
}

// sameInstant compares two optional times by the instant they name.
func sameInstant(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// skippedEqual compares two skipped-service sets by identity (fingerprint,
// or service when the bytes never decoded) and reason.
func skippedEqual(a, b []trust.SkippedService) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(s trust.SkippedService) string {
		return s.TSPName + "/" + s.ServiceName + "/" + s.FingerprintSHA256 + "/" + s.Reason
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[key(s)]++
	}
	for _, s := range b {
		k := key(s)
		if seen[k] == 0 {
			return false
		}
		seen[k]--
	}
	return true
}
