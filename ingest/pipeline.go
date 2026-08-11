package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"go.uber.org/zap"

	"github.com/go-make-bytes/trust-anchor/events"
	"github.com/go-make-bytes/trust-anchor/trust"
	"github.com/go-make-bytes/trust-anchor/tsl"
)

// Activation modes (TRUST_ACTIVATION_MODE).
const (
	ModeAuto = "auto"
	ModeHold = "hold"
)

// Config parameterizes the ingestion pipeline.
type Config struct {
	LOTLURL          string
	Territories      []string
	AcceptedStatuses []string
	// AcceptedServiceTypes is the set of trusted-list service-type
	// identifiers the extractor admits (registered Svctype URIs; empty means
	// CA/QC only). Services of other types are counted and reported.
	AcceptedServiceTypes []string
	ActivationMode       string
	HoldAutoRelease      time.Duration
	// InternalTrustSource is the optional operator-declared anchor file
	// (INTERNAL_TRUST_SOURCE, trust.LoadInternal). Empty means none configured.
	InternalTrustSource string
	// StaleGrace is the grace period past a list's NextUpdate before its data
	// is flagged stale (served with a warning, never dropped).
	StaleGrace time.Duration
}

// Pipeline executes one ingestion cycle: LOTL → pivots → national TLs →
// anchors → snapshot. It is stateless between cycles; all state lives in the
// snapshots it is handed and returns.
type Pipeline struct {
	cfg     Config
	fetcher *Fetcher
	events  *events.Emitter
	log     *zap.Logger
}

// NewPipeline builds a Pipeline.
func NewPipeline(cfg Config, fetcher *Fetcher, ev *events.Emitter, log *zap.Logger) *Pipeline {
	return &Pipeline{cfg: cfg, fetcher: fetcher, events: ev, log: log}
}

func logUint(k string, v uint64) zap.Field { return zap.Uint64(k, v) }
func logInt(k string, v int) zap.Field     { return zap.Int(k, v) }

// sha256hex is the lowercase hex SHA-256 of b — the value a TL publisher serves
// in the sibling ".sha2" (confirmed equal). Stored per territory for P2 change
// detection.
func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Refresh runs one full cycle against the previous active snapshot (nil on
// first run) and the active bootstrap set. On total failure it returns an
// error and the caller keeps serving prev (fail-safe). Per-territory failures
// carry the previous territory data over instead of failing the cycle.
func (p *Pipeline) Refresh(ctx context.Context, prev *trust.Snapshot, boot *trust.Bootstrap) (*trust.Snapshot, error) {
	now := time.Now().UTC()

	lotl, signers, pivotSeq, err := p.ingestLOTL(ctx, prev, boot)
	if err != nil {
		return nil, err
	}

	if prev != nil && lotl.SchemeInformation.TSLSequenceNumber < prev.LOTLSequence {
		return nil, fmt.Errorf("ingest: LOTL sequence regression: %d < %d", lotl.SchemeInformation.TSLSequenceNumber, prev.LOTLSequence)
	}

	next := &trust.Snapshot{
		GeneratedAt:      now,
		LOTLSequence:     lotl.SchemeInformation.TSLSequenceNumber,
		LOTLIssueTime:    lotl.SchemeInformation.ListIssueDateTime,
		LOTLNextUpdate:   lotl.SchemeInformation.NextUpdate.DateTime,
		LOTLPivotSeq:     pivotSeq,
		AdvertisedOJ:     advertisedOJReference(lotl.SchemeInformation.SchemeInformationURI.URI),
		BootstrapOJRef:   boot.OJReference,
		BootstrapVersion: boot.Version,
	}
	for _, c := range signers {
		next.LOTLSignersDER = append(next.LOTLSignersDER, c.Raw)
	}

	// National trusted lists.
	territories := append([]string(nil), p.cfg.Territories...)
	sort.Strings(territories)
	for _, code := range territories {
		t, err := p.ingestTerritory(ctx, lotl, code, prev, now)
		if err != nil {
			return nil, err
		}
		next.Territories = append(next.Territories, t)
	}

	p.applyDeclaredSources(prev, next, now)

	p.applyHoldMode(prev, next, now)

	next.ComputeID()
	if prev != nil {
		next.PrevID = prev.ID
	}
	next.Diff = trust.ComputeDiff(prev, next)

	return next, nil
}

// applyDeclaredSources loads the operator-declared anchor source — the
// internal trust source — into next. A failed load never fails the cycle:
// the previous set is carried over (the same fail-safe the territories
// have) and the source's security event is emitted, because a typo in an
// operator file must not take down trusted-list ingestion. The returned
// report (also attached to next) keeps the load outcomes distinguishable
// for the inventory log — a carry-over produces the same anchor set as an
// unchanged file, and only the report can tell them apart.
func (p *Pipeline) applyDeclaredSources(prev, next *trust.Snapshot, now time.Time) trust.DeclaredReport {
	var prevInternal []trust.Anchor
	if prev != nil {
		prevInternal = prev.Internal
	}
	var rep trust.DeclaredReport
	next.Internal, rep.Internal = p.declaredSet("internal trust source", declaredSourceInternal,
		p.cfg.InternalTrustSource != "", prevInternal,
		func() ([]trust.Anchor, error) { return trust.LoadInternal(p.cfg.InternalTrustSource, now) },
		func(err error) { p.events.InternalSourceError(nil, err) })
	next.DeclaredLoad = &rep
	return rep
}

// declaredSet loads one operator-declared anchor set; on failure it returns
// the previous set unchanged (carry-over) after emitting the source's event
// and raising the source's 0/1 failure gauge.
func (p *Pipeline) declaredSet(name, key string, configured bool, prevSet []trust.Anchor, load func() ([]trust.Anchor, error), emit func(error)) ([]trust.Anchor, trust.DeclaredSourceState) {
	state := trust.DeclaredSourceState{Configured: configured}
	set, err := load()
	if err != nil {
		emit(err)
		p.log.Warn(name+" failed to load — carrying over last good set", zap.Error(err))
		setDeclaredSourceFailed(key, true)
		state.CarriedOver = true
		state.Error = err.Error()
		state.Count = len(prevSet)
		return prevSet, state
	}
	setDeclaredSourceFailed(key, false)
	state.Count = len(set)
	return set, state
}

// RefreshDeclared rebuilds prev with freshly loaded operator-declared
// sources and no upstream fetch — the boot / on-demand reconcile, so an
// edited declaration takes effect even while the trusted-list upstream is
// unreachable. Returns a nil snapshot when the declared sets are unchanged;
// the report is returned even then, because "unchanged" covers both an
// identical file and a failed load whose carry-over reproduced the previous
// set — outcomes the caller must be able to tell apart. prev must not be
// nil: with nothing to build on, first activation belongs to a full cycle.
func (p *Pipeline) RefreshDeclared(prev *trust.Snapshot, now time.Time) (*trust.Snapshot, bool, trust.DeclaredReport, error) {
	if prev == nil {
		return nil, false, trust.DeclaredReport{}, errors.New("ingest: declared-source reconcile requires a previous snapshot")
	}
	next, err := cloneSnapshot(prev)
	if err != nil {
		return nil, false, trust.DeclaredReport{}, err
	}
	rep := p.applyDeclaredSources(prev, next, now)
	if next.ComputeID() == prev.ID {
		return nil, false, rep, nil
	}
	next.GeneratedAt = now
	next.PrevID = prev.ID
	next.Diff = trust.ComputeDiff(prev, next)
	return next, true, rep, nil
}

// ingestLOTL fetches and verifies the LOTL, processing the pivot chain when
// the current signer set no longer verifies it directly.
func (p *Pipeline) ingestLOTL(ctx context.Context, prev *trust.Snapshot, boot *trust.Bootstrap) (*tsl.TrustedList, []*x509.Certificate, uint64, error) {
	if err := p.fetcher.AllowURL(p.cfg.LOTLURL); err != nil {
		return nil, nil, 0, err
	}
	raw, err := p.fetcher.Fetch(ctx, p.cfg.LOTLURL)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ingest: fetch LOTL: %w", err)
	}

	// Unverified pre-parse: pivot URLs only. Trust decisions follow only
	// after signature verification.
	pre, err := tsl.Parse(raw)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ingest: pre-parse LOTL: %w", err)
	}
	refs := pivotRefs(pre.SchemeInformation.SchemeInformationURI.URI)
	maxPivot := uint64(0)
	if len(refs) > 0 {
		maxPivot = refs[len(refs)-1].seq
	}

	// Signer-set precedence: continue from the previous snapshot's
	// (pivot-rotated) signer set when one exists; otherwise start from the
	// operator-pinned bootstrap set.
	var signers []*x509.Certificate
	var pivotSeq uint64
	switch {
	case prev != nil && len(prev.LOTLSignersDER) > 0:
		signers, err = prev.LOTLSigners()
		pivotSeq = prev.LOTLPivotSeq
	default:
		signers, err = boot.Certificates()
	}
	if err != nil {
		return nil, nil, 0, err
	}

	verified, verr := tsl.Verify(raw, signers)
	if verr == nil {
		// The current set supersedes any unprocessed pivots — they are
		// historical rotations that ended in this set.
		if maxPivot > pivotSeq {
			pivotSeq = maxPivot
		}
	} else {
		// Direct verification failed — the signer set may have rotated via
		// pivots since our last cycle. Walk the unprocessed chain.
		p.log.Info("LOTL direct verification failed, processing pivot chain", zap.Error(verr))
		signers, pivotSeq, err = p.walkPivots(ctx, refs, signers, pivotSeq)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("ingest: pivot chain: %w (after direct verification failed: %w)", err, verr)
		}
		verified, err = tsl.Verify(raw, signers)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("ingest: LOTL verification failed after pivot processing: %w", err)
		}
	}

	lotl, err := tsl.Parse(verified)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ingest: parse verified LOTL: %w", err)
	}
	if lotl.SchemeInformation.TSLType != tsl.TSLTypeEUListOfTheLists {
		return nil, nil, 0, fmt.Errorf("ingest: LOTL has unexpected TSLType %q", lotl.SchemeInformation.TSLType)
	}
	return lotl, signers, pivotSeq, nil
}

// ingestTerritory fetches, verifies and extracts one national TL. On failure
// it carries over the previous snapshot's territory data (fail-safe); when no
// previous data exists the whole cycle fails — a partial first snapshot must
// never be served.
func (p *Pipeline) ingestTerritory(ctx context.Context, lotl *tsl.TrustedList, code string, prev *trust.Snapshot, now time.Time) (*trust.Territory, error) {
	t, err := p.fetchTerritory(ctx, lotl, code, prev, now)
	if err == nil {
		return t, nil
	}

	if errors.Is(err, ErrEgressBlocked) {
		p.events.EgressBlocked(nil, code, err.Error())
	} else {
		p.events.RefreshFailure(nil, "territory:"+code, err.Error())
	}

	var prevT *trust.Territory
	if prev != nil {
		prevT = prev.Territory(code)
	}
	if prevT == nil {
		return nil, fmt.Errorf("ingest: territory %s failed with no previous data to fall back on: %w", code, err)
	}

	p.log.Warn("territory refresh failed — carrying over last good data",
		zap.String("territory", code), zap.Error(err))
	carried := *prevT
	carried.CarriedOver = true
	carried.CarriedOverReason = err.Error()
	carried.Anchors = append([]trust.Anchor(nil), prevT.Anchors...)
	if carried.StaleAt(now, p.cfg.StaleGrace) {
		p.events.Stale(nil, code, *carried.NextUpdate)
	}
	return &carried, nil
}

func (p *Pipeline) fetchTerritory(ctx context.Context, lotl *tsl.TrustedList, code string, prev *trust.Snapshot, now time.Time) (*trust.Territory, error) {
	ptr, err := lotl.PointerFor(code)
	if err != nil {
		return nil, err
	}
	if err := p.fetcher.AllowURL(ptr.TSLLocation); err != nil {
		return nil, err
	}

	// P2 input-side change detection: when the sibling ".sha2" matches the digest
	// stored last cycle and the territory is still within NextUpdate, reuse the
	// previous (already-verified) data without re-downloading + re-verifying the
	// full TL. The ".sha2" only decides whether to fetch — trust still comes from
	// the XMLDSig verification below on anything we do download. A list past
	// NextUpdate, with no stored digest, with no NextUpdate, or whose digest
	// fetch fails always falls through to a full fetch (anti-freeze).
	if prev != nil {
		if prevT := prev.Territory(code); prevT != nil && prevT.SourceDigest != "" &&
			prevT.NextUpdate != nil && !prevT.StaleAt(now, p.cfg.StaleGrace) {
			if digest, derr := p.fetcher.FetchDigest(ctx, ptr.TSLLocation); derr == nil && digest == prevT.SourceDigest {
				reused := *prevT
				reused.CarriedOver = false // confirmed unchanged, not a fail-safe carry-over
				reused.Anchors = append([]trust.Anchor(nil), prevT.Anchors...)
				p.log.Debug("territory unchanged (.sha2 match) — skipped full fetch",
					zap.String("territory", code), zap.String("digest", digest))
				return &reused, nil
			}
		}
	}

	signers, err := ptr.Certificates()
	if err != nil {
		return nil, fmt.Errorf("pointer certs for %s: %w", code, err)
	}

	raw, err := p.fetcher.Fetch(ctx, ptr.TSLLocation)
	if err != nil {
		return nil, err
	}
	tl, err := tsl.VerifyAndParse(raw, signers)
	if err != nil {
		return nil, fmt.Errorf("territory %s: %w", code, err)
	}

	if tl.SchemeInformation.SchemeTerritory != code {
		return nil, fmt.Errorf("territory %s: list declares SchemeTerritory %q", code, tl.SchemeInformation.SchemeTerritory)
	}
	if prev != nil {
		if prevT := prev.Territory(code); prevT != nil && tl.SchemeInformation.TSLSequenceNumber < prevT.TLSequence {
			return nil, fmt.Errorf("territory %s: sequence regression: %d < %d", code, tl.SchemeInformation.TSLSequenceNumber, prevT.TLSequence)
		}
	}

	anchors, warnings, err := trust.ExtractAnchors(tl, code, p.cfg.AcceptedStatuses, p.cfg.AcceptedServiceTypes, now)
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		p.log.Warn("skipped trust service during extraction",
			zap.String("territory", code), zap.String("tsp", w.TSPName),
			zap.String("service", w.ServiceName), zap.String("reason", w.Reason))
	}

	t := &trust.Territory{
		Code:         code,
		TLSequence:   tl.SchemeInformation.TSLSequenceNumber,
		IssueTime:    tl.SchemeInformation.ListIssueDateTime,
		NextUpdate:   tl.SchemeInformation.NextUpdate.DateTime,
		SourceDigest: sha256hex(raw), // == published .sha2; drives next cycle's skip (P2)
		Anchors:      anchors,
	}
	// Stamp every TL-sourced anchor with the territory's TLSequence (T1:
	// additive Anchor.TLSequence). Overlay/internal anchors are never routed
	// through this path and keep the zero value.
	for i := range t.Anchors {
		t.Anchors[i].TLSequence = int64(t.TLSequence)
	}
	if t.StaleAt(now, p.cfg.StaleGrace) {
		p.events.Stale(nil, code, *t.NextUpdate)
	}
	return t, nil
}

// applyHoldMode implements TRUST_ACTIVATION_MODE=hold: anchor ADDITIONS move
// to the pending set (visible in the API, excluded from bundles) until
// approved via the admin endpoint or TRUST_HOLD_AUTO_RELEASE elapses.
// Removals always apply immediately — a removed or suspended CA must not stay
// trusted. Overlay anchors are operator-deployed and bypass hold.
func (p *Pipeline) applyHoldMode(prev, next *trust.Snapshot, now time.Time) {
	if p.cfg.ActivationMode != ModeHold {
		return
	}

	prevActive := map[string]struct{}{}
	prevPending := map[string]trust.PendingAnchor{}
	if prev != nil {
		for _, t := range prev.Territories {
			for _, a := range t.Anchors {
				prevActive[t.Code+"/"+a.FingerprintSHA256] = struct{}{}
			}
		}
		for _, pa := range prev.Pending {
			prevPending[pa.Anchor.Territory+"/"+pa.Anchor.FingerprintSHA256] = pa
		}
	}

	for _, t := range next.Territories {
		kept := t.Anchors[:0]
		for _, a := range t.Anchors {
			key := t.Code + "/" + a.FingerprintSHA256
			if _, active := prevActive[key]; active || prev == nil {
				// prev == nil: the very first snapshot is the baseline, not a
				// flood of held additions.
				kept = append(kept, a)
				continue
			}
			if pa, held := prevPending[key]; held {
				if p.cfg.HoldAutoRelease > 0 && now.Sub(pa.FirstSeen) >= p.cfg.HoldAutoRelease {
					kept = append(kept, a)
					p.events.PendingApproved(nil, a.FingerprintSHA256, "system", "auto-release")
					continue
				}
				next.Pending = append(next.Pending, trust.PendingAnchor{Anchor: a, FirstSeen: pa.FirstSeen})
				continue
			}
			next.Pending = append(next.Pending, trust.PendingAnchor{Anchor: a, FirstSeen: now})
			p.events.AnchorChange(nil, trust.DiffAdded, t.Code, a.FingerprintSHA256, a.TSPName, a.ServiceName, a.Status, "held for approval", true)
		}
		t.Anchors = kept
	}

	sort.Slice(next.Pending, func(i, j int) bool {
		return next.Pending[i].Anchor.FingerprintSHA256 < next.Pending[j].Anchor.FingerprintSHA256
	})
}
