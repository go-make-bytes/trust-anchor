package ingest

import (
	"bytes"
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
	"github.com/go-make-bytes/trust-anchor/source"
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
	// AllowHTTPTerritories names the territories whose trusted list may be
	// fetched over plain http (TRUST_ALLOW_HTTP_TERRITORIES, default empty).
	// Some publishers point their list at an http URL (Slovakia's LOTL
	// pointer, whose https alternative serves a wrong-hostname certificate).
	// Integrity never rests on transport — every list is XMLDSig-verified
	// against the LOTL-pinned signers — so this waives only the
	// defense-in-depth https rule, per named territory, on an explicit
	// operator declaration. It never applies to the LOTL itself.
	AllowHTTPTerritories []string
}

// allowsHTTP reports whether the operator opted the territory into
// plain-http fetches.
func (c *Config) allowsHTTP(code string) bool {
	for _, t := range c.AllowHTTPTerritories {
		if t == code {
			return true
		}
	}
	return false
}

// Pipeline executes one ingestion cycle: LOTL → pivots → national TLs →
// anchors → snapshot. It is stateless between cycles; all state lives in the
// snapshots it is handed and returns.
type Pipeline struct {
	cfg     Config
	fetcher *Fetcher
	events  *events.Emitter
	log     *zap.Logger

	// clock supplies the cycle's wall time; nil means time.Now. Injected by
	// tests that need to move the clock past a fixture's NextUpdate.
	clock func() time.Time
}

// NewPipeline builds a Pipeline.
func NewPipeline(cfg Config, fetcher *Fetcher, ev *events.Emitter, log *zap.Logger) *Pipeline {
	return &Pipeline{cfg: cfg, fetcher: fetcher, events: ev, log: log}
}

// now returns the cycle wall time (the injected clock in tests).
func (p *Pipeline) now() time.Time {
	if p.clock != nil {
		return p.clock().UTC()
	}
	return time.Now().UTC()
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
	now := p.now()

	lotl, signers, pivotSeq, err := p.ingestLOTL(ctx, prev, boot, now)
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

	// National trusted lists. Each territory is an independent upstream: one
	// failing must not suppress the others, so failures accumulate as named
	// failed entries instead of aborting the cycle. The floor below keeps
	// the all-failed case a loud cycle failure.
	territories := expandTerritories(p.cfg.Territories, lotl)
	withData := 0
	for _, code := range territories {
		t, err := p.ingestTerritory(ctx, lotl, code, prev, now)
		if err != nil {
			p.log.Warn("territory failed with no previous data — recorded as failed, cycle continues",
				zap.String("territory", code), zap.Error(err))
			next.Territories = append(next.Territories, &trust.Territory{
				Code: code, Failed: true, FailureReason: err.Error(), Anchors: []trust.Anchor{},
			})
			continue
		}
		next.Territories = append(next.Territories, t)
		withData++
	}
	if len(territories) > 0 && withData == 0 {
		return nil, fmt.Errorf("ingest: every configured territory failed and none has previous data — refusing to build a snapshot with zero verified territories")
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

// TerritoryGroupEU is the TRUST_TERRITORIES group value that expands to
// every territory the verified LOTL publishes an XML trusted-list pointer
// for. Expansion happens per cycle, from the freshly verified LOTL — never
// from a hardcoded list — so membership changes flow in on the LOTL's own
// clock. It cannot collide with a country code: EU is the LOTL's own
// self-pointer territory, which the expansion excludes.
const TerritoryGroupEU = "EU"

// expandTerritories resolves the configured territory list against the
// verified LOTL: the EU group expands to the LOTL's pointer territories,
// explicit codes pass through, duplicates collapse. A code the LOTL has no
// pointer for stays in the set and fails its ingest visibly (a failed entry)
// rather than being dropped here — configured intent is never silently
// narrowed.
func expandTerritories(configured []string, lotl *tsl.TrustedList) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(code string) {
		if _, ok := seen[code]; ok {
			return
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	for _, code := range configured {
		if code == TerritoryGroupEU {
			for _, t := range lotl.Territories() {
				add(t)
			}
			continue
		}
		add(code)
	}
	sort.Strings(out)
	return out
}

// applyDeclaredSources loads the operator-declared anchor source — the
// internal trust source — into next. A failed load never fails the cycle:
// the previous set is carried over unconditionally (an empty previous set
// carries over as empty — unlike a territory, whose carry-over needs
// previous data) and the source's security event is emitted, because a typo
// in an operator file must not take down trusted-list ingestion. The returned
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

// ingestLOTL runs the LOTL through its source adapter: fetch, then the
// verification complex (direct vs pivot walk, expiry, self-consistency — see
// euLOTLSource.Verify). This function owns only the signer-set precedence:
// continue from the previous snapshot's (pivot-rotated) signer set when one
// exists, otherwise start from the operator-pinned bootstrap set.
func (p *Pipeline) ingestLOTL(ctx context.Context, prev *trust.Snapshot, boot *trust.Bootstrap, now time.Time) (*tsl.TrustedList, []*x509.Certificate, uint64, error) {
	src := &euLOTLSource{p: p, url: p.cfg.LOTLURL, now: now}

	raw, err := src.Fetch(ctx, nil)
	if err != nil {
		return nil, nil, 0, err
	}

	var pinned [][]byte
	switch {
	case prev != nil && len(prev.LOTLSignersDER) > 0:
		pinned = prev.LOTLSignersDER
		src.pivotSeq = prev.LOTLPivotSeq
	default:
		certs, cerr := boot.Certificates()
		if cerr != nil {
			return nil, nil, 0, cerr
		}
		pinned = certsDER(certs)
	}

	if _, err := src.Verify(ctx, raw, pinned); err != nil {
		return nil, nil, 0, err
	}
	return src.list, src.signers, src.pivotSeq, nil
}

// lotlSignerSelfConsistent checks TS 119 615 PRO-4.1.4-10(a): the certificate
// that signed the LOTL is among the certificates the LOTL's own EU
// self-pointer advertises.
func lotlSignerSelfConsistent(signer *x509.Certificate, lotl *tsl.TrustedList) error {
	self, err := lotl.SelfPointer()
	if err != nil {
		return fmt.Errorf("ingest: LOTL self-consistency: %w", err)
	}
	own, err := self.Certificates()
	if err != nil {
		return fmt.Errorf("ingest: LOTL self-consistency: %w", err)
	}
	if !certInSet(signer, own) {
		return fmt.Errorf("ingest: LOTL_SIGNER_CERT_NOT_AUTHENTICATED_BY_LOTL: the LOTL's signing certificate (%s) is not in the LOTL's own EU self-pointer set", signer.Subject.CommonName)
	}
	return nil
}

// certInSet reports byte-identical membership (the same pinning rule
// signature verification uses — no chain building).
func certInSet(c *x509.Certificate, set []*x509.Certificate) bool {
	for _, s := range set {
		if bytes.Equal(s.Raw, c.Raw) {
			return true
		}
	}
	return false
}

// ingestTerritory fetches, verifies and extracts one national TL. On failure
// it carries over the previous snapshot's territory data (fail-safe); when no
// previous data exists it returns the error and the caller records the
// territory as failed — the rest of the cycle continues.
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
	if prevT == nil || prevT.Failed {
		// A failed entry is not previous data — there is nothing to carry
		// over, so the territory stays failed rather than becoming a
		// carry-over of nothing.
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

	var prevT *trust.Territory
	if prev != nil {
		prevT = prev.Territory(code)
	}

	src := &nationalTLSource{
		fetcher:          p.fetcher,
		log:              p.log,
		code:             code,
		ptr:              ptr,
		allowHTTP:        p.cfg.allowsHTTP(code),
		acceptedStatuses: p.cfg.AcceptedStatuses,
		acceptedTypes:    p.cfg.AcceptedServiceTypes,
		now:              now,
	}
	var last *source.Raw
	if prevT != nil {
		src.hasPrev = true
		src.prevSeq = prevT.TLSequence
		src.prevFresh = prevT.SourceDigest != "" && prevT.NextUpdate != nil && !prevT.StaleAt(now, p.cfg.StaleGrace)
		last = &source.Raw{Digest: prevT.SourceDigest, Sequence: prevT.TLSequence}
	}

	raw, err := src.Fetch(ctx, last)
	if errors.Is(err, source.ErrUnchanged) {
		reused := *prevT
		reused.CarriedOver = false // confirmed unchanged, not a fail-safe carry-over
		reused.Anchors = append([]trust.Anchor(nil), prevT.Anchors...)
		return &reused, nil
	}
	if err != nil {
		return nil, err
	}

	signers, err := ptr.Certificates()
	if err != nil {
		return nil, fmt.Errorf("pointer certs for %s: %w", code, err)
	}

	if _, err := src.Verify(ctx, raw, certsDER(signers)); err != nil {
		return nil, err
	}
	anchors, err := src.Extract(nil)
	if err != nil {
		return nil, err
	}
	for _, w := range src.warnings {
		fields := []zap.Field{
			zap.String("territory", code), zap.String("tsp", w.TSPName),
			zap.String("service", w.ServiceName), zap.String("reason", w.Reason),
		}
		if w.Code != "" {
			// A per-service skip; the aggregate type warnings carry none of these.
			fields = append(fields, zap.String("skip_reason", w.Code), zap.String("fingerprint", w.FingerprintSHA256))
			if w.KeyAlgorithm != "" {
				fields = append(fields, zap.String("key_algorithm", w.KeyAlgorithm), zap.String("curve", w.Curve))
			}
		}
		p.log.Warn("skipped trust service during extraction", fields...)
	}

	tl := src.list
	t := &trust.Territory{
		Code:         code,
		TLSequence:   tl.SchemeInformation.TSLSequenceNumber,
		IssueTime:    tl.SchemeInformation.ListIssueDateTime,
		NextUpdate:   tl.SchemeInformation.NextUpdate.DateTime,
		SourceDigest: raw.Digest, // == published .sha2; drives next cycle's skip
		Anchors:      anchors,
		// The per-service skips ride with the territory as data, so a list
		// that yields fewer anchors than it declares is visible on the API,
		// in the inventory and on the metrics surface — not only in this log.
		Skipped: trust.Skipped(src.warnings),
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
