package ingest

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/go-make-bytes/trust-anchor/source"
	"github.com/go-make-bytes/trust-anchor/trust"
	"github.com/go-make-bytes/trust-anchor/tsl"
)

// euLOTLSource adapts the EU list of trusted lists to the source.Source
// contract. It is the root of the trust chain: Verify carries the whole
// signer-rotation model — direct verification against the handed pinned set,
// else the pivot-chain walk — plus the publication-consistency checks on the
// verified content. An instance is built per cycle and is one-shot: Verify
// caches the parsed list, the resulting signer set and the pivot progress for
// the caller to read back.
type euLOTLSource struct {
	p   *Pipeline
	url string
	now time.Time

	// pivotSeq is seeded by the caller with the last processed pivot sequence
	// and advanced by Verify (directly, or by the pivot walk).
	pivotSeq uint64

	// prevFresh is true when the previous snapshot carries the list's digest
	// and its territory pointer set and the held list is still within its
	// NextUpdate — the only state in which the sibling ".sha2" may authorize
	// skipping the download.
	prevFresh bool

	// Cached by Verify.
	list    *tsl.TrustedList
	signers []*x509.Certificate
}

// Type returns the source-type discriminator.
func (s *euLOTLSource) Type() source.Type { return source.TypeEULOTL }

// ID is the stable source identity.
func (s *euLOTLSource) ID() string { return string(source.TypeEULOTL) }

// Fetch retrieves the list of trusted lists, consulting its sibling ".sha2"
// first: when the published digest matches the previous cycle's and the held
// list is within NextUpdate, it returns source.ErrUnchanged and the caller
// runs the territory loop off the pointer set the previous snapshot carries.
// The digest only ever decides whether to download — it is never a trust
// input, per [ETSI TS 119 612 V2.4.1 §6.1] ("shall not be used to
// authenticate the TL"). A list past NextUpdate, with no stored digest, or
// whose digest fetch fails always falls through to a full fetch, so a lying
// or stale ".sha2" can delay a refresh only until the held list's own
// validity runs out — and on that full path an expired list is refused
// (LOTL_NEXTUPDATE_PASSED), never quietly kept.
func (s *euLOTLSource) Fetch(ctx context.Context, last *source.Raw) (*source.Raw, error) {
	if err := s.p.fetcher.AllowURL(s.url); err != nil {
		return nil, err
	}
	if s.prevFresh && last != nil && last.Digest != "" {
		if digest, derr := s.p.fetcher.FetchDigest(ctx, s.url); derr == nil && digest == last.Digest {
			return nil, source.ErrUnchanged
		}
	}
	raw, err := s.p.fetcher.Fetch(ctx, s.url)
	if err != nil {
		return nil, fmt.Errorf("ingest: fetch LOTL: %w", err)
	}
	return &source.Raw{Bytes: raw, Digest: sha256hex(raw)}, nil
}

// Verify authenticates the fetched list, processing the pivot chain when the
// pinned signer set no longer verifies it directly. Beyond signature
// verification it enforces two [ETSI TS 119 615 V1.4.1 §4.1.4] rules: an
// expired list of the lists is refused (PRO-4.1.4-13, LOTL_NEXTUPDATE_PASSED),
// and on direct verification the signing certificate must be in the list's
// own EU self-pointer set (PRO-4.1.4-10(a)) — a publication-consistency
// check. After a pivot walk that same property is enforced by construction:
// the re-verification pins the signer into the newest pivot's set, which is
// the standard's n>0 requirement.
func (s *euLOTLSource) Verify(ctx context.Context, raw *source.Raw, pinnedSignersDER [][]byte) ([]byte, error) {
	// Unverified pre-parse: pivot URLs only. Trust decisions follow only
	// after signature verification.
	pre, err := tsl.Parse(raw.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ingest: pre-parse LOTL: %w", err)
	}
	refs := pivotRefs(pre.SchemeInformation.SchemeInformationURI.URI)
	maxPivot := uint64(0)
	if len(refs) > 0 {
		maxPivot = refs[len(refs)-1].seq
	}

	signers, err := parseDERCerts(pinnedSignersDER)
	if err != nil {
		return nil, err
	}

	direct := false
	verified, lotlSigner, verr := tsl.Verify(raw.Bytes, signers)
	if verr == nil {
		direct = true
		// The current set supersedes any unprocessed pivots — they are
		// historical rotations that ended in this set.
		if maxPivot > s.pivotSeq {
			s.pivotSeq = maxPivot
		}
	} else {
		// Direct verification failed — the signer set may have rotated via
		// pivots since our last cycle. Walk the unprocessed chain.
		s.p.log.Info("LOTL direct verification failed, processing pivot chain", zap.Error(verr))
		signers, s.pivotSeq, err = s.p.walkPivots(ctx, refs, signers, s.pivotSeq)
		if err != nil {
			return nil, fmt.Errorf("ingest: pivot chain: %w (after direct verification failed: %w)", err, verr)
		}
		verified, lotlSigner, err = tsl.Verify(raw.Bytes, signers)
		if err != nil {
			return nil, fmt.Errorf("ingest: LOTL verification failed after pivot processing: %w", err)
		}
	}

	lotl, err := tsl.Parse(verified)
	if err != nil {
		return nil, fmt.Errorf("ingest: parse verified LOTL: %w", err)
	}
	if lotl.SchemeInformation.TSLType != tsl.TSLTypeEUListOfTheLists {
		return nil, fmt.Errorf("ingest: LOTL has unexpected TSLType %q", lotl.SchemeInformation.TSLType)
	}

	// An expired LOTL no longer authenticates — the publisher's own validity
	// promise has run out (PRO-4.1.4-13). Cycle failure: the previous
	// snapshot stays served. Deliberately asymmetric with national TLs, whose
	// staleness is a warning by the standard's own rule (PRO-4.2.4-10) and
	// stays the carry-over + trust.stale posture.
	if nu := lotl.SchemeInformation.NextUpdate.DateTime; nu != nil && s.now.After(*nu) {
		return nil, fmt.Errorf("ingest: LOTL_NEXTUPDATE_PASSED: the LOTL's NextUpdate %s has passed — refusing to authenticate an expired list", nu.Format(time.RFC3339))
	}

	// On direct verification the LOTL's signing certificate must be in the
	// LOTL's own EU self-pointer set (PRO-4.1.4-10(a)) — it catches an
	// upstream publication mistake where the list is signed by a key its own
	// content does not advertise.
	if direct {
		if err := lotlSignerSelfConsistent(lotlSigner, lotl); err != nil {
			return nil, err
		}
	}

	s.list = lotl
	s.signers = signers
	return verified, nil
}

// Extract is a no-op for the list of the lists: it contributes the verified
// pointer set and the signer-rotation state, never trust anchors of its own —
// anchors come from the per-territory lists it points at.
func (s *euLOTLSource) Extract(_ []byte) ([]trust.Anchor, error) { return nil, nil }
