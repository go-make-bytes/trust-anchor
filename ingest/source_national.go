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

// nationalTLSource adapts one national trusted list to the source.Source
// contract: Fetch enforces egress rules and input-side change detection,
// Verify authenticates against the LOTL-pinned signer set, Extract projects
// the verified list into trust anchors. An instance is built per territory
// per cycle and is one-shot — Verify caches the parsed list so the verified
// document is parsed exactly once.
type nationalTLSource struct {
	fetcher   *Fetcher
	log       *zap.Logger
	code      string
	ptr       *tsl.TSLPointer
	allowHTTP bool

	// Change-detection input from the previous cycle. prevFresh is true when
	// the previous territory entry carries a stored digest and is still
	// within NextUpdate (+grace) — the only state in which the sibling
	// ".sha2" may authorize skipping the download.
	prevFresh bool
	// prevSeq is the sequence-regression floor; meaningful only with hasPrev.
	prevSeq uint64
	hasPrev bool

	acceptedStatuses []string
	acceptedTypes    []string
	now              time.Time

	// Cached by Verify for Extract.
	list *tsl.TrustedList
	// warnings collects the extraction skip-reasons for the caller to log.
	warnings []trust.ExtractionWarning
}

// Type returns the source-type discriminator.
func (s *nationalTLSource) Type() source.Type { return source.TypeNationalTL }

// ID is the territory code.
func (s *nationalTLSource) ID() string { return s.code }

// Fetch enforces the egress rules and consults the sibling ".sha2" before
// downloading: when the published digest matches the previous cycle's and the
// held list is within NextUpdate, it returns source.ErrUnchanged and the
// already-verified previous data is reused without a download. The digest
// only ever decides whether to fetch — it is never a trust input, per
// [ETSI TS 119 612 V2.4.1 §6.1] ("shall not be used to authenticate the TL");
// trust comes from the XMLDSig verification of anything actually downloaded.
// A list past NextUpdate, with no stored digest, or whose digest fetch fails
// always falls through to a full fetch, so a lying or stale ".sha2" can delay
// a refresh only until the held list's own validity runs out.
func (s *nationalTLSource) Fetch(ctx context.Context, last *source.Raw) (*source.Raw, error) {
	if s.allowHTTP {
		if err := s.fetcher.AllowHTTPFor(s.ptr.TSLLocation); err != nil {
			return nil, err
		}
		s.log.Warn("territory trusted list will be fetched over plain http by explicit operator opt-in — integrity comes from the XMLDSig verification, not transport",
			zap.String("territory", s.code), zap.String("url", s.ptr.TSLLocation))
	}
	if err := s.fetcher.AllowURL(s.ptr.TSLLocation); err != nil {
		return nil, err
	}

	if s.prevFresh && last != nil && last.Digest != "" {
		if digest, derr := s.fetcher.FetchDigest(ctx, s.ptr.TSLLocation); derr == nil && digest == last.Digest {
			s.log.Debug("territory unchanged (.sha2 match) — skipped full fetch",
				zap.String("territory", s.code), zap.String("digest", digest))
			return nil, source.ErrUnchanged
		}
	}

	raw, err := s.fetcher.Fetch(ctx, s.ptr.TSLLocation)
	if err != nil {
		return nil, err
	}
	return &source.Raw{Bytes: raw, Digest: sha256hex(raw)}, nil
}

// Verify authenticates the fetched list against the pinned signer set
// (XMLDSig, byte-identical certificate pinning — no chain building) and then
// checks the verified content's own claims: the declared SchemeTerritory must
// match the pointer's territory, and the sequence number must never regress.
// The parsed list is cached for Extract; the returned bytes are the verified
// canonical form.
func (s *nationalTLSource) Verify(_ context.Context, raw *source.Raw, pinnedSignersDER [][]byte) ([]byte, error) {
	signers, err := parseDERCerts(pinnedSignersDER)
	if err != nil {
		return nil, fmt.Errorf("pointer certs for %s: %w", s.code, err)
	}
	verified, _, err := tsl.Verify(raw.Bytes, signers)
	if err != nil {
		return nil, fmt.Errorf("territory %s: %w", s.code, err)
	}
	tl, err := tsl.Parse(verified)
	if err != nil {
		return nil, fmt.Errorf("territory %s: %w", s.code, err)
	}
	if tl.SchemeInformation.SchemeTerritory != s.code {
		return nil, fmt.Errorf("territory %s: list declares SchemeTerritory %q", s.code, tl.SchemeInformation.SchemeTerritory)
	}
	if s.hasPrev && tl.SchemeInformation.TSLSequenceNumber < s.prevSeq {
		return nil, fmt.Errorf("territory %s: sequence regression: %d < %d", s.code, tl.SchemeInformation.TSLSequenceNumber, s.prevSeq)
	}
	s.list = tl
	return verified, nil
}

// Extract projects the verified list into trust anchors. Verify must have
// succeeded on this instance first — the parsed list is cached there. The
// per-service skip warnings are retained on the instance for the caller to
// log with its own context.
func (s *nationalTLSource) Extract(_ []byte) ([]trust.Anchor, error) {
	if s.list == nil {
		return nil, fmt.Errorf("territory %s: extract called before a successful verify", s.code)
	}
	anchors, warnings, err := trust.ExtractAnchors(s.list, s.code, s.acceptedStatuses, s.acceptedTypes, s.now)
	if err != nil {
		return nil, err
	}
	s.warnings = warnings
	return anchors, nil
}

// parseDERCerts parses a pinned signer set handed across the source contract
// as raw DER back into certificates.
func parseDERCerts(der [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(der))
	for _, d := range der {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// certsDER projects certificates to their raw DER for the source contract.
func certsDER(certs []*x509.Certificate) [][]byte {
	der := make([][]byte, 0, len(certs))
	for _, c := range certs {
		der = append(der, c.Raw)
	}
	return der
}
