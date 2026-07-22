package ingest

import (
	"context"
	"crypto/x509"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/go-make-bytes/trust-anchor/tsl"
)

// pivotURLRe matches LOTL pivot file URLs advertised in SchemeInformationURI
// and captures their sequence number.
var pivotURLRe = regexp.MustCompile(`/eu-lotl-pivot-(\d+)\.xml$`)

type pivotRef struct {
	url string
	seq uint64
}

// pivotRefs extracts the pivot URLs from a LOTL's SchemeInformationURI list,
// sorted by ascending sequence number.
func pivotRefs(uris []string) []pivotRef {
	var refs []pivotRef
	for _, u := range uris {
		m := pivotURLRe.FindStringSubmatch(u)
		if m == nil {
			continue
		}
		seq, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			continue
		}
		refs = append(refs, pivotRef{url: u, seq: seq})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].seq < refs[j].seq })
	return refs
}

// walkPivots processes the LOTL pivot chain: every pivot newer than
// lastProcessed is fetched, verified against the current signer set (validity
// checked at the pivot's own issue time) and its EU self-pointer becomes the
// new signer set. Returns the final signer set and the newest processed
// sequence number.
//
// Pivots are LOTL-shaped documents; their content is only consumed after
// signature verification, and the issue time used for the validity check is
// re-checked against the verified content.
func (p *Pipeline) walkPivots(ctx context.Context, refs []pivotRef, signers []*x509.Certificate, lastProcessed uint64) ([]*x509.Certificate, uint64, error) {
	for _, ref := range refs {
		if ref.seq <= lastProcessed {
			continue
		}
		// Pivot URLs come from the UNVERIFIED LOTL pre-parse — enforce the
		// egress allowlist before fetching, like every other outbound URL
		// (otherwise a tampered LOTL response is an SSRF vector even though
		// the fetched content would fail verification afterwards).
		if err := p.fetcher.AllowURL(ref.url); err != nil {
			return nil, 0, fmt.Errorf("pivot %d: %w", ref.seq, err)
		}
		raw, err := p.fetcher.Fetch(ctx, ref.url)
		if err != nil {
			return nil, 0, fmt.Errorf("pivot %d: %w", ref.seq, err)
		}

		pre, err := tsl.Parse(raw)
		if err != nil {
			return nil, 0, fmt.Errorf("pivot %d: pre-parse: %w", ref.seq, err)
		}
		verified, err := tsl.VerifyAt(raw, signers, pre.SchemeInformation.ListIssueDateTime)
		if err != nil {
			return nil, 0, fmt.Errorf("pivot %d: %w", ref.seq, err)
		}
		pivot, err := tsl.Parse(verified)
		if err != nil {
			return nil, 0, fmt.Errorf("pivot %d: parse verified: %w", ref.seq, err)
		}

		// The issue time fed into the validity check came from unverified
		// bytes — it must match the signed content.
		if !pivot.SchemeInformation.ListIssueDateTime.Equal(pre.SchemeInformation.ListIssueDateTime) {
			return nil, 0, fmt.Errorf("pivot %d: issue time differs between unverified and verified content", ref.seq)
		}
		if pivot.SchemeInformation.TSLType != tsl.TSLTypeEUListOfTheLists {
			return nil, 0, fmt.Errorf("pivot %d: unexpected TSLType %q", ref.seq, pivot.SchemeInformation.TSLType)
		}
		if pivot.SchemeInformation.TSLSequenceNumber != ref.seq {
			return nil, 0, fmt.Errorf("pivot %d: content sequence %d does not match URL", ref.seq, pivot.SchemeInformation.TSLSequenceNumber)
		}

		self, err := pivot.SelfPointer()
		if err != nil {
			return nil, 0, fmt.Errorf("pivot %d: %w", ref.seq, err)
		}
		next, err := self.Certificates()
		if err != nil {
			return nil, 0, fmt.Errorf("pivot %d: signer certs: %w", ref.seq, err)
		}
		if len(next) == 0 {
			return nil, 0, fmt.Errorf("pivot %d: empty signer set", ref.seq)
		}

		signers = next
		lastProcessed = ref.seq
		p.log.Info("processed LOTL pivot", logUint("sequence", ref.seq), logInt("signers", len(next)))
	}
	return signers, lastProcessed, nil
}
