package ingest

import (
	"errors"
	"fmt"

	"github.com/go-make-bytes/trust-anchor/trust"
	"github.com/go-make-bytes/trust-anchor/tsl"
)

// pointerSet is what the territory loop needs from the list of the lists:
// which territories publish an XML trusted list, and for each the list's
// location and the certificates it must be signed with. It is built from a
// freshly verified list, or from the copy the previous snapshot carries when
// the publisher's digest proved the list unchanged — so the loop runs
// identically on both paths, and a territory the list has no pointer for
// fails the same way on both.
type pointerSet struct {
	list []trust.ListPointer // in the list's territory order (sorted)
}

// lotlPointerSet projects the verified list of the lists into the pointer set
// the snapshot carries. Signer certificates are kept as DER, unparsed: a
// certificate the parser refuses must fail its own territory at verification
// time, not the whole cycle here — the per-territory fate it had when the
// pointer was read straight off the list. A certificate that does not even
// decode is recorded as that territory's failure, for the same reason.
func lotlPointerSet(lotl *tsl.TrustedList) *pointerSet {
	ps := &pointerSet{}
	for _, code := range lotl.Territories() {
		lp := trust.ListPointer{Territory: code}
		ptr, err := lotl.PointerFor(code)
		if err != nil {
			// Territories and PointerFor select by the same rule, so this
			// does not happen; it is recorded rather than assumed away.
			lp.Failure = err.Error()
		} else {
			lp.URL = ptr.TSLLocation
			if ders, derr := ptr.CertificateDERs(); derr != nil {
				lp.Failure = fmt.Sprintf("pointer certs for %s: %v", code, derr)
			} else {
				lp.SignersDER = ders
			}
		}
		ps.list = append(ps.list, lp)
	}
	return ps
}

// carriedPointerSet rebuilds the pointer set from what a previous snapshot
// carries; the slice is copied so the served snapshot is never aliased.
func carriedPointerSet(list []trust.ListPointer) *pointerSet {
	return &pointerSet{list: append([]trust.ListPointer(nil), list...)}
}

// pointers returns the set as the snapshot carries it.
func (s *pointerSet) pointers() []trust.ListPointer { return s.list }

// territories returns the codes the set has pointers for.
func (s *pointerSet) territories() []string {
	out := make([]string, 0, len(s.list))
	for i := range s.list {
		out = append(out, s.list[i].Territory)
	}
	return out
}

// pointerFor returns the territory's pointer, or the error the list itself
// gives for a territory it publishes no XML pointer for.
func (s *pointerSet) pointerFor(code string) (*trust.ListPointer, error) {
	for i := range s.list {
		if s.list[i].Territory != code {
			continue
		}
		if s.list[i].Failure != "" {
			return nil, errors.New(s.list[i].Failure)
		}
		return &s.list[i], nil
	}
	return nil, tsl.ErrNoXMLPointer(code)
}
