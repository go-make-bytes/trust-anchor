package trust

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"strings"
)

// ValidUses are the accepted values of the `use` bundle filter.
var ValidUses = []string{UseSignature, UseAuthentication, UseSeal, UseWebsite}

// ValidUse reports whether use is an accepted filter value.
func ValidUse(use string) bool {
	if use == "" {
		return true
	}
	for _, u := range ValidUses {
		if u == use {
			return true
		}
	}
	return false
}

// Filter selects the anchors of a snapshot for a bundle response.
//
// territories: territory codes to include (empty = all in the snapshot).
// use: optional use filter (see ValidUses).
// qscdOnly: only services qualified QCWithQSCD.
// anchorType: the type= bundle filter (the exclusion rule).
// anchorType == "" is the untyped (TSL-plane) view: only untyped anchors
// (Type == "") — typed anchors never leak into existing consumers' bundles.
// anchorType != "" returns ONLY anchors of exactly that type (from any
// source: territory or internal); an unknown type is rejected (fail closed,
// see ValidAnchorType). The type dimension is one dimension: an anchor's
// Type is always derived from its published identifier (TypeKey), whether
// it came from a trusted list or a declaration.
func Filter(s *Snapshot, territories []string, use string, qscdOnly bool, anchorType string) ([]Anchor, error) {
	if !ValidUse(use) {
		return nil, fmt.Errorf("trust: invalid use %q (accepted: %s)", use, strings.Join(ValidUses, ", "))
	}
	if anchorType != "" && !ValidAnchorType(anchorType) {
		return nil, fmt.Errorf("trust: invalid type %q", anchorType)
	}

	include := func(code string) bool {
		if len(territories) == 0 {
			return true
		}
		for _, t := range territories {
			if strings.EqualFold(t, code) {
				return true
			}
		}
		return false
	}

	var out []Anchor
	for _, t := range s.Territories {
		if !include(t.Code) {
			continue
		}
		for _, a := range t.Anchors {
			if matches(a, use, qscdOnly, anchorType) {
				out = append(out, a)
			}
		}
	}
	// Internal (operator-declared, INTERNAL_TRUST_SOURCE) anchors merge in
	// beside the territory-sourced ones — matches() gates on Type, so a
	// typed internal anchor only ever appears in ITS type's bundle, and an
	// untyped declaration lands in the untyped bundle like any TL CA.
	for _, a := range s.Internal {
		if matches(a, use, qscdOnly, anchorType) {
			out = append(out, a)
		}
	}
	return out, nil
}

// matches gates one anchor against the use/qscd/type dimensions of a bundle
// request. Territory is handled by the caller (Filter), structurally, only
// for territory-sourced anchors — Internal never carried a territory
// dimension and that is unchanged here.
func matches(a Anchor, use string, qscdOnly bool, anchorType string) bool {
	// "" == "" covers the legacy (untyped) view; anchorType != "" requires
	// an exact match — a typed anchor never appears in another type's bundle
	// or in the untyped one.
	if a.Type != anchorType {
		return false
	}
	if qscdOnly && !a.QCWithQSCD {
		return false
	}
	return a.MatchesUse(use)
}

// PEMBundle renders anchors as a concatenated PEM certificate bundle.
func PEMBundle(anchors []Anchor) []byte {
	var b bytes.Buffer
	for _, a := range anchors {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: a.CertDER})
	}
	return b.Bytes()
}
