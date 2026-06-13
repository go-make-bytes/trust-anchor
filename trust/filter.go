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
//
// Manual-overlay anchors are merged into every bundle (they carry no
// territory) and respect use/qscd filters like any other anchor.
func Filter(s *Snapshot, territories []string, use string, qscdOnly bool) ([]Anchor, error) {
	if !ValidUse(use) {
		return nil, fmt.Errorf("trust: invalid use %q (accepted: %s)", use, strings.Join(ValidUses, ", "))
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
			if matches(a, use, qscdOnly) {
				out = append(out, a)
			}
		}
	}
	for _, a := range s.Overlay {
		if matches(a, use, qscdOnly) {
			out = append(out, a)
		}
	}
	return out, nil
}

func matches(a Anchor, use string, qscdOnly bool) bool {
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
