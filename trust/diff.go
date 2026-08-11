package trust

import "sort"

// Diff kinds.
const (
	DiffAdded   = "added"
	DiffRemoved = "removed"
	DiffChanged = "changed" // metadata/status change on the same certificate
)

// DiffEntry is one anchor-set change between two snapshots.
type DiffEntry struct {
	Kind        string `json:"kind"`
	Territory   string `json:"territory"` // "internal" for declared anchors
	Fingerprint string `json:"fingerprint"`
	TSPName     string `json:"tspName"`
	ServiceName string `json:"serviceName"`
	Status      string `json:"status"`
	// Detail describes what changed for kind == changed.
	Detail string `json:"detail,omitempty"`
	Source string `json:"source"`
}

// Diff is the anchor-set change between a snapshot and its predecessor.
type Diff struct {
	PrevID  string      `json:"prevId,omitempty"`
	Entries []DiffEntry `json:"entries,omitempty"`
}

// Empty reports whether the diff carries no changes.
func (d *Diff) Empty() bool { return d == nil || len(d.Entries) == 0 }

// ComputeDiff diffs the served anchor sets of two snapshots (territories +
// internal) by certificate fingerprint. prev may be nil (first
// snapshot — everything is an addition).
func ComputeDiff(prev, next *Snapshot) *Diff {
	d := &Diff{}
	if prev != nil {
		d.PrevID = prev.ID
	}

	prevSet := anchorIndex(prev)
	nextSet := anchorIndex(next)

	for key, a := range nextSet {
		old, ok := prevSet[key]
		if !ok {
			d.Entries = append(d.Entries, entry(DiffAdded, a, ""))
			continue
		}
		if detail := metadataChange(old, a); detail != "" {
			d.Entries = append(d.Entries, entry(DiffChanged, a, detail))
		}
	}
	for key, a := range prevSet {
		if _, ok := nextSet[key]; !ok {
			d.Entries = append(d.Entries, entry(DiffRemoved, a, ""))
		}
	}

	sort.Slice(d.Entries, func(i, j int) bool {
		a, b := d.Entries[i], d.Entries[j]
		if a.Territory != b.Territory {
			return a.Territory < b.Territory
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Fingerprint < b.Fingerprint
	})
	return d
}

type indexedAnchor struct {
	anchor    Anchor
	territory string
}

func anchorIndex(s *Snapshot) map[string]indexedAnchor {
	out := map[string]indexedAnchor{}
	if s == nil {
		return out
	}
	for _, t := range s.Territories {
		for _, a := range t.Anchors {
			out[t.Code+"/"+a.FingerprintSHA256] = indexedAnchor{anchor: a, territory: t.Code}
		}
	}
	for _, a := range s.Internal {
		out["internal/"+a.FingerprintSHA256] = indexedAnchor{anchor: a, territory: "internal"}
	}
	return out
}

func entry(kind string, ia indexedAnchor, detail string) DiffEntry {
	return DiffEntry{
		Kind:        kind,
		Territory:   ia.territory,
		Fingerprint: ia.anchor.FingerprintSHA256,
		TSPName:     ia.anchor.TSPName,
		ServiceName: ia.anchor.ServiceName,
		Status:      ia.anchor.Status,
		Detail:      detail,
		Source:      ia.anchor.Source,
	}
}

func metadataChange(old, next indexedAnchor) string {
	switch {
	case old.anchor.Status != next.anchor.Status:
		return "status: " + old.anchor.Status + " -> " + next.anchor.Status
	case old.anchor.QCWithQSCD != next.anchor.QCWithQSCD:
		return "qcWithQscd changed"
	case !equalStrings(old.anchor.Uses, next.anchor.Uses):
		return "uses changed"
	case old.anchor.ServiceName != next.anchor.ServiceName:
		return "service name changed"
	default:
		return ""
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
