package trust

import (
	"strings"
	"testing"
	"time"
)

// twoRoles declares one certificate under two EUDI types, in the given order.
func twoRoles(first, second string) string {
	return "anchors:\n" +
		"  - name: Two Role CA\n" +
		"    types: [" + first + ", " + second + "]\n" +
		"    territory: lv\n" +
		"    validUntil: 2029-01-01T00:00:00Z\n" +
		"    useCases: [employee]\n" +
		"    certificateFile: internal-ca-two.pem\n"
}

// TestLoadInternalTypesExpands: one entry with two types becomes two anchors
// that share everything but the type.
func TestLoadInternalTypesExpands(t *testing.T) {
	anchors, err := loadInline(t, twoRoles("pid_provider", "eaa_provider"))
	if err != nil {
		t.Fatalf("loadInternalBytes: %v", err)
	}
	if len(anchors) != 2 {
		t.Fatalf("got %d anchors, want 2 (one per type)", len(anchors))
	}
	// Same fingerprint, so the type orders them.
	if anchors[0].Type != "eaa_provider" || anchors[1].Type != "pid_provider" {
		t.Fatalf("types = %q, %q, want eaa_provider, pid_provider", anchors[0].Type, anchors[1].Type)
	}
	for _, a := range anchors {
		if a.FingerprintSHA256 != anchors[0].FingerprintSHA256 {
			t.Errorf("%s: fingerprint differs from its sibling", a.Type)
		}
		if a.ServiceType != TypeIdentifier(a.Type) {
			t.Errorf("%s: ServiceType = %q, want the type's own identifier", a.Type, a.ServiceType)
		}
		if a.Territory != "LV" || a.Status != grantedStatusURI || a.NotAfter.Year() != 2029 || a.TSPName != "Two Role CA" {
			t.Errorf("%s: shared fields not carried: territory=%q status=%q notAfter=%v name=%q",
				a.Type, a.Territory, a.Status, a.NotAfter, a.TSPName)
		}
		if len(a.UseCases) != 1 || a.UseCases[0] != "employee" {
			t.Errorf("%s: UseCases = %v, want [employee]", a.Type, a.UseCases)
		}
	}
	// Each anchor owns its use cases: editing one must not edit the other.
	anchors[0].UseCases[0] = "changed"
	if anchors[1].UseCases[0] != "employee" {
		t.Error("the two anchors share one UseCases backing array")
	}
}

// TestLoadInternalTypesOrderDoesNotMoveTheID: the order a file lists its
// types in is not content, so it must not change the snapshot ID (and with
// it every consumer's ETag).
func TestLoadInternalTypesOrderDoesNotMoveTheID(t *testing.T) {
	ids := make([]string, 0, 2)
	for _, raw := range []string{twoRoles("pid_provider", "eaa_provider"), twoRoles("eaa_provider", "pid_provider")} {
		anchors, err := loadInline(t, raw)
		if err != nil {
			t.Fatalf("loadInternalBytes: %v", err)
		}
		ids = append(ids, (&Snapshot{Internal: anchors}).ComputeID())
	}
	if ids[0] != ids[1] {
		t.Errorf("snapshot ID depends on the order of types: %s vs %s", ids[0], ids[1])
	}

	// The ID's own sort must break the tie too, whatever order it is handed.
	anchors, err := loadInline(t, twoRoles("pid_provider", "eaa_provider"))
	if err != nil {
		t.Fatal(err)
	}
	swapped := []Anchor{anchors[1], anchors[0]}
	if got := (&Snapshot{Internal: swapped}).ComputeID(); got != ids[0] {
		t.Errorf("ComputeID depends on the order of same-fingerprint anchors: %s vs %s", got, ids[0])
	}
}

// goldenInternalSnapshotID is the ComputeID() of a snapshot holding exactly
// the anchors of testdata/internal-trust-valid.yaml, computed with the code
// as it was before an entry could carry several types. A file that declares
// one type per entry must keep its ID.
const goldenInternalSnapshotID = "57c308f6d3e1311257608e5c75326a21e5fc369f4973ba7d59c2295937b6e296"

func TestLoadInternalSingleTypeFileKeepsItsID(t *testing.T) {
	anchors, err := LoadInternal(internalFixture("internal-trust-valid.yaml"), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("LoadInternal: %v", err)
	}
	if got := (&Snapshot{Internal: anchors}).ComputeID(); got != goldenInternalSnapshotID {
		t.Fatalf("ComputeID() = %s, want golden %s (an existing declaration's ID must not move)", got, goldenInternalSnapshotID)
	}
}

// TestLoadInternalTypesRejected: every malformed `types` rejects the whole
// file and names the entry.
func TestLoadInternalTypesRejected(t *testing.T) {
	for _, tc := range []struct {
		name, typeLines, wantErr string
	}{
		{"type and types", "    type: pid_provider\n    types: [eaa_provider]\n", "not both"},
		{"empty list", "    types: []\n", "types is empty"},
		{"no value", "    types:\n", "types is empty"},
		{"unknown type", "    types: [pid_provider, bogus_provider]\n", "unknown type"},
		{"listed twice", "    types: [pid_provider, pid_provider]\n", "listed twice"},
		{"untyped alias", "    types: [pid_provider, tsl_ca]\n", "EUDI anchor types only"},
		{"blank type", "    types: [pid_provider, \"\"]\n", "EUDI anchor types only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anchors, err := loadInline(t, "anchors:\n"+
				"  - name: Bad Types Anchor\n"+
				tc.typeLines+
				"    territory: LV\n"+
				"    certificateFile: internal-ca-two.pem\n")
			if err == nil {
				t.Fatalf("got nil error and %d anchors, want the file rejected", len(anchors))
			}
			if len(anchors) != 0 {
				t.Errorf("got %d anchors on failure, want 0", len(anchors))
			}
			for _, want := range []string{"Bad Types Anchor", tc.wantErr} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err.Error(), want)
				}
			}
		})
	}
}

// TestLoadInternalTypesStillOneEntryPerCertificate: a certificate's roles
// belong in one entry. The same certificate in a second entry — even under
// a type the first does not list — is still rejected.
func TestLoadInternalTypesStillOneEntryPerCertificate(t *testing.T) {
	_, err := loadInline(t, twoRoles("pid_provider", "eaa_provider")+
		"  - name: Second Entry\n"+
		"    type: qeaa_provider\n"+
		"    territory: LV\n"+
		"    certificateFile: internal-ca-two.pem\n")
	if err == nil || !strings.Contains(err.Error(), "duplicate certificate") || !strings.Contains(err.Error(), "Second Entry") {
		t.Fatalf("error = %v, want a duplicate-certificate rejection naming Second Entry", err)
	}
}

// TestFilterServesEachDeclaredType: each `type=` bundle returns the
// certificate, and the untyped bundle does not.
func TestFilterServesEachDeclaredType(t *testing.T) {
	anchors, err := loadInline(t, twoRoles("pid_provider", "eaa_provider"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Snapshot{Internal: anchors}
	fp := anchors[0].FingerprintSHA256
	for _, typ := range []string{"pid_provider", "eaa_provider"} {
		got, err := Filter(s, []string{"LV"}, "", false, typ, "")
		if err != nil {
			t.Fatalf("Filter(type=%s): %v", typ, err)
		}
		if len(got) != 1 || got[0].FingerprintSHA256 != fp || got[0].Type != typ {
			t.Errorf("Filter(type=%s) = %d anchors, want exactly the declared certificate under that type", typ, len(got))
		}
	}
	if got, _ := Filter(s, nil, "", false, "", ""); len(got) != 0 {
		t.Errorf("untyped bundle has %d anchors, want 0", len(got))
	}
}

// TestComputeDiffDeclaredTypeAddedAndRemoved: adding a second type to a
// declared certificate is exactly one addition, naming the type; taking it
// away again is exactly one removal.
func TestComputeDiffDeclaredTypeAddedAndRemoved(t *testing.T) {
	both, err := loadInline(t, twoRoles("pid_provider", "eaa_provider"))
	if err != nil {
		t.Fatal(err)
	}
	var pidOnly []Anchor
	for _, a := range both {
		if a.Type == "pid_provider" {
			pidOnly = append(pidOnly, a)
		}
	}
	prev := &Snapshot{Internal: pidOnly}
	next := &Snapshot{Internal: both}

	for _, tc := range []struct {
		name     string
		from, to *Snapshot
		kind     string
	}{
		{"add a type", prev, next, DiffAdded},
		{"remove a type", next, prev, DiffRemoved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ComputeDiff(tc.from, tc.to)
			if len(d.Entries) != 1 {
				t.Fatalf("diff has %d entries, want 1: %+v", len(d.Entries), d.Entries)
			}
			e := d.Entries[0]
			if e.Kind != tc.kind || e.Type != "eaa_provider" || e.Fingerprint != both[0].FingerprintSHA256 {
				t.Errorf("entry = %+v, want %s of eaa_provider for the declared certificate", e, tc.kind)
			}
		})
	}

	// A first snapshot holding both types reports both, not one.
	if d := ComputeDiff(nil, next); len(d.Entries) != 2 {
		t.Errorf("first-snapshot diff has %d entries, want 2", len(d.Entries))
	}
}
