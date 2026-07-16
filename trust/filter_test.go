package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// testCert generates a self-signed certificate for tests.
func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func testAnchor(t *testing.T, territory, cn string, uses []string, qscd bool) Anchor {
	t.Helper()
	cert := testCert(t, cn)
	return Anchor{
		Territory:         territory,
		Source:            SourceTL,
		TSPName:           "TSP " + cn,
		ServiceName:       cn,
		Status:            NormalizeStatus("granted"),
		CertDER:           cert.Raw,
		FingerprintSHA256: Fingerprint(cert),
		Subject:           cert.Subject.String(),
		Uses:              uses,
		QCWithQSCD:        qscd,
	}
}

func testSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	s := &Snapshot{
		GeneratedAt:  time.Now().UTC(),
		LOTLSequence: 1,
		Territories: []*Territory{
			{Code: "EE", TLSequence: 1, Anchors: []Anchor{
				testAnchor(t, "EE", "ee-sig", []string{UseSignature}, true),
			}},
			{Code: "LV", TLSequence: 1, Anchors: []Anchor{
				testAnchor(t, "LV", "lv-sig", []string{UseSignature}, true),
				testAnchor(t, "LV", "lv-seal", []string{UseSeal}, false),
				testAnchor(t, "LV", "lv-any", nil, false),
			}},
		},
		Overlay: []Anchor{func() Anchor {
			a := testAnchor(t, "", "demo-overlay", nil, false)
			a.Source = SourceOverlay
			return a
		}()},
	}
	s.ComputeID()
	return s
}

func TestFilterTerritoryAndUse(t *testing.T) {
	s := testSnapshot(t)

	all, err := Filter(s, nil, "", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 { // 4 TL anchors + overlay
		t.Fatalf("unfiltered: got %d anchors, want 5", len(all))
	}

	lv, err := Filter(s, []string{"LV"}, "", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(lv) != 4 { // 3 LV + overlay (overlay merges into every bundle)
		t.Fatalf("LV: got %d anchors, want 4", len(lv))
	}

	sig, err := Filter(s, []string{"LV"}, UseSignature, false, "")
	if err != nil {
		t.Fatal(err)
	}
	// lv-sig (signature), lv-any (no Fore* → all uses), overlay (no uses).
	if len(sig) != 3 {
		t.Fatalf("LV signature: got %d anchors, want 3", len(sig))
	}
	for _, a := range sig {
		if a.ServiceName == "lv-seal" {
			t.Error("seal-only anchor included in signature bundle")
		}
	}

	// authentication is an alias of signature at anchor level.
	auth, err := Filter(s, []string{"LV"}, UseAuthentication, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(auth) != len(sig) {
		t.Fatalf("authentication bundle (%d) differs from signature bundle (%d)", len(auth), len(sig))
	}

	qscd, err := Filter(s, []string{"LV", "EE"}, "", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(qscd) != 2 {
		t.Fatalf("qscdOnly: got %d anchors, want 2", len(qscd))
	}

	if _, err := Filter(s, nil, "bogus", false, ""); err == nil {
		t.Fatal("invalid use accepted")
	}
}

// TestFilterIncludesInternal proves the merge point AND the type= exclusion
// rule together: s.Internal is merged
// through the same matches() gate as Overlay, but a TYPED internal anchor
// (Type: "pid_provider" here) is now excluded from the untyped (legacy)
// bundle and served ONLY by its own type= query — closing the mid-plan leak
// that this test used to pin (T2: a typed internal anchor was
// indistinguishable from a legacy CA/QC anchor in the untyped bundle).
func TestFilterIncludesInternal(t *testing.T) {
	cert := testCert(t, "internal-anchor")
	s := &Snapshot{
		Territories: []*Territory{{Code: "LV", Anchors: []Anchor{
			testAnchor(t, "LV", "lv-sig", []string{UseSignature}, true),
		}}},
		Internal: []Anchor{{
			Source:            SourceInternal,
			Type:              "pid_provider",
			CertDER:           cert.Raw,
			FingerprintSHA256: Fingerprint(cert),
			Subject:           cert.Subject.String(),
		}},
	}

	// Untyped (legacy) bundle: only the TL anchor — the typed internal
	// anchor no longer leaks in.
	untyped, err := Filter(s, nil, "", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(untyped) != 1 {
		t.Fatalf("untyped: got %d anchors, want 1 (TL only, typed internal excluded)", len(untyped))
	}
	for _, a := range untyped {
		if a.Source == SourceInternal {
			t.Error("typed internal anchor leaked into the untyped Filter() output")
		}
	}

	// type=pid_provider: only the internal anchor, from any source.
	typed, err := Filter(s, nil, "", false, "pid_provider")
	if err != nil {
		t.Fatal(err)
	}
	if len(typed) != 1 {
		t.Fatalf("typed: got %d anchors, want 1 (internal only)", len(typed))
	}
	if typed[0].Source != SourceInternal || typed[0].Type != "pid_provider" {
		t.Errorf("typed Filter() output = %+v, want the internal pid_provider anchor", typed[0])
	}

	// Unknown type is rejected (fail closed).
	if _, err := Filter(s, nil, "", false, "bogus"); err == nil {
		t.Fatal("invalid type accepted")
	}
}

func TestPEMBundleParses(t *testing.T) {
	s := testSnapshot(t)
	anchors, err := Filter(s, nil, "", false, "")
	if err != nil {
		t.Fatal(err)
	}
	bundle := PEMBundle(anchors)

	// The consumer contract: the bundle must parse with crypto/x509.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		t.Fatal("PEM bundle did not parse")
	}
	certs, err := parseCerts(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != len(anchors) {
		t.Fatalf("bundle has %d certs, want %d", len(certs), len(anchors))
	}
}

func TestSnapshotIDStability(t *testing.T) {
	s := testSnapshot(t)
	id1 := s.ID

	// Generation time must not change the content hash (ETag stability).
	s.GeneratedAt = s.GeneratedAt.Add(time.Hour)
	if got := s.ComputeID(); got != id1 {
		t.Error("snapshot ID changed with GeneratedAt")
	}

	// Removing an anchor must change it.
	s.Territories[1].Anchors = s.Territories[1].Anchors[:2]
	if got := s.ComputeID(); got == id1 {
		t.Error("snapshot ID unchanged after anchor removal")
	}
}

// goldenSnapshot builds a deterministic (no random keys/certs) snapshot used
// to pin the content hash across the T1 type-model change. ComputeID only
// projects Fingerprint/Status/QSCD/Uses/Source into idAnchor, so fixed
// fingerprint strings are enough to make the ID reproducible run-to-run
// (unlike testSnapshot, whose certs — and thus fingerprints — are random).
func goldenSnapshot() *Snapshot {
	return &Snapshot{
		LOTLSequence: 1,
		Territories: []*Territory{
			{Code: "EE", TLSequence: 1, Anchors: []Anchor{
				{Source: SourceTL, FingerprintSHA256: "1111111111111111111111111111111111111111111111111111111111111a", Status: NormalizeStatus("granted"), QCWithQSCD: true, Uses: []string{UseSignature}},
			}},
			{Code: "LV", TLSequence: 1, Anchors: []Anchor{
				{Source: SourceTL, FingerprintSHA256: "2222222222222222222222222222222222222222222222222222222222222b", Status: NormalizeStatus("granted"), QCWithQSCD: true, Uses: []string{UseSignature}},
				{Source: SourceTL, FingerprintSHA256: "3333333333333333333333333333333333333333333333333333333333333c", Status: NormalizeStatus("granted"), QCWithQSCD: false, Uses: []string{UseSeal}},
				{Source: SourceTL, FingerprintSHA256: "4444444444444444444444444444444444444444444444444444444444444d", Status: NormalizeStatus("granted"), QCWithQSCD: false},
			}},
		},
		Overlay: []Anchor{
			{Source: SourceOverlay, FingerprintSHA256: "5555555555555555555555555555555555555555555555555555555555555e", Status: NormalizeStatus("granted"), QCWithQSCD: false},
		},
	}
}

// goldenSnapshotID is the ComputeID() of goldenSnapshot() captured from a run
// BEFORE T1 (Anchor/idAnchor had no Type/UseCases/TLSequence). It must not
// change: the new idAnchor fields are `,omitempty` and this fixture's
// anchors carry no Type/UseCases, so the serialized idContent — and hence
// the ID/ETag — must stay byte-identical across the upgrade.
const goldenSnapshotID = "2944f1799ba7fac3fe6733f9b725bff1b038c4ed448d22fb02d4908bf7d05521"

// TestComputeIDStableWithoutTypedFields: a snapshot whose anchors carry no
// Type/UseCases must produce the SAME ID as before this change (ETag
// stability across the upgrade — legacy consumers must not refetch). Pins
// the ID of the golden fixture captured from a pre-change run.
func TestComputeIDStableWithoutTypedFields(t *testing.T) {
	s := goldenSnapshot()
	if got := s.ComputeID(); got != goldenSnapshotID {
		t.Fatalf("ComputeID() = %s, want golden %s (legacy/untyped snapshot ID must not move)", got, goldenSnapshotID)
	}
}

// TestComputeIDChangesOnType: same snapshot, one anchor gains Type =
// "pid_provider" -> ID must change. Same for a UseCases change.
func TestComputeIDChangesOnType(t *testing.T) {
	baseID := goldenSnapshot().ComputeID()

	withType := goldenSnapshot()
	withType.Territories[0].Anchors[0].Type = "pid_provider"
	if got := withType.ComputeID(); got == baseID {
		t.Error("ComputeID unchanged after setting Type")
	}

	withUseCases := goldenSnapshot()
	withUseCases.Territories[0].Anchors[0].UseCases = []string{"pid"}
	if got := withUseCases.ComputeID(); got == baseID {
		t.Error("ComputeID unchanged after setting UseCases")
	}
}

// TestValidAnchorType: all 11 taxonomy values true; "", "bogus",
// "PID_PROVIDER" false (fail closed on anything unrecognized, case-sensitive).
func TestValidAnchorType(t *testing.T) {
	if len(AnchorTypes) != 11 {
		t.Fatalf("AnchorTypes has %d entries, want 11", len(AnchorTypes))
	}
	for typ := range AnchorTypes {
		if !ValidAnchorType(typ) {
			t.Errorf("ValidAnchorType(%q) = false, want true", typ)
		}
	}
	for _, bad := range []string{"", "bogus", "PID_PROVIDER"} {
		if ValidAnchorType(bad) {
			t.Errorf("ValidAnchorType(%q) = true, want false", bad)
		}
	}
}

func TestComputeDiff(t *testing.T) {
	prev := testSnapshot(t)
	next := testSnapshot(t) // different certs (fresh random keys) — all changed

	// Same snapshot → empty diff.
	if d := ComputeDiff(prev, prev); !d.Empty() {
		t.Fatalf("self-diff not empty: %+v", d.Entries)
	}

	d := ComputeDiff(prev, next)
	var added, removed int
	for _, e := range d.Entries {
		switch e.Kind {
		case DiffAdded:
			added++
		case DiffRemoved:
			removed++
		}
	}
	if added != 5 || removed != 5 {
		t.Fatalf("added=%d removed=%d, want 5/5", added, removed)
	}

	// Status change on the same cert → changed entry.
	mod := &Snapshot{Territories: []*Territory{{Code: "LV", Anchors: append([]Anchor(nil), prev.Territory("LV").Anchors...)}}}
	mod.Territories[0].Anchors[0].Status = NormalizeStatus("withdrawn")
	d2 := ComputeDiff(&Snapshot{Territories: []*Territory{prev.Territory("LV")}}, mod)
	var changed int
	for _, e := range d2.Entries {
		if e.Kind == DiffChanged {
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("changed=%d, want 1", changed)
	}

	// First snapshot: everything added.
	d3 := ComputeDiff(nil, prev)
	if len(d3.Entries) != 5 {
		t.Fatalf("first-snapshot diff has %d entries, want 5", len(d3.Entries))
	}
}

// TestComputeDiffIncludesInternal proves ComputeDiff diffs s.Internal like
// s.Overlay (internal anchors must
// be included in ComputeID, ComputeDiff, and trust.anchor_change events).
// prev/next differ by exactly one internal anchor; the diff must report it
// as added (forward) / removed (reverse).
func TestComputeDiffIncludesInternal(t *testing.T) {
	internalAnchor := func(t *testing.T, cn string) Anchor {
		a := testAnchor(t, "", cn, nil, false)
		a.Source = SourceInternal
		a.Territory = ""
		return a
	}

	prev := &Snapshot{Internal: []Anchor{internalAnchor(t, "internal-kept")}}
	next := &Snapshot{Internal: []Anchor{
		internalAnchor(t, "internal-kept"),
		internalAnchor(t, "internal-new"),
	}}
	// Reuse the same fingerprint for "kept" across snapshots so it is not
	// seen as both removed and added.
	next.Internal[0] = prev.Internal[0]

	d := ComputeDiff(prev, next)
	var added []DiffEntry
	for _, e := range d.Entries {
		if e.Kind == DiffAdded {
			added = append(added, e)
		}
	}
	if len(added) != 1 {
		t.Fatalf("added entries = %d, want 1 (%+v)", len(added), d.Entries)
	}
	if added[0].Fingerprint != next.Internal[1].FingerprintSHA256 {
		t.Errorf("added fingerprint = %q, want the new internal anchor's %q", added[0].Fingerprint, next.Internal[1].FingerprintSHA256)
	}
	if added[0].Source != SourceInternal {
		t.Errorf("added entry Source = %q, want %q", added[0].Source, SourceInternal)
	}

	// Reverse: removing the internal anchor is reported as DiffRemoved.
	dRev := ComputeDiff(next, prev)
	var removed []DiffEntry
	for _, e := range dRev.Entries {
		if e.Kind == DiffRemoved {
			removed = append(removed, e)
		}
	}
	if len(removed) != 1 {
		t.Fatalf("removed entries = %d, want 1 (%+v)", len(removed), dRev.Entries)
	}
	if removed[0].Fingerprint != next.Internal[1].FingerprintSHA256 {
		t.Errorf("removed fingerprint = %q, want the internal anchor's %q", removed[0].Fingerprint, next.Internal[1].FingerprintSHA256)
	}
}
