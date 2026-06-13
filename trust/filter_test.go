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

	all, err := Filter(s, nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 { // 4 TL anchors + overlay
		t.Fatalf("unfiltered: got %d anchors, want 5", len(all))
	}

	lv, err := Filter(s, []string{"LV"}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(lv) != 4 { // 3 LV + overlay (overlay merges into every bundle)
		t.Fatalf("LV: got %d anchors, want 4", len(lv))
	}

	sig, err := Filter(s, []string{"LV"}, UseSignature, false)
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
	auth, err := Filter(s, []string{"LV"}, UseAuthentication, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(auth) != len(sig) {
		t.Fatalf("authentication bundle (%d) differs from signature bundle (%d)", len(auth), len(sig))
	}

	qscd, err := Filter(s, []string{"LV", "EE"}, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(qscd) != 2 {
		t.Fatalf("qscdOnly: got %d anchors, want 2", len(qscd))
	}

	if _, err := Filter(s, nil, "bogus", false); err == nil {
		t.Fatal("invalid use accepted")
	}
}

func TestPEMBundleParses(t *testing.T) {
	s := testSnapshot(t)
	anchors, err := Filter(s, nil, "", false)
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
