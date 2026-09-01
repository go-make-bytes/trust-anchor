package trust

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-make-bytes/trust-anchor/tsl"
)

// bakedManifest is the operator-managed LOTL signer set the image ships with.
func bakedManifest() string {
	return filepath.Join("..", "trust-config", "lotl-signers.yaml")
}

// pemEncodeCert wraps DER certificate bytes in a PEM CERTIFICATE block.
func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestLoadBakedSignerManifest: the shipped manifest loads as the full signer
// set — the loader turns each embedded PEM block into a certificate.
func TestLoadBakedSignerManifest(t *testing.T) {
	certs, err := LoadCertsFromPath(bakedManifest())
	if err != nil {
		t.Fatalf("LoadCertsFromPath(manifest): %v", err)
	}
	if len(certs) != 6 {
		t.Fatalf("loaded %d certificates, want 6", len(certs))
	}
	for i, c := range certs {
		if len(c.Raw) == 0 {
			t.Errorf("certificate %d has no DER bytes", i)
		}
	}

	// SeedBootstrap reads the manifest's own oj_reference — no env var, no drift.
	boot, err := SeedBootstrap(bakedManifest(), time.Now().UTC())
	if err != nil {
		t.Fatalf("SeedBootstrap(manifest): %v", err)
	}
	if boot.OJReference != "C/2026/1944" {
		t.Errorf("bootstrap OJReference = %q, want C/2026/1944 (from the manifest)", boot.OJReference)
	}
	if len(boot.CertsDER) != 6 {
		t.Errorf("bootstrap certs = %d, want 6", len(boot.CertsDER))
	}
}

// TestBakedManifestValidatesLOTL is the offline-boot proof: with no network
// egress, the baked signer set validates a real EU List of Trusted Lists —
// exactly what the service does at boot when seeded from the pinned path.
func TestBakedManifestValidatesLOTL(t *testing.T) {
	certs, err := LoadCertsFromPath(bakedManifest())
	if err != nil {
		t.Fatalf("LoadCertsFromPath(manifest): %v", err)
	}

	lotl, err := os.ReadFile(filepath.Join("..", "testdata", "eu-lotl.xml"))
	if err != nil {
		t.Fatalf("read LOTL fixture: %v", err)
	}

	if _, _, err := tsl.Verify(lotl, certs); err != nil {
		t.Fatalf("baked signer set did not validate the LOTL: %v", err)
	}
}

// TestLoadCertsFromPathPEMBackCompat: a plain PEM file (and by extension the
// PEM/DER directory path) still loads — the manifest support is additive, not
// a replacement.
func TestLoadCertsFromPathPEMBackCompat(t *testing.T) {
	certs, err := LoadCertsFromPath(bakedManifest())
	if err != nil {
		t.Fatalf("LoadCertsFromPath(manifest): %v", err)
	}

	dir := t.TempDir()
	pemPath := filepath.Join(dir, "signer.pem")
	if err := os.WriteFile(pemPath, pemEncodeCert(certs[0].Raw), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadCertsFromPath(pemPath)
	if err != nil {
		t.Fatalf("LoadCertsFromPath(pem): %v", err)
	}
	if len(got) != 1 || string(got[0].Raw) != string(certs[0].Raw) {
		t.Fatalf("PEM round-trip: got %d certs, want the single re-encoded one", len(got))
	}

	// A plain PEM carries no manifest → the bootstrap records no OJ reference.
	boot, err := SeedBootstrap(pemPath, time.Now().UTC())
	if err != nil {
		t.Fatalf("SeedBootstrap(pem): %v", err)
	}
	if boot.OJReference != "" {
		t.Errorf("PEM bootstrap OJReference = %q, want empty", boot.OJReference)
	}
}

// TestLoadManifestByContentSniff: a manifest whose path carries no decisive
// extension is still recognised by its top-level "signers:" key.
func TestLoadManifestByContentSniff(t *testing.T) {
	raw, err := os.ReadFile(bakedManifest())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// A deliberately extension-less name so detection must fall to the sniff.
	p := filepath.Join(dir, "lotl-bootstrap")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	certs, err := LoadCertsFromPath(p)
	if err != nil {
		t.Fatalf("LoadCertsFromPath(sniffed manifest): %v", err)
	}
	if len(certs) != 6 {
		t.Fatalf("loaded %d certificates via content sniff, want 6", len(certs))
	}
}

// TestLoadSignerManifestFailClosed: a manifest that is malformed, empty, or
// missing an entry's certificate is rejected outright — never a partial set.
func TestLoadSignerManifestFailClosed(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"no signers", "oj_reference: C/2026/1944\n"},
		{"empty certificate", "signers:\n  - name: Empty\n    certificate: \"\"\n"},
		{"garbage certificate", "signers:\n  - name: Bad\n    certificate: |\n      not a certificate\n"},
		{"type mismatch", "signers: not-a-list\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certs, _, err := loadSignerManifest([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("loadSignerManifest(%s): got nil error, want failure", tc.name)
			}
			if len(certs) != 0 {
				t.Errorf("loadSignerManifest(%s): got %d certs on failure, want 0", tc.name, len(certs))
			}
		})
	}
}
