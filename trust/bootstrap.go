package trust

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LoadCertsFromPath loads X.509 certificates from a PEM file or a directory
// of PEM/DER files. Used for the OJEU bootstrap seed and tests.
func LoadCertsFromPath(path string) ([]*x509.Certificate, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	var files []string
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			switch strings.ToLower(filepath.Ext(e.Name())) {
			case ".pem", ".crt", ".cer", ".der":
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}

	var out []*x509.Certificate
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // operator-controlled trust material
		if err != nil {
			return nil, err
		}
		certs, err := parseCerts(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, certs...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificates found at %s", path)
	}
	return out, nil
}

// SeedBootstrap builds the version-1 bootstrap state from the operator-pinned
// certificates at path (LOTL_BOOTSTRAP_CERTS_PATH) and the OJ reference they
// were taken from (OJ_PINNED_REFERENCE).
func SeedBootstrap(path, ojReference string, now time.Time) (*Bootstrap, error) {
	certs, err := LoadCertsFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("trust: load bootstrap certs: %w", err)
	}
	b := &Bootstrap{Version: 1, OJReference: ojReference, ActivatedAt: now, Seeded: true}
	for _, c := range certs {
		b.CertsDER = append(b.CertsDER, c.Raw)
	}
	return b, nil
}
