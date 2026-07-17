package trust

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// LoadCertsFromPath loads X.509 certificates from an operator-pinned bootstrap
// path: a LOTL signer manifest (lotl-signers.yaml), a single PEM/DER file, or
// a directory of PEM/DER files. Used for the LOTL bootstrap seed and tests.
func LoadCertsFromPath(path string) ([]*x509.Certificate, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		raw, err := os.ReadFile(path) //nolint:gosec // operator-controlled trust material
		if err != nil {
			return nil, err
		}
		return parseBootstrapFile(path, raw)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var files []string
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

// signersKeyRe matches the manifest's top-level "signers:" key. A PEM/DER
// certificate file never contains it (base64 has no colon, and PEM headers
// carry none), so it is a safe content sniff for a path with no decisive
// extension.
var signersKeyRe = regexp.MustCompile(`(?m)^signers[ \t]*:`)

// parseBootstrapFile turns a single bootstrap file's bytes into certificates.
// A LOTL signer manifest — a structured "signers:" list with each certificate
// embedded as a PEM block — is parsed as such; any other file is read as raw
// PEM/DER certificate material. The manifest is recognised by a .yaml/.yml
// extension or a top-level "signers:" key, so the pinned path can point at
// either shape (a manifest, or a plain concatenated PEM).
func parseBootstrapFile(path string, raw []byte) ([]*x509.Certificate, error) {
	if isSignerManifest(path, raw) {
		return loadSignerManifest(raw)
	}
	certs, err := parseCerts(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found at %s", path)
	}
	return certs, nil
}

// isSignerManifest reports whether a single-file bootstrap path should be
// parsed as a LOTL signer manifest rather than raw PEM/DER.
func isSignerManifest(path string, raw []byte) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return true
	case ".pem", ".crt", ".cer", ".der":
		return false
	default:
		return signersKeyRe.Match(raw)
	}
}

// signerManifest is the LOTL signer set (lotl-signers.yaml): the certificates
// authorised to sign the EU List of Trusted Lists, each embedded as a PEM
// block. Only the fields the loader needs are modelled; the manifest also
// carries human metadata (issuer, validity, fingerprints) that is
// informational and cross-checked out of band before a change is trusted.
type signerManifest struct {
	Signers []manifestSigner `yaml:"signers"`
}

type manifestSigner struct {
	Name        string `yaml:"name"`
	Certificate string `yaml:"certificate"`
}

// loadSignerManifest parses a LOTL signer manifest and returns its embedded
// certificates. Fail-closed: malformed YAML, an entry missing its certificate,
// or an entry whose PEM does not hold exactly one certificate is an error — a
// partial or ambiguous bootstrap set is never returned.
func loadSignerManifest(raw []byte) ([]*x509.Certificate, error) {
	var m signerManifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		// Static message: a YAML type-mismatch error echoes the offending
		// scalar verbatim, and bootstrap material must not leak into an error.
		return nil, errors.New("trust: LOTL signer manifest: malformed YAML")
	}
	if len(m.Signers) == 0 {
		return nil, errors.New("trust: LOTL signer manifest: no signers declared")
	}
	out := make([]*x509.Certificate, 0, len(m.Signers))
	for i, s := range m.Signers {
		if strings.TrimSpace(s.Certificate) == "" {
			return nil, fmt.Errorf("trust: LOTL signer manifest: signer %d (%q): missing certificate", i+1, s.Name)
		}
		certs, err := parseCerts([]byte(s.Certificate))
		if err != nil {
			return nil, fmt.Errorf("trust: LOTL signer manifest: signer %d (%q): %w", i+1, s.Name, err)
		}
		if len(certs) != 1 {
			return nil, fmt.Errorf("trust: LOTL signer manifest: signer %d (%q): expected exactly one certificate, got %d", i+1, s.Name, len(certs))
		}
		out = append(out, certs[0])
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
