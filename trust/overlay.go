package trust

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadOverlay loads the manual demo/test anchor overlay from a PEM file or a
// directory of PEM/DER files (TRUST_EXTRA_ANCHORS_PATH). Overlay anchors are
// tagged Source manual-overlay, carry no territory, no Fore* qualifier (all
// uses) and no QCWithQSCD. Production deployments leave the path empty.
func LoadOverlay(path string) ([]Anchor, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("trust: overlay path: %w", err)
	}

	var files []string
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("trust: read overlay dir: %w", err)
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

	var anchors []Anchor
	seen := map[string]struct{}{}
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // operator-controlled trust material
		if err != nil {
			return nil, fmt.Errorf("trust: read overlay file %s: %w", f, err)
		}
		certs, err := parseCerts(raw)
		if err != nil {
			return nil, fmt.Errorf("trust: overlay file %s: %w", f, err)
		}
		for _, cert := range certs {
			fp := Fingerprint(cert)
			if _, dup := seen[fp]; dup {
				continue
			}
			seen[fp] = struct{}{}
			anchors = append(anchors, Anchor{
				Source:            SourceOverlay,
				TSPName:           "manual overlay",
				ServiceName:       cert.Subject.CommonName,
				Status:            "manual-overlay",
				CertDER:           cert.Raw,
				FingerprintSHA256: fp,
				Subject:           cert.Subject.String(),
				NotBefore:         cert.NotBefore,
				NotAfter:          cert.NotAfter,
			})
		}
	}
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].FingerprintSHA256 < anchors[j].FingerprintSHA256 })
	return anchors, nil
}

// parseCerts reads one or more certificates from PEM, falling back to DER.
func parseCerts(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	if len(out) > 0 {
		return out, nil
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("neither PEM nor DER certificate: %w", err)
	}
	return []*x509.Certificate{cert}, nil
}
