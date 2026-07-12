package trust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// grantedStatusURI is the status assigned to an internal anchor that does
// not declare one explicitly — internal anchors default to the same
// "granted" status TL-extracted anchors carry.
const grantedStatusURI = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"

// internalFile is the package-internal YAML schema for INTERNAL_TRUST_SOURCE.
// The file is a trust root: operator-controlled config, the same posture as
// LOTL_BOOTSTRAP_CERTS_PATH — every entry is a certificate the service
// trusts directly, with no TL/XMLDSig chain behind it.
type internalFile struct {
	Anchors []internalAnchor `yaml:"anchors"`
}

// internalAnchor is one operator-declared entry. Exactly one of
// Certificate/CertificateFile must be set.
type internalAnchor struct {
	Name            string    `yaml:"name"`
	Type            string    `yaml:"type"`
	Territory       string    `yaml:"territory"`
	Status          string    `yaml:"status"`          // default: granted URI
	Certificate     string    `yaml:"certificate"`     // inline PEM — exactly one of
	CertificateFile string    `yaml:"certificateFile"` // ...these two
	ValidUntil      time.Time `yaml:"validUntil"`      // optional; capped by cert NotAfter
	UseCases        []string  `yaml:"useCases"`
}

// errf formats a validation error naming this entry. Errors identify entries
// by name (and fingerprint, once known) only — never by embedding file
// contents or key material.
func (e internalAnchor) errf(format string, args ...any) error {
	return fmt.Errorf("trust: internal anchor %q: "+format, append([]any{e.Name}, args...)...)
}

// eudiServiceTypeSuffix maps every taxonomy value (AnchorTypes) to the
// CamelCase suffix of its placeholder EUDI service-type URI. Table-driven
// (not a switch) so a taxonomy addition without a matching row here is
// visibly incomplete rather than silently falling through to a default.
var eudiServiceTypeSuffix = map[string]string{
	"pid_provider":            "PidProvider",
	"qeaa_provider":           "QEAAProvider",
	"pub_eaa_provider":        "PubEAAProvider",
	"eaa_provider":            "EAAProvider",
	"wallet_provider":         "WalletProvider",
	"access_ca":               "AccessCA",
	"wrprc_issuer":            "WRPRCIssuer",
	"pid_provider_status":     "PidProviderStatus",
	"qeaa_provider_status":    "QEAAProviderStatus",
	"pub_eaa_provider_status": "PubEAAProviderStatus",
	"eaa_provider_status":     "EAAProviderStatus",
}

const eudiServiceTypeBase = "http://uri.etsi.org/TrstSvc/Svctype/EUDI/"

// serviceTypeURIFor maps the taxonomy onto placeholder EUDI service-type
// URIs (consistent with the consumer's mock fixtures; real URIs pending
// CID (EU) 2025/2164 — extension E1). Informational only: the consumer
// filters by the type= request param, never by this URI. Callers must
// reject unknown types before calling this (ValidAnchorType) — an unmapped
// type returns "".
func serviceTypeURIFor(t string) string {
	suffix, ok := eudiServiceTypeSuffix[t]
	if !ok {
		return ""
	}
	return eudiServiceTypeBase + suffix
}

// LoadInternal parses and validates the operator-declared anchor file named
// by INTERNAL_TRUST_SOURCE. An unset path is not an error — the internal
// source is optional — and returns (nil, nil).
//
// Fail-closed: ANY invalid entry rejects the WHOLE file. An operator typo in
// one entry must never silently drop just that CA while serving the rest;
// the caller (the ingest pipeline) carries the previous internal set over
// instead of adopting a partial one.
func LoadInternal(path string, now time.Time) ([]Anchor, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // operator-controlled trust material
	if err != nil {
		return nil, fmt.Errorf("trust: internal trust source: %w", err)
	}
	return loadInternalBytes(raw, filepath.Dir(path), now)
}

// loadInternalBytes is LoadInternal's parser, split out so it can be fuzzed
// directly on bytes without a filesystem round-trip. baseDir resolves
// relative certificateFile entries.
func loadInternalBytes(raw []byte, baseDir string, now time.Time) ([]Anchor, error) {
	var file internalFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		// Deliberately a STATIC message: yaml.v3 type-mismatch errors embed
		// the raw offending scalar text from the file (e.g. a bad validUntil
		// value echoes verbatim), and this error flows into the
		// trust.internal_source_error security event. Losing the
		// line-number detail is accepted — the operator re-validates the
		// file locally — the no-file-contents-in-errors posture wins.
		return nil, errors.New("trust: internal trust source: malformed YAML")
	}

	anchors := make([]Anchor, 0, len(file.Anchors))
	seenBy := make(map[string]string, len(file.Anchors)) // fingerprint -> declaring entry name
	for _, e := range file.Anchors {
		anchor, err := buildInternalAnchor(e, baseDir, now)
		if err != nil {
			return nil, err
		}
		if declaredBy, dup := seenBy[anchor.FingerprintSHA256]; dup {
			return nil, e.errf("duplicate certificate (fingerprint %s already declared by %q)", anchor.FingerprintSHA256, declaredBy)
		}
		seenBy[anchor.FingerprintSHA256] = e.Name
		anchors = append(anchors, anchor)
	}

	sort.Slice(anchors, func(i, j int) bool { return anchors[i].FingerprintSHA256 < anchors[j].FingerprintSHA256 })
	return anchors, nil
}

// buildInternalAnchor validates one entry and builds its Anchor.
func buildInternalAnchor(e internalAnchor, baseDir string, now time.Time) (Anchor, error) {
	if !ValidAnchorType(e.Type) {
		return Anchor{}, e.errf("unknown type %q", e.Type)
	}

	territory := strings.ToUpper(strings.TrimSpace(e.Territory))
	if !validInternalTerritory(territory) {
		return Anchor{}, e.errf("invalid territory %q (want a 2-letter code or EU)", e.Territory)
	}

	certBytes, err := resolveInternalCertBytes(e, baseDir)
	if err != nil {
		return Anchor{}, err
	}
	certs, err := parseCerts(certBytes)
	if err != nil {
		return Anchor{}, e.errf("parse certificate: %w", err)
	}
	if len(certs) != 1 {
		return Anchor{}, e.errf("expected exactly one certificate, got %d", len(certs))
	}
	cert := certs[0]
	fp := Fingerprint(cert)

	if now.After(cert.NotAfter) {
		return Anchor{}, e.errf("certificate expired at %s (fingerprint %s)", cert.NotAfter.Format(time.RFC3339), fp)
	}

	// validUntil defaults to the certificate's own NotAfter and is capped to
	// min(declared, cert.NotAfter) — an operator cannot extend an anchor's
	// life past the certificate's own validity window.
	notAfter := cert.NotAfter
	if !e.ValidUntil.IsZero() && e.ValidUntil.Before(notAfter) {
		notAfter = e.ValidUntil
	}

	status := e.Status
	if status == "" {
		status = grantedStatusURI
	}

	return Anchor{
		Territory:          territory,
		Source:             SourceInternal,
		TSPName:            e.Name,
		ServiceName:        cert.Subject.CommonName,
		ServiceType:        serviceTypeURIFor(e.Type),
		Status:             status,
		StatusStartingTime: cert.NotBefore,
		CertDER:            cert.Raw,
		FingerprintSHA256:  fp,
		Subject:            cert.Subject.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           notAfter,
		Type:               e.Type,
		UseCases:           e.UseCases,
	}, nil
}

// resolveInternalCertBytes returns the raw certificate bytes for one entry,
// enforcing exactly one certificate source.
func resolveInternalCertBytes(e internalAnchor, baseDir string) ([]byte, error) {
	switch {
	case e.Certificate != "" && e.CertificateFile != "":
		return nil, e.errf("exactly one of certificate/certificateFile must be set, both given")
	case e.Certificate != "":
		return []byte(e.Certificate), nil
	case e.CertificateFile != "":
		p := e.CertificateFile
		if !filepath.IsAbs(p) {
			p = filepath.Join(baseDir, p)
		}
		raw, err := os.ReadFile(p) //nolint:gosec // operator-controlled trust material
		if err != nil {
			return nil, e.errf("read certificateFile %s: %w", p, err)
		}
		return raw, nil
	default:
		return nil, e.errf("missing certificate source (set certificate or certificateFile)")
	}
}

// validInternalTerritory reports whether t (already upper-cased) is a
// 2-letter code: an ISO 3166-1 alpha-2 country code, or the pseudo-code "EU"
// trusted lists use for pan-European services.
func validInternalTerritory(t string) bool {
	if len(t) != 2 {
		return false
	}
	for _, r := range t {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}
