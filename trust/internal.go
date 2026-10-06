package trust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
// Certificate/CertificateFile must be set. Type may be omitted (or set to
// the explicit alias "tsl_ca"): the entry then lands in the untyped TSL
// plane — a card/QC CA the EU list does not publish, served in the same
// untyped bundle as trusted-list anchors.
//
// Types declares one certificate under several EUDI roles — a CA that signs
// both PIDs and attestations, say. The entry expands into one anchor per
// listed type, all sharing its certificate, territory, status, validity and
// use cases. Type and Types are mutually exclusive.
type internalAnchor struct {
	Name            string    `yaml:"name"`
	Type            string    `yaml:"type"`
	Types           []string  `yaml:"types"`
	Territory       string    `yaml:"territory"`
	Status          string    `yaml:"status"`          // default: granted URI
	Certificate     string    `yaml:"certificate"`     // inline PEM — exactly one of
	CertificateFile string    `yaml:"certificateFile"` // ...these two
	ValidUntil      time.Time `yaml:"validUntil"`      // optional; capped by cert NotAfter
	UseCases        []string  `yaml:"useCases"`

	// Which of the two type keys the entry wrote, read off the YAML node: a
	// `types:` with no value decodes to the same nil slice as no key at all,
	// and must be rejected rather than quietly declaring an untyped CA.
	hasType, hasTypes bool
}

// untypedAlias is the explicit spelling of "no type": a declaration into the
// untyped TSL plane. Both an absent type and this alias normalize to "".
const untypedAlias = "tsl_ca"

// errMalformedSource is deliberately a STATIC message: yaml.v3 type-mismatch
// errors embed the raw offending scalar text from the file (e.g. a bad
// validUntil value echoes verbatim), and this error flows into the
// trust.internal_source_error security event. Losing the line-number detail
// is accepted — the operator re-validates the file locally — the
// no-file-contents-in-errors posture wins.
var errMalformedSource = errors.New("trust: internal trust source: malformed YAML")

// Accepted keys, from the schema's own yaml tags so the check cannot drift
// from what the decoder reads.
var (
	fileKeys  = yamlKeys(reflect.TypeFor[internalFile]())
	entryKeys = yamlKeys(reflect.TypeFor[internalAnchor]())
)

func yamlKeys(t reflect.Type) []string {
	keys := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		if k, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ","); k != "" && k != "-" {
			keys = append(keys, k)
		}
	}
	return keys
}

// errf formats a validation error naming this entry. Errors identify entries
// by name (and fingerprint, once known) only — never by embedding file
// contents or key material.
func (e internalAnchor) errf(format string, args ...any) error {
	return fmt.Errorf("trust: internal anchor %q: "+format, append([]any{e.Name}, args...)...)
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
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, errMalformedSource
	}
	root := &doc
	if root.Kind == yaml.DocumentNode {
		root = nil
		if len(doc.Content) > 0 {
			root = doc.Content[0]
		}
	}
	if root == nil || root.Kind == 0 { // empty file, or comments only
		return []Anchor{}, nil
	}

	var file internalFile
	if err := root.Decode(&file); err != nil {
		return nil, errMalformedSource
	}
	// Unknown keys reject the file. The decoder would ignore them, and an
	// ignored key is never harmless here: a misspelled `type` leaves an entry
	// untyped — the card/QC plane, not the role the operator meant — and a
	// misspelled `anchors` declares nothing at all.
	if line, unknown := unknownKey(root, fileKeys); unknown {
		return nil, fmt.Errorf("trust: internal trust source: unknown key at line %d (accepted: %s)", line, strings.Join(fileKeys, ", "))
	}
	entryNodes := sequenceItems(mappingValue(root, "anchors"))
	if len(entryNodes) != len(file.Anchors) { // cannot happen once Decode succeeded; fail closed anyway
		return nil, errMalformedSource
	}

	anchors := make([]Anchor, 0, len(file.Anchors))
	seenBy := make(map[string]string, len(file.Anchors)) // fingerprint -> declaring entry name
	for i, e := range file.Anchors {
		node := resolveAlias(entryNodes[i])
		if line, unknown := unknownKey(node, entryKeys); unknown {
			return nil, e.errf("unknown key at line %d (accepted: %s)", line, strings.Join(entryKeys, ", "))
		}
		e.hasType = mappingValue(node, "type") != nil
		e.hasTypes = mappingValue(node, "types") != nil

		built, err := buildInternalAnchors(e, baseDir, now)
		if err != nil {
			return nil, err
		}
		// One certificate, one entry: an entry carries all of a certificate's
		// roles, so the same certificate in a second entry is a mistake (a
		// leftover after a type edit, two names for one CA), never a way to
		// add a role.
		fp := built[0].FingerprintSHA256
		if declaredBy, dup := seenBy[fp]; dup {
			return nil, e.errf("duplicate certificate (fingerprint %s already declared by %q)", fp, declaredBy)
		}
		seenBy[fp] = e.Name
		anchors = append(anchors, built...)
	}

	sort.Slice(anchors, func(i, j int) bool { return internalLess(anchors[i], anchors[j]) })
	return anchors, nil
}

// internalLess orders declared anchors by fingerprint, then type — one
// certificate declared under several roles yields several anchors with the
// same fingerprint, and their order must not depend on the file's.
func internalLess(a, b Anchor) bool {
	if a.FingerprintSHA256 != b.FingerprintSHA256 {
		return a.FingerprintSHA256 < b.FingerprintSHA256
	}
	return a.Type < b.Type
}

// resolveAlias follows one YAML alias, so an aliased entry is checked like a
// written one. One level only: an alias to an alias is left as is and fails
// decoding on its own.
func resolveAlias(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}

// mappingValue returns the value node of key in mapping n, or nil.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	n = resolveAlias(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// sequenceItems returns the items of sequence n (nil for anything else).
func sequenceItems(n *yaml.Node) []*yaml.Node {
	n = resolveAlias(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

// unknownKey reports the line of the first key of mapping n that is not in
// accepted. The key itself is never returned: it is file content.
func unknownKey(n *yaml.Node, accepted []string) (int, bool) {
	if n == nil || n.Kind != yaml.MappingNode {
		return 0, false
	}
	for i := 0; i < len(n.Content); i += 2 {
		if !slices.Contains(accepted, n.Content[i].Value) {
			return n.Content[i].Line, true
		}
	}
	return 0, false
}

// declaredTypes resolves an entry's type keys to the anchor types it expands
// into: one for `type` ("" for the untyped plane), one per role for `types`.
func declaredTypes(e internalAnchor) ([]string, error) {
	if !e.hasTypes {
		t := strings.TrimSpace(e.Type)
		if t == untypedAlias {
			t = ""
		}
		if t != "" && !ValidAnchorType(t) {
			return nil, e.errf("unknown type %q", e.Type)
		}
		return []string{t}, nil
	}
	if e.hasType {
		return nil, e.errf("set either type or types, not both")
	}
	if len(e.Types) == 0 {
		return nil, e.errf("types is empty (list at least one type, or use type)")
	}
	out := make([]string, 0, len(e.Types))
	for _, raw := range e.Types {
		t := strings.TrimSpace(raw)
		switch {
		case t == "" || t == untypedAlias:
			// The untyped plane is a different kind of trust (a card/QC CA),
			// not one more role: it is declared by an entry of its own.
			return nil, e.errf("types lists EUDI anchor types only; declare an untyped CA in an entry without types")
		case !ValidAnchorType(t):
			return nil, e.errf("unknown type %q", raw)
		case slices.Contains(out, t):
			return nil, e.errf("type %q listed twice", t)
		}
		out = append(out, t)
	}
	return out, nil
}

// buildInternalAnchors validates one entry and builds its anchors — one per
// declared type. An entry with no type (or the explicit tsl_ca alias) lands
// in the untyped TSL plane; a typed entry must name known EUDI anchor types.
func buildInternalAnchors(e internalAnchor, baseDir string, now time.Time) ([]Anchor, error) {
	types, err := declaredTypes(e)
	if err != nil {
		return nil, err
	}

	territory := strings.ToUpper(strings.TrimSpace(e.Territory))
	if !validInternalTerritory(territory) {
		return nil, e.errf("invalid territory %q (want a 2-letter code or EU)", e.Territory)
	}

	certBytes, err := resolveInternalCertBytes(e, baseDir)
	if err != nil {
		return nil, err
	}
	certs, err := parseCerts(certBytes)
	if err != nil {
		return nil, e.errf("parse certificate: %w", err)
	}
	if len(certs) != 1 {
		return nil, e.errf("expected exactly one certificate, got %d", len(certs))
	}
	cert := certs[0]
	fp := Fingerprint(cert)

	if now.After(cert.NotAfter) {
		return nil, e.errf("certificate expired at %s (fingerprint %s)", cert.NotAfter.Format(time.RFC3339), fp)
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

	keyAlgorithm, curve := spkiAlgorithm(cert.Raw)
	anchors := make([]Anchor, 0, len(types))
	for _, t := range types {
		anchors = append(anchors, Anchor{
			Territory:          territory,
			Source:             SourceInternal,
			TSPName:            e.Name,
			ServiceName:        cert.Subject.CommonName,
			ServiceType:        TypeIdentifier(t),
			Status:             status,
			StatusStartingTime: cert.NotBefore,
			CertDER:            cert.Raw,
			FingerprintSHA256:  fp,
			Subject:            cert.Subject.String(),
			NotBefore:          cert.NotBefore,
			NotAfter:           notAfter,
			KeyAlgorithm:       keyAlgorithm,
			Curve:              curve,
			Type:               t,
			UseCases:           slices.Clone(e.UseCases),
		})
	}
	return anchors, nil
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
