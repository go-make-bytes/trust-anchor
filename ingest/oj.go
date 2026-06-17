package ingest

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/gmb-sig/trust-anchor/trust"
)

// ojELIRe extracts the OJ notice reference from an EUR-Lex ELI URI, e.g.
// https://eur-lex.europa.eu/eli/C/2026/1944/oj -> C/2026/1944.
var ojELIRe = regexp.MustCompile(`/eli/([A-Z]+/\d{4}/\d+)/oj`)

// advertisedOJReference finds the OJ reference advertised inside the LOTL
// SchemeInformationURI list. Empty when none is advertised.
func advertisedOJReference(uris []string) string {
	for _, u := range uris {
		if m := ojELIRe.FindStringSubmatch(u); m != nil {
			return m[1]
		}
	}
	return ""
}

// cellarURL builds the EUR-Lex CELLAR REST resource URL for an OJ reference.
// The CELLAR API is used because the eur-lex.europa.eu HTML is JS-rendered
// behind a WAF and unreliable for automation (verified empirically — see
// DECISIONS.md).
func cellarURL(ojRef string) string {
	return "https://publications.europa.eu/resource/eli/" + ojRef + "/oj"
}

// FetchFirstBootstrap fetches the OJ notice named by ojRef from the EU CELLAR
// API (and the OJNoticeURL override when set), extracts the LOTL signer
// certificates, and returns a candidate first-install bootstrap (version 1).
// It does NOT persist or activate anything — Manager.Initialize decides
// activation. The returned bool echoes the configured BootstrapAutoApprove so
// the Manager need not reach into the pipeline config. Implements the
// ojBootstrapSeeder interface consulted by Manager.Initialize at first install.
func (p *Pipeline) FetchFirstBootstrap(ctx context.Context, ojRef string, now time.Time) (*trust.Bootstrap, bool, error) {
	urls := []string{cellarURL(ojRef)}
	if p.cfg.OJNoticeURL != "" {
		urls = append([]string{p.cfg.OJNoticeURL}, urls...)
	}

	var certs []*x509.Certificate
	var fetchErr error
	for _, u := range urls {
		if err := p.fetcher.AllowURL(u); err != nil {
			fetchErr = err
			continue
		}
		raw, err := p.fetcher.Fetch(ctx, u)
		if err != nil {
			fetchErr = err
			continue
		}
		certs = extractCertificates(raw)
		if len(certs) > 0 {
			break
		}
		fetchErr = fmt.Errorf("no certificates found in OJ notice at %s", u)
	}
	if len(certs) == 0 {
		if fetchErr == nil {
			fetchErr = fmt.Errorf("no OJ notice source available for %s", ojRef)
		}
		return nil, p.cfg.BootstrapAutoApprove, fmt.Errorf("fetch OJ bootstrap %s: %w", ojRef, fetchErr)
	}

	boot := &trust.Bootstrap{Version: 1, OJReference: ojRef, ActivatedAt: now, Seeded: true}
	seen := map[string]struct{}{}
	for _, c := range certs {
		fp := trust.Fingerprint(c)
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		boot.CertsDER = append(boot.CertsDER, c.Raw)
	}
	return boot, p.cfg.BootstrapAutoApprove, nil
}

// stageBootstrapUpdate handles the OJ watch (task §4.7): when the LOTL
// advertises an OJ reference different from the active bootstrap's, it
// fetches the notice (best-effort — failures are treated as "no change"),
// extracts the certificates and returns a staged pending update for operator
// review. It NEVER activates anything.
func (p *Pipeline) stageBootstrapUpdate(ctx context.Context, advertised string, boot *trust.Bootstrap, prev *trust.PendingBootstrap, now time.Time) *trust.PendingBootstrap {
	if advertised == "" || advertised == boot.OJReference {
		return nil
	}
	// Already staged for the same reference — keep the existing staging.
	if prev != nil && prev.OJReference == advertised {
		return prev
	}

	urls := []string{cellarURL(advertised)}
	if p.cfg.OJNoticeURL != "" {
		urls = append([]string{p.cfg.OJNoticeURL}, urls...)
	}

	var certs []*x509.Certificate
	var fetchErr error
	for _, u := range urls {
		if err := p.fetcher.AllowURL(u); err != nil {
			fetchErr = err
			continue
		}
		raw, err := p.fetcher.Fetch(ctx, u)
		if err != nil {
			fetchErr = err
			continue
		}
		certs = extractCertificates(raw)
		if len(certs) > 0 {
			break
		}
		fetchErr = fmt.Errorf("no certificates found in OJ notice at %s", u)
	}
	if len(certs) == 0 {
		// Best-effort: treat as "no change", retry next cycle.
		p.log.Warn("OJ bootstrap notice fetch failed — treating as no change",
			zap.String("advertised_oj", advertised), zap.Error(fetchErr))
		return prev
	}

	pending := &trust.PendingBootstrap{OJReference: advertised, DetectedAt: now}
	seen := map[string]struct{}{}
	for _, c := range certs {
		fp := trust.Fingerprint(c)
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		pending.CertsDER = append(pending.CertsDER, c.Raw)
		pending.Subjects = append(pending.Subjects, c.Subject.String())
		pending.Fingerprints = append(pending.Fingerprints, fp)
	}

	active := map[string]struct{}{}
	for _, fp := range boot.Fingerprints() {
		active[fp] = struct{}{}
	}
	for _, fp := range pending.Fingerprints {
		if _, ok := active[fp]; !ok {
			pending.Added = append(pending.Added, fp)
		}
		delete(active, fp)
	}
	for fp := range active {
		pending.Removed = append(pending.Removed, fp)
	}
	sort.Strings(pending.Added)
	sort.Strings(pending.Removed)

	p.events.BootstrapReviewNeeded(nil, advertised, pending.Added, pending.Removed)
	p.log.Warn("staged OJ bootstrap update pending operator approval",
		zap.String("oj_reference", advertised),
		zap.Strings("added", pending.Added),
		zap.Strings("removed", pending.Removed))
	return pending
}

// tagRe strips markup so base64 lines split across HTML/XML elements join.
var tagRe = regexp.MustCompile(`<[^>]*>`)

// extractCertificates pulls X.509 certificates out of an OJ notice document
// (HTML, XHTML or XML). Markup and whitespace are stripped, then the text is
// scanned for the base64 DER-certificate signature ("MII" = SEQUENCE with a
// two-byte length): at each hit the DER length is read from the decoded
// header and exactly that many base64 characters are sliced and parsed.
// Surrounding prose — even when it consists of base64-alphabet characters —
// cannot corrupt the extraction because slicing is length-exact.
func extractCertificates(raw []byte) []*x509.Certificate {
	text := tagRe.ReplaceAllString(string(raw), " ")
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t', '\v', '\f', 0xA0:
			return -1
		}
		return r
	}, text)

	var out []*x509.Certificate
	for i := 0; ; {
		idx := strings.Index(clean[i:], "MII")
		if idx < 0 {
			break
		}
		start := i + idx

		cert := parseCertAt(clean[start:])
		if cert == nil {
			i = start + 3
			continue
		}
		out = append(out, cert)
		// Skip the consumed base64 characters.
		i = start + base64Len(len(cert.Raw))
	}
	return out
}

// base64Len returns the encoded length (with padding) of n raw bytes.
func base64Len(n int) int { return ((n + 2) / 3) * 4 }

// parseCertAt decodes a DER certificate that starts at the beginning of the
// base64 text s, using the DER header to size the slice exactly.
func parseCertAt(s string) *x509.Certificate {
	if len(s) < 8 {
		return nil
	}
	hdr, err := base64.StdEncoding.DecodeString(s[:8])
	if err != nil || len(hdr) < 4 || hdr[0] != 0x30 || hdr[1] != 0x82 {
		return nil
	}
	total := (int(hdr[2])<<8 | int(hdr[3])) + 4 // SEQUENCE header + content
	need := base64Len(total)
	if need > len(s) {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(s[:need])
	if err != nil || len(der) < total {
		return nil
	}
	cert, err := x509.ParseCertificate(der[:total])
	if err != nil {
		return nil
	}
	return cert
}
