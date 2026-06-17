// Package ingest implements the trust-anchor ingestion pipeline: LOTL fetch,
// pivot-chain processing, national TL verification, anchor extraction,
// snapshot assembly and change governance.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gmb-sig/go-platform-kit/observability"
)

// ErrEgressBlocked marks a fetch refused by the egress allow-list.
var ErrEgressBlocked = errors.New("ingest: egress blocked")

// Fetcher downloads trusted-list material over TLS with an explicit host
// allow-list, a response size cap and a per-request timeout. The allow-list
// starts with the LOTL host (plus the OJ hosts for the bootstrap watch) and
// is extended with TL hosts discovered from the *verified* LOTL.
type Fetcher struct {
	client  *http.Client
	timeout time.Duration
	maxSize int64

	mu      sync.RWMutex
	allowed map[string]struct{}
}

// NewFetcher builds a Fetcher allowing the given initial hosts.
func NewFetcher(timeout time.Duration, maxSize int64, initialHosts ...string) *Fetcher {
	f := &Fetcher{
		// TLS certificate verification is the default transport behaviour and
		// must never be disabled here — these fetches define trust. The transport
		// is otel-instrumented so LOTL/CELLAR/national-TL fetches show as client
		// spans (no-op when tracing is inert).
		client:  &http.Client{Timeout: timeout, Transport: observability.InstrumentedTransport(nil)},
		timeout: timeout,
		maxSize: maxSize,
		allowed: map[string]struct{}{},
	}
	for _, h := range initialHosts {
		f.Allow(h)
	}
	return f
}

// SetTransport replaces the HTTP transport. Test use only — hermetic pipeline
// tests serve recorded fixtures through a stub RoundTripper. The https +
// allow-list checks still run against the request URL.
func (f *Fetcher) SetTransport(rt http.RoundTripper) {
	f.client = &http.Client{Timeout: f.timeout, Transport: rt}
}

// Allow adds a host to the egress allow-list.
func (f *Fetcher) Allow(host string) {
	if host == "" {
		return
	}
	f.mu.Lock()
	f.allowed[strings.ToLower(host)] = struct{}{}
	f.mu.Unlock()
}

// AllowURL adds the URL's host to the allow-list after validating the scheme.
// It returns an error (without adding) for non-https locations.
func (f *Fetcher) AllowURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("ingest: invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: %q is not https", ErrEgressBlocked, raw)
	}
	f.Allow(u.Hostname())
	return nil
}

// Fetch downloads raw bytes from rawURL, enforcing https, the allow-list and
// the size cap. The parent ctx is detached before the timeout is derived so a
// pooled request context can never race the watcher goroutine (go-platform-kit
// broker Transport note).
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ingest: invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: %q is not https", ErrEgressBlocked, rawURL)
	}
	f.mu.RLock()
	_, ok := f.allowed[strings.ToLower(u.Hostname())]
	f.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: host %q not in allow-list", ErrEgressBlocked, u.Hostname())
	}

	reqCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), f.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.etsi.tsl+xml, application/xml;q=0.9, */*;q=0.1")
	// Some TL hosts (e.g. sr.riik.ee) reject Go's default User-Agent.
	req.Header.Set("User-Agent", "trust-anchor/1.0 (eSignature-Portal trusted-list ingester)")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ingest: fetch %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ingest: fetch %s: unexpected status %d", rawURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("ingest: read %s: %w", rawURL, err)
	}
	if int64(len(body)) > f.maxSize {
		return nil, fmt.Errorf("ingest: %s exceeds size cap of %d bytes", rawURL, f.maxSize)
	}
	return body, nil
}

// digestURL derives the sibling checksum URL for a trusted-list URL: the same
// base path with the extension replaced by ".sha2" (the EU scheme convention —
// both the LOTL and the national TLs publish one, e.g. latvian-tsl.xml →
// latvian-tsl.sha2). Falls back to appending ".sha2" when there is no extension.
func digestURL(listURL string) string {
	if i := strings.LastIndex(listURL, "."); i > strings.LastIndex(listURL, "/") {
		return listURL[:i] + ".sha2"
	}
	return listURL + ".sha2"
}

// FetchDigest fetches the sibling ".sha2" for a trusted-list URL and returns its
// trimmed lowercase hex value (the SHA-256 of the list bytes, confirmed equal to
// the published checksum). It is an input-side change-detection signal only
// (spec P2): the caller still XMLDSig-verifies anything it downloads. Any error
// (including a 404 when no sibling digest is published) is returned so the caller
// falls back to a full fetch. The list's host must already be allow-listed
// (AllowURL on the list URL also covers its same-host ".sha2").
func (f *Fetcher) FetchDigest(ctx context.Context, listURL string) (string, error) {
	body, err := f.Fetch(ctx, digestURL(listURL))
	if err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(string(body))), nil
}
