//go:build live

package ingest

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/go-make-bytes/trust-anchor/events"
)

// countingTransport counts requests per URL on their way to the network.
type countingTransport struct {
	next   http.RoundTripper
	mu     sync.Mutex
	counts map[string]int
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.counts[req.URL.String()]++
	c.mu.Unlock()
	return c.next.RoundTrip(req)
}

func (c *countingTransport) reset() {
	c.mu.Lock()
	c.counts = map[string]int{}
	c.mu.Unlock()
}

func (c *countingTransport) count(url string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[url]
}

// TestLiveLOTLDigestSkip runs two cycles back to back against the real
// publishers: the second must fetch the list of the lists' sibling ".sha2"
// and nothing else of it, and carry the same list metadata. Live-tagged:
// network, real upstreams.
//
//	go test -tags live ./ingest/ -run TestLiveLOTLDigestSkip -v
func TestLiveLOTLDigestSkip(t *testing.T) {
	const lotl = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
	ct := &countingTransport{next: http.DefaultTransport, counts: map[string]int{}}
	fetcher := NewFetcher(60*time.Second, 20*1024*1024)
	fetcher.SetTransport(ct)
	cfg := Config{
		LOTLURL:          lotl,
		Territories:      []string{"LV", "EE"},
		AcceptedStatuses: []string{"granted"},
		ActivationMode:   ModeAuto,
		StaleGrace:       24 * time.Hour,
	}
	log, _ := zap.NewDevelopment()
	p := NewPipeline(cfg, fetcher, events.New(log), log)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cycle 1: snapshot %s, LOTL seq %d, eu-lotl.xml fetched %d time(s), %d pointers carried",
		snap1.ID, snap1.LOTLSequence, ct.count(lotl), len(snap1.LOTLPointers))

	ct.reset()
	snap2, err := p.Refresh(context.Background(), snap1, boot)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cycle 2: snapshot %s, LOTL seq %d, eu-lotl.xml fetched %d time(s), eu-lotl.sha2 fetched %d time(s)",
		snap2.ID, snap2.LOTLSequence, ct.count(lotl), ct.count(digestURL(lotl)))
	if got := ct.count(digestURL(lotl)); got != 1 {
		t.Errorf("eu-lotl.sha2 fetched %d times on the warm cycle, want 1", got)
	}
	if got := ct.count(lotl); got != 0 {
		t.Errorf("eu-lotl.xml downloaded %d time(s) on the warm cycle — the publisher's digest did not skip it (a publication between the two cycles would explain exactly one)", got)
	}
	if snap2.LOTLSequence != snap1.LOTLSequence {
		t.Errorf("LOTL sequence moved between back-to-back cycles: %d -> %d", snap1.LOTLSequence, snap2.LOTLSequence)
	}
	if snap2.ID != snap1.ID {
		t.Logf("snapshot id moved between the cycles (%s -> %s): a national list changed in between, not a skip failure", snap1.ID, snap2.ID)
	}
}
