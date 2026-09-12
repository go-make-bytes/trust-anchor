package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-make-bytes/trust-anchor/tsl"
)

// The list of the lists' own ".sha2": the same input-side skip the national
// lists have, one level up. The territory pointer set the loop needs is
// carried in the snapshot, so a matching digest lets the loop run without
// the download — and every anti-freeze rule of the national skip holds here
// too. (A pivot rotation with a matching digest cannot occur: a rotated list
// of the lists is new bytes, so its digest differs by construction.)

func serveMatchingLOTLDigest(t *testing.T, ft *fixtureTransport) {
	t.Helper()
	ft.body[digestURL(lotlURL)] = []byte(sha256hex(readTestdata(t, "eu-lotl.xml")))
}

func sameDER(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func TestRefreshSkipsUnchangedLOTLViaDigest(t *testing.T) {
	ft := newFixtureTransport()
	serveMatchingLOTLDigest(t, ft)
	p := testPipeline(t, ft, ModeAuto)
	// A configured territory the list has no pointer for must fail the same
	// way whether the pointer set came off the list or was carried.
	p.cfg.Territories = append(p.cfg.Territories, "XX")
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256hex(readTestdata(t, "eu-lotl.xml")); snap1.LOTLDigest != want {
		t.Fatalf("LOTLDigest = %q, want the list's SHA-256 %q", snap1.LOTLDigest, want)
	}
	lotl, err := tsl.Parse(readTestdata(t, "eu-lotl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(snap1.LOTLPointers), len(lotl.Territories()); got != want {
		t.Fatalf("carried %d pointers, want one per list territory (%d)", got, want)
	}
	derBytes := 0
	for _, lp := range snap1.LOTLPointers {
		if lp.Failure != "" || lp.URL == "" || len(lp.SignersDER) == 0 {
			t.Fatalf("pointer for %s is not usable: %+v", lp.Territory, lp)
		}
		for _, d := range lp.SignersDER {
			derBytes += len(d)
		}
	}
	full, err := json.Marshal(snap1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pointer set: %d territories, %d bytes of signer DER; snapshot JSON %d bytes", len(snap1.LOTLPointers), derBytes, len(full))

	// A restart's worth of persistence: the carried inputs survive the JSON
	// round trip the stores use.
	prev, err := cloneSnapshot(snap1)
	if err != nil {
		t.Fatal(err)
	}
	// The national lists publish no digest here, so both are downloaded
	// again: the loop must run — and verify — off the carried pointer set.
	ft.counts = map[string]int{}

	snap2, err := p.Refresh(context.Background(), prev, boot)
	if err != nil {
		t.Fatal(err)
	}
	if ft.counts[lotlURL] != 0 {
		t.Errorf("LOTL was downloaded (%d) despite a matching .sha2", ft.counts[lotlURL])
	}
	if ft.counts[digestURL(lotlURL)] != 1 {
		t.Errorf("LOTL .sha2 fetched %d times, want 1", ft.counts[digestURL(lotlURL)])
	}
	if ft.counts[lvURL] != 1 || ft.counts[eeURL] != 1 {
		t.Errorf("territory loop did not run off the carried pointer set: LV %d, EE %d fetches", ft.counts[lvURL], ft.counts[eeURL])
	}
	if got := ft.pivotFetches(); got != 0 {
		t.Errorf("pivot fetches = %d, want 0 on a skipped LOTL", got)
	}
	if snap2.ID != snap1.ID {
		t.Errorf("unchanged inputs produced a different snapshot id")
	}
	if snap2.LOTLSequence != snap1.LOTLSequence || snap2.LOTLPivotSeq != snap1.LOTLPivotSeq ||
		snap2.AdvertisedOJ != snap1.AdvertisedOJ || snap2.LOTLDigest != snap1.LOTLDigest ||
		!snap2.LOTLIssueTime.Equal(snap1.LOTLIssueTime) {
		t.Errorf("LOTL metadata not carried intact: seq %d/%d, pivot %d/%d, oj %q/%q", snap1.LOTLSequence, snap2.LOTLSequence, snap1.LOTLPivotSeq, snap2.LOTLPivotSeq, snap1.AdvertisedOJ, snap2.AdvertisedOJ)
	}
	if !sameDER(snap1.LOTLSignersDER, snap2.LOTLSignersDER) {
		t.Errorf("LOTL signer set not carried intact")
	}
	if len(snap2.LOTLPointers) != len(snap1.LOTLPointers) {
		t.Errorf("pointer set not carried intact: %d vs %d", len(snap1.LOTLPointers), len(snap2.LOTLPointers))
	}
	lv := snap2.Territory("LV")
	if lv == nil || lv.CarriedOver || lv.Failed || len(lv.Anchors) != 5 {
		t.Fatalf("LV not cleanly refreshed off the carried pointer: %+v", lv)
	}
	xx1, xx2 := snap1.Territory("XX"), snap2.Territory("XX")
	if xx1 == nil || xx2 == nil || !xx1.Failed || !xx2.Failed || xx1.FailureReason != xx2.FailureReason {
		t.Errorf("a territory without a pointer must fail identically on both paths: fresh %+v vs carried %+v", xx1, xx2)
	}
	if !snap2.Diff.Empty() {
		t.Errorf("unchanged cycle produced diff entries: %+v", snap2.Diff.Entries)
	}
}

func TestRefreshRefetchesLOTLOnDigestChange(t *testing.T) {
	ft := newFixtureTransport()
	serveMatchingLOTLDigest(t, ft)
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := cloneSnapshot(snap1)
	if err != nil {
		t.Fatal(err)
	}
	// The publisher now advertises a different digest: the full path runs.
	ft.body[digestURL(lotlURL)] = []byte("0000000000000000000000000000000000000000000000000000000000000000")
	ft.counts = map[string]int{}

	snap2, err := p.Refresh(context.Background(), prev, boot)
	if err != nil {
		t.Fatal(err)
	}
	if ft.counts[lotlURL] != 1 {
		t.Errorf("LOTL downloaded %d times after its .sha2 changed, want 1", ft.counts[lotlURL])
	}
	if snap2.ID != snap1.ID {
		t.Errorf("the same list bytes produced a different snapshot id")
	}
}

func TestRefreshLOTLWithoutPublishedDigestDownloads(t *testing.T) {
	ft := newFixtureTransport() // no ".sha2" body: the transport answers 404
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := cloneSnapshot(snap1)
	if err != nil {
		t.Fatal(err)
	}
	ft.counts = map[string]int{}

	if _, err := p.Refresh(context.Background(), prev, boot); err != nil {
		t.Fatal(err)
	}
	if ft.counts[digestURL(lotlURL)] != 1 {
		t.Errorf("the .sha2 was not even attempted (%d) although the held list qualified for the skip", ft.counts[digestURL(lotlURL)])
	}
	if ft.counts[lotlURL] != 1 {
		t.Errorf("a failed digest fetch must fall through to the full download, got %d", ft.counts[lotlURL])
	}
}

func TestRefreshLOTLNoStoredDigestDownloads(t *testing.T) {
	ft := newFixtureTransport()
	serveMatchingLOTLDigest(t, ft)
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	snap1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	// A snapshot persisted by a release before the digest existed carries
	// neither the digest nor the pointer set.
	prev, err := cloneSnapshot(snap1)
	if err != nil {
		t.Fatal(err)
	}
	prev.LOTLDigest = ""
	prev.LOTLPointers = nil
	ft.counts = map[string]int{}

	snap2, err := p.Refresh(context.Background(), prev, boot)
	if err != nil {
		t.Fatal(err)
	}
	if ft.counts[digestURL(lotlURL)] != 0 {
		t.Errorf("nothing to compare against, yet the .sha2 was fetched (%d)", ft.counts[digestURL(lotlURL)])
	}
	if ft.counts[lotlURL] != 1 {
		t.Errorf("LOTL downloaded %d times with no stored digest, want 1", ft.counts[lotlURL])
	}
	if snap2.LOTLDigest != snap1.LOTLDigest || len(snap2.LOTLPointers) == 0 {
		t.Errorf("the full cycle did not learn the inputs for the next skip: digest %q, %d pointers", snap2.LOTLDigest, len(snap2.LOTLPointers))
	}
}

func TestRefreshLOTLPastNextUpdateNeverSkips(t *testing.T) {
	pre, err := tsl.Parse(readTestdata(t, "eu-lotl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	nu := pre.SchemeInformation.NextUpdate.DateTime
	if nu == nil {
		t.Fatal("fixture LOTL has no NextUpdate")
	}
	ft := newFixtureTransport()
	serveMatchingLOTLDigest(t, ft) // the publisher still advertises the held list's digest
	p := testPipeline(t, ft, ModeAuto)
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")

	p.clock = func() time.Time { return nu.Add(-time.Hour) }
	snap1, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := cloneSnapshot(snap1)
	if err != nil {
		t.Fatal(err)
	}

	// The held list has expired. A matching digest must not keep it: the
	// full path runs and refuses the expired list by name.
	p.clock = func() time.Time { return nu.Add(time.Hour) }
	ft.counts = map[string]int{}
	_, err = p.Refresh(context.Background(), prev, boot)
	if err == nil || !strings.Contains(err.Error(), "LOTL_NEXTUPDATE_PASSED") {
		t.Fatalf("an expired held list with a matching .sha2 must be downloaded and refused, got %v", err)
	}
	if ft.counts[digestURL(lotlURL)] != 0 {
		t.Errorf("the .sha2 was consulted for an expired held list (%d) — the skip must not be considered at all", ft.counts[digestURL(lotlURL)])
	}
	if ft.counts[lotlURL] != 1 {
		t.Errorf("the full download did not happen (%d) — a digest match was allowed to freeze an expired list", ft.counts[lotlURL])
	}
}
