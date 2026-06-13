package store

import (
	"context"
	"testing"
	"time"

	"github.com/gmb-sig/trust-anchor/trust"
)

func roundTrip(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()

	// Empty store: nil, nil.
	snap, err := s.LoadLatestSnapshot(ctx)
	if err != nil || snap != nil {
		t.Fatalf("empty store: %v %v", snap, err)
	}
	boot, err := s.LoadLatestBootstrap(ctx)
	if err != nil || boot != nil {
		t.Fatalf("empty store: %v %v", boot, err)
	}

	in := &trust.Snapshot{
		GeneratedAt:  time.Now().UTC().Truncate(time.Second),
		LOTLSequence: 388,
		Territories: []*trust.Territory{{
			Code: "LV", TLSequence: 51,
			Anchors: []trust.Anchor{{Territory: "LV", FingerprintSHA256: "aa", CertDER: []byte{1, 2, 3}}},
		}},
	}
	in.ComputeID()
	if err := s.SaveSnapshot(ctx, in); err != nil {
		t.Fatal(err)
	}
	out, err := s.LoadLatestSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.ID != in.ID || out.LOTLSequence != 388 || len(out.Territories) != 1 {
		t.Fatalf("snapshot round-trip mismatch: %+v", out)
	}

	b := &trust.Bootstrap{Version: 1, OJReference: "C/2026/1944", CertsDER: [][]byte{{9}}, ActivatedAt: time.Now().UTC()}
	if err := s.SaveBootstrap(ctx, b); err != nil {
		t.Fatal(err)
	}
	b2, err := s.LoadLatestBootstrap(ctx)
	if err != nil || b2 == nil || b2.Version != 1 || b2.OJReference != "C/2026/1944" {
		t.Fatalf("bootstrap round-trip mismatch: %+v %v", b2, err)
	}

	// Newer version becomes latest.
	b3 := &trust.Bootstrap{Version: 2, OJReference: "C/2030/1000", CertsDER: [][]byte{{8}}, ActivatedAt: time.Now().UTC()}
	if err := s.SaveBootstrap(ctx, b3); err != nil {
		t.Fatal(err)
	}
	latest, err := s.LoadLatestBootstrap(ctx)
	if err != nil || latest.Version != 2 {
		t.Fatalf("latest bootstrap: %+v %v", latest, err)
	}
}

func TestMemoryStore(t *testing.T) { roundTrip(t, NewMemory()) }

func TestFSStore(t *testing.T) {
	s, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s)
}
