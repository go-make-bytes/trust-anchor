package ingest

import (
	"time"

	"go.uber.org/zap"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// inventoryAnchor is the per-anchor projection logged for declared trust.
// Subjects and fingerprints are non-sensitive provenance; the certificate
// itself never appears.
type inventoryAnchor struct {
	Name       string    `json:"name"`
	Type       string    `json:"type,omitempty"`
	Territory  string    `json:"territory,omitempty"`
	Status     string    `json:"status"`
	SHA256     string    `json:"sha256"`
	ValidUntil time.Time `json:"validUntil"`
}

// inventoryAnchors projects a declared anchor set for logging.
func inventoryAnchors(anchors []trust.Anchor) []inventoryAnchor {
	out := make([]inventoryAnchor, 0, len(anchors))
	for _, a := range anchors {
		name := a.TSPName
		if a.Source == trust.SourceOverlay {
			// Overlay anchors all carry the same constant TSP name; the
			// certificate subject CN is the identifying half.
			name = a.ServiceName
		}
		out = append(out, inventoryAnchor{
			Name:       name,
			Type:       a.Type,
			Territory:  a.Territory,
			Status:     a.Status,
			SHA256:     a.FingerprintSHA256,
			ValidUntil: a.NotAfter,
		})
	}
	return out
}

// logInventory writes the one structured trust-inventory event: declared
// trust is named (every operator-declared anchor in full — an anchor
// declared in one file on one disk has no other record), derived trust is
// counted (trusted-list anchors are in published, signed, re-fetchable
// lists — per-territory and per-type counts suffice, and stay bounded as
// the published trust infrastructure grows). Emitted at startup and on any
// change to the declared set.
func logInventory(log *zap.Logger, s *trust.Snapshot, rep trust.DeclaredReport) {
	if log == nil || s == nil {
		return
	}

	derivedByTerritory := map[string]int{}
	derivedByType := map[string]int{}
	for _, t := range s.Territories {
		derivedByTerritory[t.Code] = len(t.Anchors)
		for _, a := range t.Anchors {
			derivedByType[a.Type]++
		}
	}

	fields := []zap.Field{
		zap.String("snapshot", s.ID),
		zap.String("internal_state", rep.Internal.State()),
		zap.Int("internal_count", len(s.Internal)),
		zap.String("overlay_state", rep.Overlay.State()),
		zap.Int("overlay_count", len(s.Overlay)),
		zap.Any("derived_territory_counts", derivedByTerritory),
		zap.Any("derived_type_counts", derivedByType),
		zap.Int("pending_count", len(s.Pending)),
	}
	if rep.Internal.Error != "" {
		fields = append(fields, zap.String("internal_error", rep.Internal.Error))
	}
	if rep.Overlay.Error != "" {
		fields = append(fields, zap.String("overlay_error", rep.Overlay.Error))
	}
	if len(s.Internal) > 0 {
		fields = append(fields, zap.Any("internal_anchors", inventoryAnchors(s.Internal)))
	}
	if len(s.Overlay) > 0 {
		fields = append(fields, zap.Any("overlay_anchors", inventoryAnchors(s.Overlay)))
	}
	log.Info("trust inventory", fields...)
}
