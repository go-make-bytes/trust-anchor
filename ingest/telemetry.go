package ingest

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VictoriaMetrics/metrics"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// Freshness and volume gauges, registered on the process-wide
// VictoriaMetrics registry (the one the HTTP server serves at /metrics), so
// they are scrapeable with a plain curl during an incident. Label values are
// low-cardinality by construction — source tags, territory codes and the
// closed anchor-type taxonomy. The snapshot id is deliberately NOT a label:
// every distinct label set creates a new time series, and a content hash
// would churn one per snapshot. Identity lives on the API (/v1/snapshot),
// not in metrics.
const (
	metricSnapshotAge    = "trust_snapshot_age_seconds"
	metricLastSuccess    = "trust_sync_last_success_timestamp_seconds"
	metricAnchorsTotal   = "trust_anchors_total"
	metricDeclaredFailed = "trust_declared_source_failed"
)

// Declared-source keys used as the `source` label value and in load reports.
const (
	declaredSourceOverlay  = "overlay"
	declaredSourceInternal = "internal"
)

// activeSnapshotFn feeds the age gauge. It is process-global (the metrics
// registry is), swapped by each NewManager so the gauge always reads the
// live manager.
var activeSnapshotFn atomic.Value // func() *trust.Snapshot

// registerAgeGauge registers the age callback gauge exactly once. The value
// is computed at scrape time; -1 means no active snapshot (nothing served
// yet), which alerting catches together with a zero last-success timestamp.
var registerAgeGauge = sync.OnceFunc(func() {
	metrics.GetOrCreateGauge(metricSnapshotAge, func() float64 {
		fn, _ := activeSnapshotFn.Load().(func() *trust.Snapshot)
		if fn == nil {
			return -1
		}
		s := fn()
		if s == nil {
			return -1
		}
		return time.Since(s.GeneratedAt).Seconds()
	})
})

// setLastSyncSuccess stamps the successful-cycle timestamp gauge.
func setLastSyncSuccess(now time.Time) {
	metrics.GetOrCreateGauge(metricLastSuccess, nil).Set(float64(now.Unix()))
}

// setDeclaredSourceFailed raises/clears the per-source 0/1 failure gauge: 1
// means the last load of that operator-declared source failed and the
// previous set is being served (carry-over). Alerting-layer only — a
// carried-over set is stale but healthy, and must not flip readiness.
func setDeclaredSourceFailed(source string, failed bool) {
	v := 0.0
	if failed {
		v = 1
	}
	metrics.GetOrCreateGauge(fmt.Sprintf(`%s{source=%q}`, metricDeclaredFailed, source), nil).Set(v)
}

var (
	anchorGaugeMu   sync.Mutex
	anchorGaugeSeen = map[string]*metrics.Gauge{}
)

// setAnchorGauges recomputes the volume gauges from the snapshot now being
// served. Series that existed for the previous snapshot but not this one are
// set to 0 rather than left dangling at their old value — a vanished
// territory or type must read as zero anchors, not as its last count.
func setAnchorGauges(s *trust.Snapshot) {
	counts := map[string]int{}
	series := func(source, territory, typ string) string {
		return fmt.Sprintf(`%s{source=%q,territory=%q,type=%q}`, metricAnchorsTotal, source, territory, typ)
	}
	if s != nil {
		for _, t := range s.Territories {
			for _, a := range t.Anchors {
				counts[series(a.Source, t.Code, a.Type)]++
			}
		}
		for _, a := range s.Overlay {
			counts[series(a.Source, a.Territory, a.Type)]++
		}
		for _, a := range s.Internal {
			counts[series(a.Source, a.Territory, a.Type)]++
		}
	}

	anchorGaugeMu.Lock()
	defer anchorGaugeMu.Unlock()
	for name, g := range anchorGaugeSeen {
		if _, live := counts[name]; !live {
			g.Set(0)
		}
	}
	for name, v := range counts {
		g := anchorGaugeSeen[name]
		if g == nil {
			g = metrics.GetOrCreateGauge(name, nil)
			anchorGaugeSeen[name] = g
		}
		g.Set(float64(v))
	}
}
