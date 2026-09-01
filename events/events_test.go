package events

import (
	"testing"

	"github.com/go-quicktest/qt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// observed returns an Emitter whose security lines can be read back. The security
// event IS a log line, so the log is where the assertion belongs.
func observed() (*Emitter, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)

	return New(zap.New(core)), logs
}

func line(t *testing.T, logs *observer.ObservedLogs) observer.LoggedEntry {
	t.Helper()

	entries := logs.FilterMessage("security_event").All()
	qt.Assert(t, qt.Equals(len(entries), 1))

	return entries[0]
}

func attr(e observer.LoggedEntry, key string) any {
	for _, f := range e.Context {
		if f.Key == "attributes" {
			if m, ok := f.Interface.(map[string]any); ok {
				return m[key]
			}
		}
	}

	return nil
}

// A trust anchor appearing is noteworthy and worth a human looking at, but it is
// the successful, expected outcome of a refresh — not a failure. It must not reach
// the SIEM as an error, or every trusted-list update paints the stream red and the
// events that ARE failures stop standing out.
//
// This is asserted on both channels on purpose. They used to disagree: the line was
// capped at warn while the severity field on it still said high, so a rule reading
// severity saw something the operator looking at levels never did.
func TestAnchorAdditionIsAWarningOnBothChannels(t *testing.T) {
	e, logs := observed()

	e.AnchorChange(nil, "added", "LV", "fp-1", "tsp", "svc", "granted", "", false)

	entry := line(t, logs)
	qt.Assert(t, qt.Equals(entry.Level, zapcore.WarnLevel))
	qt.Assert(t, qt.Equals(attr(entry, "severity"), any("warning")))
}

// A removal is the same act in the other direction, and carries the same weight.
func TestAnchorRemovalIsAWarning(t *testing.T) {
	e, logs := observed()

	e.AnchorChange(nil, "removed", "LV", "fp-1", "tsp", "svc", "withdrawn", "", false)

	entry := line(t, logs)
	qt.Assert(t, qt.Equals(entry.Level, zapcore.WarnLevel))
	qt.Assert(t, qt.Equals(attr(entry, "severity"), any("warning")))
}

// A metadata edit is not a change of who is trusted, so it stays informational —
// the distinction the severity is carrying.
func TestAnchorMetadataChangeStaysInfo(t *testing.T) {
	e, logs := observed()

	e.AnchorChange(nil, "changed", "LV", "fp-1", "tsp", "svc", "granted", "name", false)

	entry := line(t, logs)
	qt.Assert(t, qt.Equals(entry.Level, zapcore.InfoLevel))
	qt.Assert(t, qt.Equals(attr(entry, "severity"), any("info")))
}

// A blocked egress IS a failure, and must still arrive as an error — the point of
// lowering anchor changes is that real alarms stay distinguishable.
func TestBlockedEgressIsStillAnError(t *testing.T) {
	e, logs := observed()

	e.EgressBlocked(nil, "http://elsewhere.example", "not on the allow-list")

	qt.Assert(t, qt.Equals(line(t, logs).Level, zapcore.ErrorLevel))
}

// The refresh Tasker has no request, and its events still reach the log — the
// background path is what this service emits almost everything through.
func TestBackgroundEventsReachTheLog(t *testing.T) {
	e, logs := observed()

	e.RefreshFailure(nil, "fetch", "upstream timeout")

	entry := line(t, logs)
	qt.Assert(t, qt.Equals(entry.Level, zapcore.WarnLevel))
	qt.Assert(t, qt.Equals(attr(entry, "stage"), any("fetch")))
}
