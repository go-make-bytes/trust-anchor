package trust

// DeclaredSourceState describes the last load attempt of the
// operator-declared anchor source (the internal trust source). It exists to
// keep three outcomes that look identical from outside distinguishable:
// source not configured at all, file loaded but declaring zero anchors, and
// file rejected with the previous set carried over. The third is the trap —
// whole-file fail-closed means one typo boots serving the old set, which
// reads as a successful edit unless the inventory says otherwise.
type DeclaredSourceState struct {
	// Configured reports whether the source path is set at all.
	Configured bool
	// CarriedOver reports a failed load: the previous set stayed in effect.
	CarriedOver bool
	// Error is the load error when CarriedOver (error text only — never file
	// contents or key material).
	Error string
	// Count is the number of anchors now in effect for this source.
	Count int
}

// State names the source's condition for logs: not_configured, ok or
// carried_over.
func (s DeclaredSourceState) State() string {
	switch {
	case !s.Configured:
		return "not_configured"
	case s.CarriedOver:
		return "carried_over"
	default:
		return "ok"
	}
}

// DeclaredReport is the outcome of one declared-source load.
type DeclaredReport struct {
	Internal DeclaredSourceState
}
