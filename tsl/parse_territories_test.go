package tsl

import (
	"reflect"
	"testing"
)

// TestLOTLTerritories pins the territory set the recorded LOTL publishes XML
// pointers for: the member states (Greece under its publisher code EL) plus
// the EEA countries and UK — and, notably, no UA or MD, which is why non-LOTL
// territories need a declared source. The LOTL's own self-pointer (EU) is
// excluded.
func TestLOTLTerritories(t *testing.T) {
	tl, err := Parse(readFixture(t, "eu-lotl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	got := tl.Territories()
	want := []string{
		"AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "ES", "FI", "FR",
		"HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV", "MT", "NL", "NO",
		"PL", "PT", "RO", "SE", "SI", "SK", "UK",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LOTL territories = %v, want %v", got, want)
	}
	for _, absent := range []string{"EU", "GR", "UA", "MD"} {
		for _, code := range got {
			if code == absent {
				t.Fatalf("%s must not be in the pointer territory set", absent)
			}
		}
	}
}
