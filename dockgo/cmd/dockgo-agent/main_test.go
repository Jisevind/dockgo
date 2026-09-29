package main

import (
	"reflect"
	"testing"
)

// TestSplitCommaList pins the ALLOWED_COMPOSE_PATHS parsing contract: a blank
// value means no restriction (nil), and blank or whitespace-only entries are
// dropped rather than kept as empty paths.
func TestSplitCommaList(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty yields nil", raw: "", want: nil},
		{name: "whitespace only yields nil", raw: "   ", want: nil},
		{name: "two values", raw: "a,b", want: []string{"a", "b"}},
		{name: "trims blanks and surrounding space", raw: " a , , b ", want: []string{"a", "b"}},
		{name: "single value", raw: "a", want: []string{"a"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := splitCommaList(tc.raw)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("splitCommaList(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}
