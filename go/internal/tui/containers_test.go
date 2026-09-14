package tui

import "testing"

func TestParsePct(t *testing.T) {
	cases := map[string]float64{
		"12.34%":  12.34,
		" 0.00% ": 0,
		"100%":    100,
		"--":      0, // docker prints this before the first sample
		"":        0, // missing stats
		"7":       7, // tolerate a bare number
	}
	for in, want := range cases {
		if got := parsePct(in); got != want {
			t.Errorf("parsePct(%q) = %v, want %v", in, got, want)
		}
	}
}
