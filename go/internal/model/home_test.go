package model

import "testing"

func TestHomeReady(t *testing.T) {
	ok := Check{Name: "a", State: CheckOK, Gate: true}
	warnGate := Check{Name: "b", State: CheckWarn, Gate: true}
	failGate := Check{Name: "c", State: CheckFail, Gate: true}
	// A non-gate check that is failing must NOT hold readiness back.
	failLane := Check{Name: "lane", State: CheckWarn, Gate: false}

	cases := []struct {
		name   string
		checks []Check
		want   bool
	}{
		{"all gates ok, lane warn", []Check{ok, ok, failLane}, true},
		{"a gate warns", []Check{ok, warnGate}, false},
		{"a gate fails", []Check{ok, failGate}, false},
		{"no checks", nil, true},
		{"only a failing lane (no gates)", []Check{failLane}, true},
	}
	for _, c := range cases {
		if got := (Home{Checks: c.checks}).Ready(); got != c.want {
			t.Errorf("%s: Ready() = %v, want %v", c.name, got, c.want)
		}
	}
}
