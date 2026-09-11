// Package run is the UI-agnostic subprocess engine. It knows how to describe an
// invocation (Plan), run it as a transparent passthrough (for verbs whose value
// is their own streamed output or machine-readable payload), and stream its
// output line-by-line into a channel of model.Updates (for the dashboard verbs).
package run

import (
	"os"
	"strings"
)

// Plan describes one external invocation.
type Plan struct {
	Bin  string   // executable
	Args []string // arguments
	Dir  string   // working directory ("" = inherit)
	Env  []string // extra KEY=VALUE appended to the current environment
}

// Command renders the plan as a display string for the "→ command" echo.
func (p Plan) Command() string {
	return strings.TrimSpace(p.Bin + " " + strings.Join(p.Args, " "))
}

// environ merges the process environment with the plan's additions.
func (p Plan) environ() []string {
	if len(p.Env) == 0 {
		return os.Environ()
	}
	return append(os.Environ(), p.Env...)
}
