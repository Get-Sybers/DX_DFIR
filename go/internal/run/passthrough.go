package run

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/get-sybers/dx_dfir/go/internal/style"
)

// Passthrough runs the plan with the child's stdio wired straight to ours, so
// its output streams live and untouched. This is the faithful port of cli._run:
// it prints the grey "→ command" echo to stderr, then returns the child's exit
// code (propagating it), or 127 if the binary could not be launched.
//
// Because stdout is inherited, a verb whose payload is machine-readable (stix
// bundles, engine NDJSON) stays pipe-clean — the echo and diagnostics go to
// stderr only.
func Passthrough(ctx context.Context, p Plan, echo bool) int {
	if echo {
		fmt.Fprintln(os.Stderr, style.Grey(style.GlyphArrow+" "+p.Command()))
	}
	cmd := exec.CommandContext(ctx, p.Bin, p.Args...)
	cmd.Dir = p.Dir
	cmd.Env = p.environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if code := ee.ExitCode(); code >= 0 {
				return code
			}
			return 1 // killed by signal
		}
		fmt.Fprintln(os.Stderr, style.Red(fmt.Sprintf("failed to launch %s: %v", p.Bin, err)))
		return 127
	}
	return 0
}
