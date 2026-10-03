package run

import (
	"bytes"
	"context"
	"os/exec"
)

// Capture runs the plan to completion, returning its stdout and stderr as
// strings plus the exit error. Used for quick machine-readable probes (e.g. a
// tool's `--version` on the readiness dashboard) where the caller parses the
// output rather than streaming it.
func Capture(ctx context.Context, p Plan) (stdout, stderr string, err error) {
	cmd := exec.CommandContext(ctx, p.Bin, p.Args...)
	cmd.Dir = p.Dir
	cmd.Env = append(p.environ(), forcePlainEnv...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}
