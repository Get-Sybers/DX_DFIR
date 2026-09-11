package run

import (
	"bytes"
	"context"
	"os/exec"
)

// Capture runs the plan to completion, returning its stdout and stderr as
// strings plus the exit error. Used for quick machine-readable queries (e.g.
// `python -m get_sybers_dxdfir.collection status`) where the front-end parses
// the JSON on stdout rather than streaming.
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
