package run

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
)

// Line is a raw output line from the child, tagged by stream. Text is verbatim
// (not sanitized), so consumers can parse machine-readable JSON / sentinel lines
// exactly; display consumers call Sanitize themselves.
type Line struct {
	Stream string // "out" | "err"
	Text   string
}

// forcePlainEnv makes a child that is not attached to a tty still produce
// prompt, parseable, uncoloured output.
var forcePlainEnv = []string{
	"PYTHONUNBUFFERED=1",
	"ANSIBLE_FORCE_COLOR=0",
	"NO_COLOR=1",
	"TERM=dumb",
}

// Stream starts the plan and returns a channel of sanitized output lines and a
// single-value channel with the exit error (nil on success). The lines channel
// is closed when both pipes drain; the done channel delivers exactly once after
// that, so a consumer that reads lines to close then reads done sees the whole
// tail before the status (the cmd.Wait-after-wg.Wait ordering).
//
// Cancelling ctx kills the child (exec.CommandContext), which is how an operator
// quit in the dashboard tears down a running ansible-playbook.
func Stream(ctx context.Context, p Plan) (<-chan Line, <-chan error) {
	lines := make(chan Line, 256)
	done := make(chan error, 1)

	cmd := exec.CommandContext(ctx, p.Bin, p.Args...)
	cmd.Dir = p.Dir
	cmd.Env = append(p.environ(), forcePlainEnv...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		close(lines)
		done <- err
		return lines, done
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		close(lines)
		done <- err
		return lines, done
	}
	if err := cmd.Start(); err != nil {
		close(lines)
		done <- err
		return lines, done
	}

	var wg sync.WaitGroup
	scan := func(r io.Reader, name string) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024) // forensic/JSON lines overflow the 64KB default
		for sc.Scan() {
			select {
			case lines <- Line{Stream: name, Text: sc.Text()}:
			case <-ctx.Done():
				return
			}
		}
	}
	wg.Add(2)
	go scan(stdout, "out")
	go scan(stderr, "err")

	go func() {
		wg.Wait()
		close(lines)
		werr := cmd.Wait()
		// A ctx-cancelled kill surfaces as an ExitError/"signal: killed"; map it
		// to context.Canceled so the orchestrator recognises an operator abort.
		if ctx.Err() != nil {
			werr = ctx.Err()
		}
		done <- werr
		close(done)
	}()

	return lines, done
}

// ExitCode extracts a process exit code from a Stream/Passthrough error.
// context.Canceled → 130 (SIGINT convention); a clean nil → 0.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if c := ee.ExitCode(); c >= 0 {
			return c
		}
	}
	return 1
}
