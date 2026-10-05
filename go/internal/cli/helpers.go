package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/Get-Sybers/DX_DFIR/go/internal/model"
	"github.com/Get-Sybers/DX_DFIR/go/internal/plain"
	"github.com/Get-Sybers/DX_DFIR/go/internal/style"
)

func redf(format string, a ...any) string { return style.Red(fmt.Sprintf(format, a...)) }

// present runs a progress stream under the plain line presenter: periodic
// status lines plus live log output on stderr, so a machine-readable stdout
// stays clean. onAbort is invoked by the presenter when the operator quits so
// the orchestrator can cancel the underlying job.
func present(updates <-chan model.Update, onAbort func()) error {
	return plain.New().Run(updates, onAbort)
}

// exitFromErr maps a presenter/job error to the process exit code contract:
// operator abort → 130, any job failure → 1, success → 0.
func exitFromErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, model.ErrAborted) || errors.Is(err, context.Canceled) {
		return ExitError{Code: 130}
	}
	var ee ExitError
	if errors.As(err, &ee) {
		return ee
	}
	return ExitError{Code: 1}
}
