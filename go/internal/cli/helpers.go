package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/get-sybers/dx_dfir/go/internal/model"
	"github.com/get-sybers/dx_dfir/go/internal/plain"
	"github.com/get-sybers/dx_dfir/go/internal/style"
	"github.com/get-sybers/dx_dfir/go/internal/termdetect"
	"github.com/get-sybers/dx_dfir/go/internal/tui"
)

func redf(format string, a ...any) string { return style.Red(fmt.Sprintf(format, a...)) }

// present runs a progress stream under the right presenter: the termui
// dashboard when the terminal can host it (and not opted out), else plain line
// streaming. If the dashboard cannot initialise (ErrNoTTY, e.g. window too
// small), it falls back to plain before any update is consumed.
func present(env *Env, tuiP model.Presenter, updates <-chan model.Update, onAbort func()) error {
	// The interactive shell runs jobs as children with DXDFIR_PROGRESS=json so it
	// can drive its Pipeline widgets from the real update stream (one JSON
	// ProgressEvent per line) rather than scraping plain text.
	if os.Getenv("DXDFIR_PROGRESS") == "json" {
		return plain.NewJSONProgress().Run(updates, onAbort)
	}
	if !env.ForcePlain && termdetect.UseTUI(env.ForceTUI) {
		err := tuiP.Run(updates, onAbort)
		if !errors.Is(err, tui.ErrNoTTY) {
			return err
		}
		// dashboard declined before consuming updates; stream plain instead
	}
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
