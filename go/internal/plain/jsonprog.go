package plain

import (
	"encoding/json"
	"os"

	"github.com/get-sybers/dx_dfir/go/internal/model"
)

// JSONProgress is a presenter that emits the update stream as one JSON
// model.ProgressEvent per line on stdout — so a parent dxdfir (the interactive
// shell) can drive its Pipeline-tab gauge + lane/step queue from the real job
// state, not by scraping plain text. Selected when DXDFIR_PROGRESS=json.
type JSONProgress struct{}

// NewJSONProgress returns the JSON-progress presenter.
func NewJSONProgress() JSONProgress { return JSONProgress{} }

// Run streams model.ProgressEvent lines and returns the job error (so the exit
// code contract is unchanged for the child process).
func (JSONProgress) Run(updates <-chan model.Update, onAbort func()) error {
	_ = onAbort
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	var lastErr error
	for u := range updates {
		switch {
		case u.Log != nil:
			_ = enc.Encode(model.ProgressEvent{Log: u.Log.Text})
		case u.Snapshot != nil:
			_ = enc.Encode(model.ProgressEvent{Snapshot: u.Snapshot})
		}
		if u.Done {
			lastErr = u.Err
			break
		}
	}
	msg := ""
	if lastErr != nil {
		msg = lastErr.Error()
	}
	_ = enc.Encode(model.ProgressEvent{Done: true, Err: msg})
	return lastErr
}
