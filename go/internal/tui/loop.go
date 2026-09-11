package tui

import (
	"os"
	"time"

	ui "github.com/gizak/termui/v3"

	"github.com/get-sybers/dx_dfir/go/internal/model"
	"github.com/get-sybers/dx_dfir/go/internal/plain"
)

// view is what the event loop drives; each dashboard (process, collection)
// implements it. All widget mutation happens on the loop goroutine.
type view interface {
	apply(model.Update)       // fold an update into widget state
	layout(w, h int)          // (re)place widgets for a terminal size
	drawables() []ui.Drawable // widgets to render this frame, in z-order
	final() model.Snapshot    // the last snapshot, for the post-close summary
}

// run owns the terminal for the lifetime of a job: it initialises termbox,
// drives the ticker-coalesced render loop, and — crucially — tears the
// alternate screen down BEFORE printing the durable plain summary, so the record
// survives in scrollback. Returns ErrNoTTY if the terminal cannot host the
// dashboard (the caller then falls back to the plain presenter).
func run(v view, updates <-chan model.Update, onAbort func()) (retErr error) {
	if err := ui.Init(); err != nil {
		return ErrNoTTY
	}
	closed := false
	closeUI := func() {
		if !closed {
			ui.Close()
			closed = true
		}
	}
	defer func() {
		if r := recover(); r != nil {
			closeUI()
			panic(r)
		}
	}()
	defer closeUI()

	w, h := ui.TerminalDimensions()
	if w < minCols || h < minRows {
		closeUI()
		return ErrNoTTY // too small for the dashboard — stream plain instead
	}
	v.layout(w, h)
	ui.Render(v.drawables()...)

	events := ui.PollEvents()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	dirty := false
	aborted := false
	finished := false
	var jobErr error

	for !finished {
		select {
		case e := <-events:
			switch e.ID {
			case "q", "<C-c>", "<Escape>":
				if !aborted {
					aborted = true
					onAbort() // cancel the job; the run tears down on Done
				}
			case "<Resize>":
				if r, ok := e.Payload.(ui.Resize); ok {
					v.layout(r.Width, r.Height)
					ui.Clear()
					ui.Render(v.drawables()...)
				}
			case "<C-l>":
				ui.Clear()
				ui.Render(v.drawables()...)
			}
		case u, ok := <-updates:
			if !ok {
				finished = true
				break
			}
			v.apply(u)
			dirty = true
			if u.Done {
				jobErr = u.Err
				finished = true
			}
		case <-ticker.C:
			if dirty {
				ui.Render(v.drawables()...)
				dirty = false
			}
		}
	}

	ui.Render(v.drawables()...) // final frame
	closeUI()
	plain.PrintSummary(os.Stderr, v.final())
	if aborted {
		return model.ErrAborted
	}
	return jobErr
}

// ProcessPresenter renders the `process` dashboard.
type ProcessPresenter struct{}

// NewProcess returns the process dashboard presenter.
func NewProcess() *ProcessPresenter { return &ProcessPresenter{} }

// Run implements model.Presenter.
func (p *ProcessPresenter) Run(updates <-chan model.Update, onAbort func()) error {
	return run(newProcessView(), updates, onAbort)
}

// CollectionPresenter renders the collection-creation dashboard.
type CollectionPresenter struct{}

// NewCollection returns the collection dashboard presenter.
func NewCollection() *CollectionPresenter { return &CollectionPresenter{} }

// Run implements model.Presenter.
func (p *CollectionPresenter) Run(updates <-chan model.Update, onAbort func()) error {
	return run(newCollectionView(), updates, onAbort)
}
