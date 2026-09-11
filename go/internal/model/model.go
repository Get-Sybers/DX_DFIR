// Package model holds the presenter-agnostic types shared between the
// subprocess/watch producers and the two presenters (tui and plain). It imports
// neither termui nor os/exec, so both presenters and the runner can depend on it
// without an import cycle and unit tests need no terminal.
package model

import (
	"errors"
	"time"
)

// ErrAborted is returned by a Presenter when the operator quit the display
// (q / Ctrl-C) before the job finished. The orchestrator maps it to a clean,
// non-panicking exit after the underlying process has been cancelled.
var ErrAborted = errors.New("aborted by operator")

// State is the lifecycle of one lane / operation, mirroring the count buckets
// the Python processors already emit (processed / skipped / failed).
type State string

const (
	Queued  State = "queued"
	Running State = "running"
	Done    State = "done"
	Skipped State = "skipped"
	Failed  State = "failed"
)

// Kind decides how a lane's progress is drawn — the taxonomy the investigation
// established from the tools' output shapes.
type Kind int

const (
	// KindGauge: a clear i/N is reconstructable from per-item output files
	// landing on disk (zeek, evtx, suricata, zimmerman, volatility).
	KindGauge Kind = iota
	// KindHeartbeat: coarse, no per-item sub-signal; show elapsed + the growing
	// on-disk artefact size as the "still alive" proof (plaso — status_view none).
	KindHeartbeat
	// KindSpinner: a single final write, denominator unknowable; never fake a
	// gauge, show a spinner + elapsed (hayabusa, yara).
	KindSpinner
	// KindBytes: a determinate byte-driven gauge (collection hashing).
	KindBytes
)

// Step is a named sub-step within a lane (e.g. the ~9 EZ-Tools per zimmerman host).
type Step struct {
	Name  string
	State State
}

// Lane is a snapshot of one lane / operation at a point in time. The producer
// rebuilds these each tick; the presenter renders the latest.
type Lane struct {
	ID    string
	Title string
	Kind  Kind
	State State

	Done  int // completed units (KindGauge)
	Total int // total units; 0 => unknown (KindSpinner)

	Cur    int64 // bytes done (KindBytes) or on-disk artefact size (KindHeartbeat)
	CurMax int64 // total bytes (KindBytes); 0 => unknown

	Detail string  // current item / status line, already trimmed for width
	Rate   float64 // units-or-bytes per second, 0 => not computed

	Steps []Step // optional nested checklist (zimmerman)

	Started time.Time
	Ended   time.Time

	// Fails and Notes are the SHORT exception lists surfaced on completion —
	// never the full success list (that is debug-log material).
	Fails []string
	Notes []string
}

// Percent returns the gauge fill 0..100 for gauge/byte lanes, or -1 when a
// percentage would be a lie (spinner / heartbeat / unknown total).
func (l Lane) Percent() int {
	switch l.Kind {
	case KindGauge:
		if l.Total <= 0 {
			return -1
		}
		return clamp(l.Done * 100 / l.Total)
	case KindBytes:
		if l.CurMax <= 0 {
			return -1
		}
		return clamp(int(l.Cur * 100 / l.CurMax))
	default:
		return -1
	}
}

// Overall is the top-line job progress. A single flat percentage is misleading
// across lanes of incomparable weight, so LanesDone/LanesTotal is the primary
// signal and Pct is optional (-1 when not meaningful).
type Overall struct {
	LanesDone  int
	LanesTotal int
	Detail     string
	Pct        int // -1 if not applicable
}

// Snapshot is the whole dashboard state at one tick.
type Snapshot struct {
	Title   string
	Overall Overall
	Lanes   []Lane
	// Active is the ID of the long-pole lane whose filtered log-tail should be
	// shown (volatility / plaso while running); "" hides the tail pane.
	Active string
	// Tail is the active lane's filtered, bounded log-tail (already sanitized and
	// deduplicated). It is the single source of truth for the log pane; the plain
	// presenter prints only the newly-appended lines.
	Tail []string
	// Summary, when set on the final snapshot, is the durable end-of-run report
	// (already formatted lines). It overrides the lane-derived summary — used by
	// the collection flow, whose summary is moved/skipped/sha1 rather than lanes.
	Summary []string
}

// LogLine is one line of subprocess/tool output, already ANSI-stripped and
// bracket-escaped by the producer before it reaches a presenter.
type LogLine struct {
	Stream string // "out" | "err"
	LaneID string // owning lane, "" for job-level
	Text   string
}

// Update is one message on the presenter channel. Exactly one of Snapshot / Log
// is usually set; the final message has Done=true and may carry Err.
type Update struct {
	Snapshot *Snapshot
	Log      *LogLine
	Done     bool
	Err      error
}

// Presenter renders a stream of Updates. Implemented by internal/tui (termui)
// and internal/plain (line streaming). onAbort is invoked when the operator
// requests an early quit so the orchestrator can cancel the underlying job; the
// presenter keeps draining until it sees Done, then returns (ErrAborted if the
// quit was operator-initiated, else the job's Err).
type Presenter interface {
	Run(updates <-chan Update, onAbort func()) error
}

func clamp(p int) int {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}
