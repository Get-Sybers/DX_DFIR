// Package plain is the non-TTY presenter: it consumes the exact same
// model.Update stream the termui dashboard does, but renders it as line output
// on STDERR. This is what runs under a pipe, CI, DXDFIR_NO_TUI, or a dumb
// terminal — so the subprocess/watch layer is identical and only the presenter
// differs. STDERR is used throughout so a machine-readable stdout stays clean.
package plain

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/get-sybers/dx_dfir/go/internal/model"
	"github.com/get-sybers/dx_dfir/go/internal/style"
)

// Presenter streams progress as periodic status lines plus live log lines.
type Presenter struct {
	w        io.Writer
	interval time.Duration // minimum gap between periodic progress lines
}

// New returns a plain presenter writing to stderr.
func New() *Presenter {
	return &Presenter{w: os.Stderr, interval: 3 * time.Second}
}

// Run implements model.Presenter. onAbort is unused (plain mode has no key
// handling; Ctrl-C reaches the child via the process group / signal handler).
func (p *Presenter) Run(updates <-chan model.Update, onAbort func()) error {
	_ = onAbort
	var last model.Snapshot
	var lastPrint time.Time
	lastLanesDone := -1

	for u := range updates {
		switch {
		case u.Log != nil:
			p.printLog(u.Log)
		case u.Snapshot != nil:
			last = *u.Snapshot
			// Print a progress line on a lane-completion change, or at most once
			// per interval otherwise — enough to prove a long run is alive
			// without flooding a log file.
			if last.Overall.LanesDone != lastLanesDone || time.Since(lastPrint) >= p.interval {
				p.printProgress(last)
				lastPrint = time.Now()
				lastLanesDone = last.Overall.LanesDone
			}
		}
		if u.Done {
			p.printSummary(last)
			return u.Err
		}
	}
	p.printSummary(last)
	return nil
}

func (p *Presenter) printLog(l *model.LogLine) {
	line := l.Text
	if l.LaneID != "" {
		line = style.Grey("["+l.LaneID+"] ") + line
	}
	fmt.Fprintln(p.w, line)
}

func (p *Presenter) printProgress(s model.Snapshot) {
	var b strings.Builder
	b.WriteString(style.Bold("[dxdfir] "))
	if s.Overall.LanesTotal > 0 {
		fmt.Fprintf(&b, "lanes %d/%d", s.Overall.LanesDone, s.Overall.LanesTotal)
	}
	if act := findLane(s, s.Active); act != nil {
		fmt.Fprintf(&b, " · %s", laneOneLine(*act))
	} else if s.Overall.Detail != "" {
		fmt.Fprintf(&b, " · %s", s.Overall.Detail)
	}
	fmt.Fprintln(p.w, b.String())
}

func laneOneLine(l model.Lane) string {
	switch l.Kind {
	case model.KindGauge:
		if pct := l.Percent(); pct >= 0 {
			return fmt.Sprintf("%s %d%% (%d/%d) %s", l.Title, pct, l.Done, l.Total, l.Detail)
		}
		return fmt.Sprintf("%s (%d) %s", l.Title, l.Done, l.Detail)
	case model.KindBytes:
		if pct := l.Percent(); pct >= 0 {
			return fmt.Sprintf("%s %d%% (%s/%s) %s", l.Title, pct,
				humanBytes(l.Cur), humanBytes(l.CurMax), l.Detail)
		}
		return fmt.Sprintf("%s %s hashed %s", l.Title, humanBytes(l.Cur), l.Detail)
	case model.KindHeartbeat:
		return fmt.Sprintf("%s working %s (%s) %s", l.Title,
			elapsed(l.Started), humanBytes(l.Cur), l.Detail)
	default: // spinner
		return fmt.Sprintf("%s working %s %s", l.Title, elapsed(l.Started), l.Detail)
	}
}

func (p *Presenter) printSummary(s model.Snapshot) { PrintSummary(p.w, s) }

// PrintSummary writes the durable end-of-run summary. It is shared with the TUI
// presenter, which calls it AFTER ui.Close() (the alternate screen is gone, so
// the summary is the record that survives in scrollback).
func PrintSummary(w io.Writer, s model.Snapshot) {
	// A pre-formatted summary (collection flow) overrides the lane-derived one.
	if len(s.Summary) > 0 {
		for _, line := range s.Summary {
			fmt.Fprintln(w, line)
		}
		return
	}
	if len(s.Lanes) == 0 {
		return
	}
	fmt.Fprintln(w, style.Bold("-- summary --"))
	for _, l := range s.Lanes {
		mark, colour := stateMark(l.State)
		head := fmt.Sprintf("  %s %-12s", mark, l.Title)
		switch l.Kind {
		case model.KindGauge:
			head += fmt.Sprintf(" %d/%d done", l.Done, tot(l))
		case model.KindBytes:
			head += fmt.Sprintf(" %s hashed", humanBytes(l.Cur))
		}
		fmt.Fprintln(w, colour(head))
		for _, f := range l.Fails {
			fmt.Fprintln(w, style.Red("      "+style.GlyphErr+" "+f))
		}
		for _, n := range l.Notes {
			fmt.Fprintln(w, style.Yellow("      "+style.GlyphWarn+" "+n))
		}
	}
}

func stateMark(s model.State) (string, func(string) string) {
	switch s {
	case model.Done:
		return style.GlyphOK, style.Green
	case model.Failed:
		return style.GlyphErr, style.Red
	case model.Skipped:
		return style.GlyphInfo, style.Grey
	case model.Running:
		return "..", style.Cyan
	default:
		return "  ", func(s string) string { return s }
	}
}

func findLane(s model.Snapshot, id string) *model.Lane {
	if id == "" {
		return nil
	}
	for i := range s.Lanes {
		if s.Lanes[i].ID == id {
			return &s.Lanes[i]
		}
	}
	return nil
}

func tot(l model.Lane) int {
	if l.Total > 0 {
		return l.Total
	}
	return l.Done
}

func elapsed(start time.Time) string {
	if start.IsZero() {
		return "0s"
	}
	d := time.Since(start).Round(time.Second)
	return d.String()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}
