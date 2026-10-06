// Package plain is the sole presenter: it consumes the model.Update stream and
// renders it on STDERR, so a machine-readable stdout stays clean.
//
// On an interactive terminal it draws a small status block that updates IN
// PLACE (a spinner, each lane's state and percentage, and the file the running
// lane is on) — ordinary plain-CLI progress like `docker pull`, redrawn with
// carriage-return / clear-line on the normal screen. It is NOT a TUI: there is
// no alternate screen, no key handling, no cursor parking. The moment stderr is
// not a terminal (a pipe, CI, a log file) it falls back to periodic one-line
// status output that never redraws.
package plain

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Get-Sybers/DX_DFIR/go/internal/model"
	"github.com/Get-Sybers/DX_DFIR/go/internal/style"
)

// spinFrames is the ASCII "loading wheel" (ASCII-safe, width 1 everywhere,
// matching the style package's no-wide-rune rule).
var spinFrames = []rune{'|', '/', '-', '\\'}

// Presenter streams progress on stderr: a live in-place status block on a
// terminal, periodic status lines otherwise.
type Presenter struct {
	w        io.Writer
	interval time.Duration // minimum gap between periodic lines (non-TTY path)
	live     bool          // redraw in place (stderr is an interactive terminal)
	cols     int           // terminal width for truncation; keeps rows from wrapping
}

// New returns a plain presenter writing to stderr.
func New() *Presenter {
	return &Presenter{
		w:        os.Stderr,
		interval: 3 * time.Second,
		live:     style.Enabled, // TTY + colour allowed, and not NO_COLOR/dumb
		cols:     termCols(os.Stderr),
	}
}

// Run implements model.Presenter. onAbort is unused (plain mode has no key
// handling; Ctrl-C reaches the child via the process group / signal handler).
func (p *Presenter) Run(updates <-chan model.Update, onAbort func()) error {
	_ = onAbort
	if p.live {
		return p.runLive(updates)
	}
	return p.runLines(updates)
}

// runLive draws the status block in place, animating the spinner on its own
// ~8fps clock so a long, quiet lane still looks alive between producer ticks.
func (p *Presenter) runLive(updates <-chan model.Update) error {
	var last model.Snapshot
	var started time.Time
	have := false
	prev := 0 // rows currently occupied by the live block
	spin := 0

	ticker := time.NewTicker(125 * time.Millisecond)
	defer ticker.Stop()

	io.WriteString(p.w, "\x1b[?25l")       // hide cursor
	defer io.WriteString(p.w, "\x1b[?25h") // show cursor

	finish := func(err error) error {
		p.clearBlock(prev)
		prev = 0
		PrintSummary(p.w, last)
		return err
	}
	draw := func() {
		if have {
			prev = p.paint(p.renderBlock(last, spinFrames[spin%len(spinFrames)], elapsed(started)), prev)
		}
	}

	for {
		select {
		case u, ok := <-updates:
			if !ok {
				return finish(nil)
			}
			if u.Log != nil {
				// Push any log line out above the live block, then let the
				// next redraw repaint the block beneath it.
				p.clearBlock(prev)
				prev = 0
				p.printLog(u.Log)
			}
			if u.Snapshot != nil {
				last = *u.Snapshot
				if !have {
					started = time.Now()
				}
				have = true
			}
			if u.Done {
				return finish(u.Err)
			}
			draw()
		case <-ticker.C:
			spin++
			draw()
		}
	}
}

// runLines is the non-terminal path: a status line on a lane-completion change
// or at most once per interval, so a piped run or a CI log stays readable and
// bounded instead of flooding.
func (p *Presenter) runLines(updates <-chan model.Update) error {
	var last model.Snapshot
	var lastPrint time.Time
	lastLanesDone := -1

	for u := range updates {
		switch {
		case u.Log != nil:
			p.printLog(u.Log)
		case u.Snapshot != nil:
			last = *u.Snapshot
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

// paint redraws the block in place: move up over the previous block, rewrite
// each row (clearing it first), then wipe any rows the block shrank past.
// Returns the new row count. Every row is truncated to the terminal width so a
// row never wraps and desyncs the cursor arithmetic.
func (p *Presenter) paint(rows []string, prev int) int {
	var b strings.Builder
	if prev > 0 {
		fmt.Fprintf(&b, "\x1b[%dA", prev) // cursor up to the block's first row
	}
	for _, r := range rows {
		b.WriteString("\r\x1b[2K") // carriage return + clear the whole line
		b.WriteString(r)
		b.WriteByte('\n')
	}
	if extra := prev - len(rows); extra > 0 {
		for i := 0; i < extra; i++ {
			b.WriteString("\r\x1b[2K\n") // clear each orphaned row
		}
		fmt.Fprintf(&b, "\x1b[%dA", extra) // step back up so the next paint aligns
	}
	io.WriteString(p.w, b.String())
	return len(rows)
}

// clearBlock erases the live block so the next write (a log line or the final
// summary) lands on a clean screen with no leftover progress rows.
func (p *Presenter) clearBlock(prev int) {
	if prev <= 0 {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\x1b[%dA", prev)
	for i := 0; i < prev; i++ {
		b.WriteString("\r\x1b[2K\n")
	}
	fmt.Fprintf(&b, "\x1b[%dA", prev)
	io.WriteString(p.w, b.String())
}

// renderBlock builds the live status block in the shape Docker's pull/build
// output uses: a header carrying the overall count and the job's elapsed time,
// one aligned row per lane with its status on the left and that lane's elapsed
// right-aligned, and a short tail for a long-pole lane. Rows are
// plain-then-coloured so the visible width never counts the zero-width escapes.
func (p *Presenter) renderBlock(s model.Snapshot, spin rune, jobElapsed string) []string {
	head := "[dx]"
	if s.Title != "" {
		head += " " + s.Title
	}
	if s.Overall.LanesTotal > 0 {
		head += fmt.Sprintf(" (%d/%d)", s.Overall.LanesDone, s.Overall.LanesTotal)
	}
	rows := []string{p.row(style.Bold(head), style.Grey(jobElapsed))}

	pad := 0
	for _, l := range s.Lanes {
		if n := len(l.Title); n > pad {
			pad = n
		}
	}

	for _, l := range s.Lanes {
		left, right := laneCells(l, spin, pad)
		rows = append(rows, p.row(left, right))
	}

	// A long-pole lane (plaso / anamnesis) carries a filtered log tail; show it
	// indented beneath the lanes so the operator sees the tool is moving.
	for _, t := range s.Tail {
		rows = append(rows, p.trunc(style.Grey("    | "+t)))
	}
	return rows
}

// markW is the fixed width of the status-mark column. It holds the widest mark
// ("[ok]") so every lane's title and detail line up regardless of which mark
// (spinner, "[ok]", "=>", ...) precedes it — padding only the title left the
// columns ragged because the marks differ in width.
const markW = 4

// laneCells renders one lane as (left, right): the status on the left (a `=>`
// prefix for settled lanes, the spinning wheel while running) and that lane's
// elapsed time on the right, mirroring Docker's per-step timing column. The
// mark is padded to markW *before* colouring so the pad counts visible columns,
// not escape bytes.
func laneCells(l model.Lane, spin rune, pad int) (string, string) {
	title := fmt.Sprintf("%-*s", pad, l.Title)
	switch l.State {
	case model.Done:
		return style.Green(fmt.Sprintf(" %-*s %s  %s", markW, style.GlyphOK, title, doneDetail(l))),
			style.Grey(elapsed2(l.Started, l.Ended))
	case model.Failed:
		return style.Red(fmt.Sprintf(" %-*s %s  failed", markW, style.GlyphErr, title)),
			style.Grey(elapsed2(l.Started, l.Ended))
	case model.Skipped:
		return style.Grey(fmt.Sprintf(" %-*s %s  skipped", markW, style.GlyphInfo, title)), ""
	case model.Running:
		mark := fmt.Sprintf("%-*s", markW, string(spin))
		return fmt.Sprintf(" %s %s  %s", style.Cyan(mark), title, runningDetail(l)),
			style.Cyan(elapsed(l.Started))
	default: // queued
		return style.Grey(fmt.Sprintf(" %-*s %s  queued", markW, "=>", title)), ""
	}
}

// row lays a left segment and a right segment across the terminal width, the
// right segment flush to the right edge (one column of margin). When they would
// not fit it falls back to "left right" and lets trunc clip.
func (p *Presenter) row(left, right string) string {
	if right == "" {
		return p.trunc(left)
	}
	lw, rw := visibleWidth(left), visibleWidth(right)
	if p.cols > 0 && lw+rw+1 <= p.cols-1 {
		return left + strings.Repeat(" ", p.cols-1-lw-rw) + right
	}
	return p.trunc(left + " " + right)
}

// runningDetail is the live right-hand side of a running lane: a percentage and
// bar when a gauge/byte denominator exists, else elapsed time; plus the current
// item (the file the lane is on) when the producer has one.
func runningDetail(l model.Lane) string {
	var head string
	switch l.Kind {
	case model.KindGauge:
		if pct := l.Percent(); pct >= 0 {
			head = fmt.Sprintf("%3d%% %s (%d/%d)", pct, bar(pct), l.Done, l.Total)
		} else {
			head = fmt.Sprintf("(%d)", l.Done)
		}
	case model.KindBytes:
		if pct := l.Percent(); pct >= 0 {
			head = fmt.Sprintf("%3d%% %s (%s/%s)", pct, bar(pct), humanBytes(l.Cur), humanBytes(l.CurMax))
		} else {
			head = humanBytes(l.Cur) + " hashed"
		}
	case model.KindHeartbeat:
		head = fmt.Sprintf("working %s (%s)", elapsed(l.Started), humanBytes(l.Cur))
	default: // spinner
		head = "working " + elapsed(l.Started)
	}
	// A gauge/byte lane that reads 100% while still Running has all its outputs
	// on disk (often a re-run where nothing is redone) and is waiting on the
	// playbook to exit; say so rather than look stuck at 100% but uncounted.
	if (l.Kind == model.KindGauge || l.Kind == model.KindBytes) && l.Percent() >= 100 {
		return head + style.Grey("  finishing")
	}
	if l.Item != "" {
		head += "  " + l.Item
	}
	return head
}

// doneDetail is the compact right-hand side of a completed lane.
func doneDetail(l model.Lane) string {
	switch l.Kind {
	case model.KindGauge:
		return fmt.Sprintf("%d/%d", l.Done, tot(l))
	case model.KindBytes:
		return humanBytes(l.Cur) + " hashed"
	default:
		return "done " + elapsed2(l.Started, l.Ended)
	}
}

// bar is a fixed-width ASCII progress bar with a leading edge, matching the
// look of `docker pull`'s per-layer bar: "[===>      ]".
func bar(pct int) string {
	const width = 12
	filled := pct * width / 100
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	switch {
	case filled == 0:
		return "[" + strings.Repeat(" ", width) + "]"
	case filled >= width:
		return "[" + strings.Repeat("=", width) + "]"
	default:
		return "[" + strings.Repeat("=", filled-1) + ">" + strings.Repeat(" ", width-filled) + "]"
	}
}

// visibleWidth counts the printable runes in s, skipping ANSI escape sequences
// (which occupy no columns).
func visibleWidth(s string) int {
	width, inEsc := 0, false
	for _, r := range s {
		switch {
		case inEsc:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
		case r == '\x1b':
			inEsc = true
		default:
			width++
		}
	}
	return width
}

// trunc clips a rendered row to the terminal width. Escape sequences are
// zero-width, so it counts only printable runes and keeps any trailing reset.
func (p *Presenter) trunc(s string) string {
	if p.cols <= 0 {
		return s
	}
	var b strings.Builder
	width := 0
	inEsc := false
	for _, r := range s {
		switch {
		case inEsc:
			b.WriteRune(r)
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
		case r == '\x1b':
			inEsc = true
			b.WriteRune(r)
		default:
			if width >= p.cols-1 {
				continue // drop the visible rune, keep draining escapes/reset
			}
			b.WriteRune(r)
			width++
		}
	}
	return b.String()
}

func (p *Presenter) printLog(l *model.LogLine) {
	line := l.Text
	if l.LaneID != "" {
		line = style.Grey("["+l.LaneID+"] ") + line
	}
	fmt.Fprintln(p.w, line)
}

// printProgress is the one-line (non-TTY) status: overall lanes plus the lane
// that is currently running — the long-pole active lane if the producer named
// one, otherwise the first running lane, so a gauge lane's live percentage is
// never invisible in a log.
func (p *Presenter) printProgress(s model.Snapshot) {
	var b strings.Builder
	b.WriteString(style.Bold("[dx] "))
	if s.Overall.LanesTotal > 0 {
		fmt.Fprintf(&b, "lanes %d/%d", s.Overall.LanesDone, s.Overall.LanesTotal)
	}
	act := findLane(s, s.Active)
	if act == nil {
		act = firstRunning(s)
	}
	if act != nil {
		fmt.Fprintf(&b, " · %s", laneOneLine(*act))
	} else if s.Overall.Detail != "" {
		fmt.Fprintf(&b, " · %s", s.Overall.Detail)
	}
	fmt.Fprintln(p.w, b.String())
}

func laneOneLine(l model.Lane) string {
	item := ""
	if l.Item != "" {
		item = " " + l.Item
	}
	switch l.Kind {
	case model.KindGauge:
		if pct := l.Percent(); pct >= 0 {
			return fmt.Sprintf("%s %d%% (%d/%d)%s", l.Title, pct, l.Done, l.Total, item)
		}
		return fmt.Sprintf("%s (%d)%s", l.Title, l.Done, item)
	case model.KindBytes:
		if pct := l.Percent(); pct >= 0 {
			return fmt.Sprintf("%s %d%% (%s/%s)%s", l.Title, pct,
				humanBytes(l.Cur), humanBytes(l.CurMax), item)
		}
		return fmt.Sprintf("%s %s hashed%s", l.Title, humanBytes(l.Cur), item)
	case model.KindHeartbeat:
		return fmt.Sprintf("%s working %s (%s)%s", l.Title,
			elapsed(l.Started), humanBytes(l.Cur), item)
	default: // spinner
		return fmt.Sprintf("%s working %s%s", l.Title, elapsed(l.Started), item)
	}
}

func (p *Presenter) printSummary(s model.Snapshot) { PrintSummary(p.w, s) }

// PrintSummary writes the durable end-of-run summary — the record that survives
// in scrollback after the live block (if any) has been cleared.
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

func firstRunning(s model.Snapshot) *model.Lane {
	for i := range s.Lanes {
		if s.Lanes[i].State == model.Running {
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

func elapsed2(start, end time.Time) string {
	if start.IsZero() || end.IsZero() {
		return ""
	}
	return end.Sub(start).Round(time.Second).String()
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
