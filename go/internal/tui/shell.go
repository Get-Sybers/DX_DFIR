package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"

	"github.com/get-sybers/dx_dfir/go/internal/model"
)

// Shell is the persistent dxdfir front-end (fix.md item 2): a tabbed dashboard
// with a live command box, so the operator keeps driving the SAME CLI verbs
// without leaving the UI. The CLI logic is unchanged — each typed line runs
// `dxdfir <args> --no-tui` as a child of this binary and its output streams into
// the log pane. Tabs (Pipeline | Containers) switch with Tab (digits are typed
// into the command box, so number keys are not tab shortcuts).
//
// This is the scaffold: the command box, the streaming log pane, and the tab
// frame. The Containers table and the richer Pipeline widgets (progress gauge +
// the lane/step queue that ticks) land on top of it next.
type Shell struct {
	self    string // path to this dxdfir binary, re-invoked with --no-tui per command
	version string
}

// NewShell returns the persistent shell, resolving the binary to re-invoke.
func NewShell(version string) *Shell {
	self, err := os.Executable()
	if err != nil || self == "" {
		self = "dxdfir" // fall back to PATH
	}
	return &Shell{self: self, version: version}
}

// tabs are the top-level views; the command box is shared across all of them.
var shellTabs = []string{"Pipeline", "Containers"}

const (
	tabPipeline   = 0
	tabContainers = 1
)

type shellView struct {
	self string

	tabpane    *widgets.TabPane
	log        *widgets.List  // streamed output of the last/running command
	gauge      *widgets.Gauge // Pipeline: overall progress of a running job
	queue      *widgets.Table // Pipeline: the lane/step queue, ticked as it runs
	containers *widgets.Table
	input      *widgets.Paragraph
	hint       *widgets.Paragraph

	draw       []ui.Drawable
	w          int
	bodyBottom int // y where the body ends (the input box starts)

	tab      int
	cmd      string   // current input buffer
	lines    []string // log lines
	contRows []containerRow
	snap     *model.Snapshot // latest job snapshot (Pipeline tab), nil until a run
	jsonMode bool            // the running command streams JSON progress (process)
	running  bool
	title    string
}

func newShellView(self string) *shellView {
	tp := widgets.NewTabPane(shellTabs...)
	tp.Border = true
	v := &shellView{
		self:       self,
		tabpane:    tp,
		log:        widgets.NewList(),
		gauge:      widgets.NewGauge(),
		queue:      widgets.NewTable(),
		containers: widgets.NewTable(),
		input:      widgets.NewParagraph(),
		hint:       widgets.NewParagraph(),
		title:      "dxdfir",
	}
	v.log.Title = "output"
	v.log.WrapText = false
	v.gauge.Title = "pipeline"
	v.queue.Title = "queue"
	v.queue.RowSeparator = false
	v.queue.FillRow = true
	v.containers.Title = "containers"
	v.containers.RowSeparator = false
	v.containers.FillRow = true
	v.input.Title = "command"
	v.hint.Border = false
	v.hint.TextStyle = styleFg(colGrey)
	v.hint.Text = "type a dxdfir command, Enter to run · Tab switches view · Ctrl-C quits"
	return v
}

func (v *shellView) layout(w, h int) {
	v.w = w
	v.bodyBottom = h - 3 // body ends where the command box starts
	v.tabpane.SetRect(0, 0, w, 3)
	v.input.SetRect(0, v.bodyBottom, w, h-1)
	v.hint.SetRect(0, h-1, w, h)
	v.refresh()
}

func (v *shellView) refresh() {
	v.tabpane.ActiveTabIndex = v.tab

	prompt := "> " + v.cmd
	if v.running {
		prompt = spinnerFrame() + " running: " + v.title
	} else {
		prompt += "_" // cursor
	}
	v.input.Text = prompt

	// The body depends on the active tab (and, on Pipeline, on whether a job has
	// run). refresh() owns placing the body widgets because the split changes.
	var body []ui.Drawable
	switch v.tab {
	case tabContainers:
		v.containers.SetRect(0, 3, v.w, v.bodyBottom)
		v.buildContainers()
		body = []ui.Drawable{v.containers}
	default: // Pipeline
		v.log.Title = "output"
		if v.snap != nil { // a process job has run: gauge + queue above the log
			const gaugeBottom = 6
			v.gauge.SetRect(0, 3, v.w, gaugeBottom)
			v.buildGauge()
			qRows := v.queueRows()
			qh := len(qRows) + 2 // + top/bottom border
			if maxQ := (v.bodyBottom - gaugeBottom) - 3; qh > maxQ {
				qh = maxQ // always leave >=3 rows for the log
			}
			if qh < 3 {
				qh = 3
			}
			v.queue.SetRect(0, gaugeBottom, v.w, gaugeBottom+qh)
			v.queue.Rows = qRows
			v.log.SetRect(0, gaugeBottom+qh, v.w, v.bodyBottom)
			body = []ui.Drawable{v.gauge, v.queue, v.log}
		} else {
			v.log.SetRect(0, 3, v.w, v.bodyBottom)
			body = []ui.Drawable{v.log}
		}
	}

	// Log rows, trimmed to the log's height (its rect is set above).
	if lh := v.log.Inner.Dy(); lh > 0 && len(v.lines) > lh {
		v.log.Rows = v.lines[len(v.lines)-lh:]
	} else {
		v.log.Rows = append([]string(nil), v.lines...)
	}

	v.draw = append([]ui.Drawable{v.tabpane}, body...)
	v.draw = append(v.draw, v.input, v.hint)
}

// buildGauge fills the Pipeline progress gauge from the latest snapshot.
func (v *shellView) buildGauge() {
	o := v.snap.Overall
	pct := o.Pct
	if pct < 0 { // gauge N/A for this job kind: fall back to lanes finished
		if o.LanesTotal > 0 {
			pct = 100 * o.LanesDone / o.LanesTotal
		} else {
			pct = 0
		}
	}
	if pct < 0 {
		pct = 0
	} else if pct > 100 {
		pct = 100
	}
	v.gauge.Percent = pct
	label := fmt.Sprintf("%d%%  %d/%d lanes", pct, o.LanesDone, o.LanesTotal)
	if o.Detail != "" {
		label += "  " + o.Detail
	}
	v.gauge.Label = sanitize(label)
}

// queueRows renders the lane/step queue that ticks as the job runs — one row per
// lane, its steps indented beneath, each prefixed by a state icon.
func (v *shellView) queueRows() [][]string {
	rows := [][]string{{"", "LANE / STEP", "PROGRESS", "DETAIL"}}
	for _, l := range v.snap.Lanes {
		items := ""
		if l.Total > 0 {
			items = fmt.Sprintf("%d/%d", l.Done, l.Total)
		}
		rows = append(rows, []string{stateIcon(l.State), sanitize(l.Title), items, sanitize(l.Detail)})
		for _, st := range l.Steps {
			rows = append(rows, []string{"  " + stateIcon(st.State), "  " + sanitize(st.Name), "", ""})
		}
	}
	return rows
}

// stateIcon maps a lane/step state to its queue glyph.
func stateIcon(s model.State) string {
	switch s {
	case model.Running:
		return "▸"
	case model.Done:
		return "✓"
	case model.Failed:
		return "✗"
	case model.Skipped:
		return "–"
	default: // Queued or unset
		return "·"
	}
}

// buildContainers fills the containers table from the latest poll.
func (v *shellView) buildContainers() {
	rows := [][]string{{"NAME", "IMAGE", "STATUS", "CPU", "MEM"}}
	for _, c := range v.contRows {
		rows = append(rows, []string{sanitize(c.name), sanitize(c.image), sanitize(c.status), c.cpu, c.mem})
	}
	if len(v.contRows) == 0 {
		v.containers.Title = "containers — none running"
	} else {
		v.containers.Title = "containers"
	}
	v.containers.Rows = rows
}

func (v *shellView) drawables() []ui.Drawable { return v.draw }

func (v *shellView) appendLine(s string) {
	v.lines = append(v.lines, sanitize(s))
	const cap = 5000 // bound the scrollback
	if len(v.lines) > cap {
		v.lines = v.lines[len(v.lines)-cap:]
	}
}

// Run owns the terminal for the shell's lifetime. Returns ErrNoTTY when the
// terminal cannot host the dashboard (the caller then prints plain help).
func (s *Shell) Run() (retErr error) {
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
		return ErrNoTTY
	}
	v := newShellView(s.self)
	v.lines = []string{
		"dxdfir " + s.version + " — interactive shell",
		"",
		"Run any dxdfir command here, e.g.:",
		"    list                          # staged evidence per lane",
		"    collection status             # tracked collections",
		"    process <collection> <lane>   # process a collection with a lane",
		"",
		"Tab switches the Pipeline / Containers view · `clear` clears · `quit` exits · Ctrl-C cancels a run.",
	}
	v.layout(w, h)
	ui.Render(v.drawables()...)

	events := ui.PollEvents()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	// Poll docker for the Containers tab in the background (bounded per call), so
	// the ktop-style table stays live during a run without blocking the UI.
	pollCtx, stopPoll := context.WithCancel(context.Background())
	defer stopPoll()
	contCh := make(chan []containerRow, 1)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			rows := pollContainers(pollCtx)
			select {
			case contCh <- rows:
			case <-pollCtx.Done():
				return
			}
			select {
			case <-t.C:
			case <-pollCtx.Done():
				return
			}
		}
	}()

	// Command output streams in on outLines; outDone signals completion.
	var outLines chan string
	var outDone chan struct{}
	var cancel context.CancelFunc
	dirty := false

	for {
		select {
		case e := <-events:
			switch e.ID {
			case "<C-c>":
				if v.running && cancel != nil {
					cancel() // cancel the running command, stay in the shell
					continue
				}
				return nil // idle: quit the shell
			case "<Tab>":
				v.tab = (v.tab + 1) % len(shellTabs)
				dirty = true
			case "<Resize>":
				if r, ok := e.Payload.(ui.Resize); ok {
					v.layout(r.Width, r.Height)
					ui.Clear()
					ui.Render(v.drawables()...)
				}
			case "<Enter>":
				if v.running {
					continue
				}
				line := strings.TrimSpace(v.cmd)
				v.cmd = ""
				if line == "" {
					dirty = true
					continue
				}
				if line == "quit" || line == "exit" {
					return nil
				}
				if line == "clear" {
					v.lines = nil
					dirty = true
					continue
				}
				// `process` streams JSON progress so the Pipeline widgets (gauge +
				// queue) track the real job state; everything else streams plain
				// lines into the log.
				fields := strings.Fields(line)
				v.jsonMode = len(fields) > 0 && fields[0] == "process"
				if v.jsonMode {
					v.snap = nil        // reset the queue/gauge for the new run
					v.tab = tabPipeline // surface the progress
				}
				outLines, outDone, cancel = s.start(line, v.jsonMode)
				v.running = true
				v.title = line
				dirty = true
			case "<Backspace>", "<C-8>":
				if !v.running && v.cmd != "" {
					r := []rune(v.cmd)
					v.cmd = string(r[:len(r)-1])
					dirty = true
				}
			case "<Space>":
				if !v.running {
					v.cmd += " "
					dirty = true
				}
			default:
				// A single printable rune (termui reports it as its literal id).
				if !v.running && len(e.ID) == 1 {
					v.cmd += e.ID
					dirty = true
				}
			}
		case ln, ok := <-outLines:
			if !ok {
				outLines = nil // channel drained
				continue
			}
			if v.jsonMode {
				var ev model.ProgressEvent
				if json.Unmarshal([]byte(ln), &ev) == nil {
					if ev.Snapshot != nil {
						v.snap = ev.Snapshot
					}
					if ev.Log != "" {
						v.appendLine(ev.Log)
					}
					if ev.Err != "" {
						v.appendLine("error: " + ev.Err)
					}
				} else {
					v.appendLine(ln) // not a JSON event (e.g. a stderr line): show raw
				}
			} else {
				v.appendLine(ln)
			}
			dirty = true
		case <-outDoneOr(outDone):
			v.running = false
			outDone = nil
			cancel = nil
			dirty = true
		case rows := <-contCh:
			v.contRows = rows
			if v.tab == tabContainers {
				dirty = true
			}
		case <-ticker.C:
			if dirty || v.running { // keep the spinner alive while running
				v.refresh()
				ui.Render(v.drawables()...)
				dirty = false
			}
		}
	}
}

// start runs `dxdfir <args> --no-tui` as a child, streaming combined output into
// the returned channel; outDone closes when the command exits. cancel stops it.
func (s *Shell) start(line string, jsonMode bool) (chan string, chan struct{}, context.CancelFunc) {
	lines := make(chan string, 256)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())

	args := append(splitArgs(line), "--no-tui")
	cmd := exec.CommandContext(ctx, s.self, args...)
	if jsonMode {
		// The child emits one model.ProgressEvent JSON line per update; the shell
		// decodes them to drive the Pipeline gauge + queue (see present()).
		cmd.Env = append(os.Environ(), "DXDFIR_PROGRESS=json")
	}
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	go func() {
		// bufio.Reader (not Scanner): no max-token limit, so a huge line never
		// stops the read, and pr is always closed on exit — so the writer below
		// (and the child's writes) can never block forever on a stalled reader.
		br := bufio.NewReader(pr)
		for {
			line, err := br.ReadString('\n')
			if len(line) > 0 {
				lines <- strings.TrimRight(line, "\r\n")
			}
			if err != nil {
				break // io.EOF when pw closes, or any read error
			}
		}
		pr.Close()   // release the writer if it is still blocked mid-write
		close(lines) // this goroutine owns closing `lines`; nothing else sends on it
	}()
	go func() {
		err := cmd.Run()
		// Route any launch/exit error through the pipe (the scanner reads it as a
		// final line) BEFORE closing pw — never send on `lines` here, the scanner
		// may already have closed it.
		if err != nil && ctx.Err() == nil {
			io.WriteString(pw, "[exit] "+err.Error()+"\n")
		}
		pw.Close()
		close(done)
	}()
	return lines, done, cancel
}

// outDoneOr returns a nil-safe channel: a nil done channel blocks forever, so
// the select arm is simply inert until a command is running.
func outDoneOr(done chan struct{}) <-chan struct{} {
	if done == nil {
		return nil
	}
	return done
}

// splitArgs is a minimal shell-word splitter: whitespace-separated, with "…"/'…'
// quoting for a single argument that contains spaces.
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inWord := false
	var quote rune
	flush := func() {
		if inWord {
			out = append(out, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			inWord = true
		case r == '"' || r == '\'':
			quote = r
			inWord = true
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	flush()
	return out
}
