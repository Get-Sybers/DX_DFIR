package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"

	"github.com/get-sybers/dx_dfir/go/internal/model"
	"github.com/get-sybers/dx_dfir/go/internal/repo"
)

// Shell is the persistent dxdfir front-end (fix.md item 2): a tabbed dashboard
// with a live command box, so the operator keeps driving the SAME CLI verbs
// without leaving the UI. The CLI logic is unchanged — each typed line runs
// `dxdfir <args> --no-tui` as a child of this binary and its output streams into
// the log pane. Tab cycles the views (digits are typed into the command box, so
// number keys are not tab shortcuts):
//
//   - Pipeline:   the streaming log, plus a progress gauge + lane/step queue that
//     tick live while a `process` job runs (via the DXDFIR_PROGRESS=json stream).
//   - Containers: a ktop-style docker ps/stats table of the tool containers.
//   - Kibana:     run ES|QL queries against Elasticsearch and render the results
//     (the command box becomes the query input on this tab); stack status too.
//   - Timeline:   the byakugan behaviour timeline (data_store/processed/car).
type Shell struct {
	self     string // path to this dxdfir binary, re-invoked with --no-tui per command
	version  string
	repoRoot string // for the Kibana .env + the on-disk CAR timeline; "" if unlocated
}

// NewShell returns the persistent shell, resolving the binary to re-invoke and
// the repo root (best-effort — the tabs that need it degrade to a note when "").
func NewShell(version string) *Shell {
	self, err := os.Executable()
	if err != nil || self == "" {
		self = "dxdfir" // fall back to PATH
	}
	root := ""
	if r, err := repo.Detect(""); err == nil && r != nil {
		root = r.Root
	}
	return &Shell{self: self, version: version, repoRoot: root}
}

// tabs are the top-level views; the command box is shared across all of them.
var shellTabs = []string{"Pipeline", "Containers", "Kibana", "Timeline"}

const (
	tabPipeline   = 0
	tabContainers = 1
	tabKibana     = 2
	tabTimeline   = 3
)

type shellView struct {
	self     string
	repoRoot string

	tabpane    *widgets.TabPane
	log        *widgets.List      // streamed output of the last/running command
	gauge      *widgets.Gauge     // Pipeline: overall progress of a running job
	queue      *widgets.Table     // Pipeline: the lane/step queue, ticked as it runs
	containers *widgets.Table     // Containers: ktop-style docker table
	contCPU    *widgets.Gauge     // Containers: aggregate CPU gauge (ktop-style)
	contMEM    *widgets.Gauge     // Containers: aggregate memory gauge
	kibHdr     *widgets.Paragraph // Kibana: stack status header
	kibStreams *widgets.Table     // Kibana: logs-dxdfir.* data streams
	timeline   *widgets.Table     // Timeline: byakugan behaviour timeline
	input      *widgets.Paragraph
	hint       *widgets.Paragraph

	draw       []ui.Drawable
	w          int
	bodyBottom int // y where the body ends (the input box starts)

	tab      int
	cmd      string   // current input buffer
	lines    []string // log lines
	contRows []containerRow
	kib      kibanaStatus
	kibQuery string     // last ES|QL query typed on the Kibana tab
	kibRes   esqlResult // its result (columns + rows, or a note)
	querying bool       // an ES|QL query is in flight
	timeRows []timelineRow
	timeNote string
	snap     *model.Snapshot // latest job snapshot (Pipeline tab), nil until a run
	jsonMode bool            // the running command streams JSON progress (process)
	running  bool
	title    string
}

func newShellView(self, repoRoot string) *shellView {
	tp := widgets.NewTabPane(shellTabs...)
	tp.Border = true
	v := &shellView{
		self:       self,
		repoRoot:   repoRoot,
		tabpane:    tp,
		log:        widgets.NewList(),
		gauge:      widgets.NewGauge(),
		queue:      widgets.NewTable(),
		containers: widgets.NewTable(),
		contCPU:    widgets.NewGauge(),
		contMEM:    widgets.NewGauge(),
		kibHdr:     widgets.NewParagraph(),
		kibStreams: widgets.NewTable(),
		timeline:   widgets.NewTable(),
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
	v.contCPU.Title = "CPU"
	v.contMEM.Title = "memory"
	v.kibHdr.Title = "elastic stack"
	v.kibStreams.Title = "data streams"
	v.kibStreams.RowSeparator = false
	v.kibStreams.FillRow = true
	v.timeline.Title = "behaviour timeline"
	v.timeline.RowSeparator = false
	v.timeline.FillRow = true
	v.input.Title = "command"
	v.input.WrapText = false // one-line box; refresh() clips to keep the cursor visible
	v.hint.Border = false
	v.hint.TextStyle = styleFg(colGrey)
	v.hint.Text = "type a command, Enter to run · Tab/→ next · Shift-Tab/← prev · Ctrl-C quits"
	return v
}

func (v *shellView) layout(w, h int) {
	// Clamp to the minimum the widgets can occupy, so a terminal resized below it
	// yields a stable (if clipped) layout rather than negative/overlapping rects.
	if w < minCols {
		w = minCols
	}
	if h < minRows {
		h = minRows
	}
	v.w = w
	// The command box needs 3 rows (border, one text row, border) — at 2 rows the
	// borders ate the only line and nothing typed was visible. Body ends above it.
	inputTop := h - 4
	v.bodyBottom = inputTop
	v.tabpane.SetRect(0, 0, w, 3)
	v.input.SetRect(0, inputTop, w, h-1)
	v.hint.SetRect(0, h-1, w, h)
	v.refresh()
}

func (v *shellView) refresh() {
	v.tabpane.ActiveTabIndex = v.tab

	prompt := "> " + v.cmd + "_" // trailing cursor
	switch {
	case v.running:
		prompt = spinnerFrame() + " running: " + v.title
	case v.querying:
		prompt = spinnerFrame() + " querying…"
	}
	// Keep the cursor end visible: on a line wider than the box, show the tail.
	if iw := v.input.Inner.Dx(); iw > 3 {
		if r := []rune(prompt); len(r) > iw {
			prompt = "…" + string(r[len(r)-iw+1:])
		}
	}
	v.input.Text = prompt
	// On the Kibana tab the box is an ES|QL query input, elsewhere the CLI.
	if v.tab == tabKibana {
		v.input.Title = "es|ql query"
	} else {
		v.input.Title = "command"
	}

	// The body depends on the active tab (and, on Pipeline, on whether a job has
	// run). refresh() owns placing the body widgets because the split changes.
	var body []ui.Drawable
	switch v.tab {
	case tabContainers:
		v.buildContainers()
		// ktop-style: two resource gauges (CPU / memory) stacked over the table,
		// dropped when the body is too short to fit them plus a usable table.
		if v.bodyBottom-3 >= 9 {
			v.contCPU.SetRect(0, 3, v.w, 6)
			v.contMEM.SetRect(0, 6, v.w, 9)
			v.containers.SetRect(0, 9, v.w, v.bodyBottom)
			body = []ui.Drawable{v.contCPU, v.contMEM, v.containers}
		} else {
			v.containers.SetRect(0, 3, v.w, v.bodyBottom)
			body = []ui.Drawable{v.containers}
		}
	case tabKibana:
		// A status header over the data-stream table.
		const hdrBottom = 8
		v.kibHdr.SetRect(0, 3, v.w, hdrBottom)
		v.kibStreams.SetRect(0, hdrBottom, v.w, v.bodyBottom)
		v.buildKibana()
		body = []ui.Drawable{v.kibHdr, v.kibStreams}
	case tabTimeline:
		v.timeline.SetRect(0, 3, v.w, v.bodyBottom)
		v.buildTimeline()
		body = []ui.Drawable{v.timeline}
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

// buildContainers fills the ktop-style Containers tab: the aggregate CPU/memory
// gauges plus the per-container table, from the latest docker poll.
func (v *shellView) buildContainers() {
	rows := [][]string{{"NAME", "IMAGE", "STATUS", "CPU", "MEM"}}
	var cpuSum, memSum float64
	real := 0 // rows that are containers, not the "docker unavailable" diagnostic
	for _, c := range v.contRows {
		rows = append(rows, sanitizeRow([]string{c.name, c.image, c.status, c.cpu, c.mem}))
		if c.status != "" || c.cpu != "" { // a real container row carries a status
			real++
			cpuSum += c.cpuPct
			memSum += c.memPct
		}
	}
	v.containers.Rows = rows
	switch {
	case real > 0:
		v.containers.Title = fmt.Sprintf("containers (%d running)", real)
	case len(v.contRows) > 0:
		// Rows exist but none are real containers: the docker-unavailable
		// diagnostic. Say so — the row itself carries the reason.
		v.containers.Title = "containers — docker unavailable"
	default:
		v.containers.Title = "containers — none running (spawned per-file during a process run)"
	}

	// CPU across all containers is summed then normalised by host cores (docker's
	// per-container CPU% is already relative to one core); memory sums each
	// container's share of the host. Round once so the gauge bar and its label
	// agree (Percent is an int, the label was rounding separately), then clamp.
	cores := runtime.NumCPU()
	cpuG := cpuSum
	if cores > 0 {
		cpuG = cpuSum / float64(cores)
	}
	cpuPct := clampPct(int(math.Round(cpuG)))
	memPct := clampPct(int(math.Round(memSum)))
	v.contCPU.Percent = cpuPct
	v.contCPU.Label = fmt.Sprintf("%d%%  ·  Σ %.0f%% over %d cores", cpuPct, cpuSum, cores)
	v.contMEM.Percent = memPct
	v.contMEM.Label = fmt.Sprintf("%d%%  ·  %d container(s)", memPct, real)
}

// buildKibana renders the Kibana tab: a stack-status header + the query line,
// over the ES|QL result table (or the available data streams before any query).
// Every dynamic string is sanitized — health details, the echoed query, and the
// external result cells can all carry termui markup / control runes.
func (v *shellView) buildKibana() {
	k := v.kib
	header := []string{
		"ES: " + k.esState + "  " + k.esDetail + "   ·   Kibana: " + k.kibanaState + "  " + k.kibanaURL,
	}
	switch {
	case v.querying:
		header = append(header, "query> "+v.kibQuery+"   (running…)")
	case v.kibQuery != "":
		line := "query> " + v.kibQuery
		if v.kibRes.note != "" {
			line += "   [" + v.kibRes.note + "]"
		} else if len(v.kibRes.rows) > 0 {
			line += fmt.Sprintf("   [%d rows]", len(v.kibRes.rows))
		}
		header = append(header, line)
	default:
		header = append(header, "query> (type an ES|QL query below, e.g.  FROM logs-dxdfir.* | LIMIT 20)")
	}
	if k.note != "" {
		header = append(header, k.note)
	}
	for i := range header {
		header[i] = sanitize(header[i])
	}
	v.kibHdr.Text = strings.Join(header, "\n")

	// Result table: the query's columns/rows once one has run; otherwise the
	// available data streams, which double as a "what can I query" aid.
	if v.kibRes.ran && len(v.kibRes.cols) > 0 {
		rows := [][]string{sanitizeRow(v.kibRes.cols)}
		for _, r := range v.kibRes.rows {
			rows = append(rows, sanitizeRow(r))
		}
		v.kibStreams.Title = fmt.Sprintf("results (%d rows)", len(v.kibRes.rows))
		v.kibStreams.Rows = rows
		return
	}
	rows := [][]string{{"DATA STREAM", "DOCS", "SIZE"}}
	for _, s := range k.streams {
		rows = append(rows, []string{sanitize(s.index), sanitize(s.docs), sanitize(s.size)})
	}
	if len(k.streams) == 0 {
		v.kibStreams.Title = "data streams — none (run a query above)"
	} else {
		v.kibStreams.Title = fmt.Sprintf("data streams (%d) — or run a query above", len(k.streams))
	}
	v.kibStreams.Rows = rows
}

// sanitizeRow sanitizes every cell of a table row (external / user-supplied
// content), so termui markup and control runes can't corrupt the render.
func sanitizeRow(row []string) []string {
	out := make([]string, len(row))
	for i, c := range row {
		out[i] = sanitize(c)
	}
	return out
}

// buildTimeline fills the behaviour-timeline table from the latest read, newest
// event first (see timeline.go).
func (v *shellView) buildTimeline() {
	rows := [][]string{{"TIME", "KIND", "OBJECT", "HOST", "SUMMARY"}}
	for _, r := range v.timeRows {
		rows = append(rows, []string{
			sanitize(r.ts), sanitize(r.kind), sanitize(r.object), sanitize(r.host), sanitize(r.summary),
		})
	}
	switch {
	case v.timeNote != "":
		v.timeline.Title = "behaviour timeline — " + v.timeNote
	case len(v.timeRows) > 0:
		v.timeline.Title = fmt.Sprintf("behaviour timeline (%d newest)", len(v.timeRows))
	default:
		v.timeline.Title = "behaviour timeline"
	}
	v.timeline.Rows = rows
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
	v := newShellView(s.self, s.repoRoot)
	v.lines = []string{
		"dxdfir " + s.version + " — interactive shell",
		"",
		"Run any dxdfir command here, e.g.:",
		"    list                          # staged evidence per lane",
		"    collection status             # tracked collections",
		"    process <collection> <lane>   # process a collection with a lane",
		"",
		"Tab / →  next view · Shift-Tab / ←  previous · `clear` clears · `quit` exits · Ctrl-C cancels a run.",
	}
	v.layout(w, h)
	ui.Render(v.drawables()...)

	events := ui.PollEvents()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	// Background pollers for the read-only tabs (each bounded per call), so their
	// panes stay live during a run without blocking the UI. The latest value is
	// always stored; only the active tab triggers a redraw.
	pollCtx, stopPoll := context.WithCancel(context.Background())
	defer stopPoll()
	contCh := startPoll(pollCtx, 2*time.Second, pollContainers)
	kibCh := startPoll(pollCtx, 5*time.Second, func(ctx context.Context) kibanaStatus {
		return pollKibana(ctx, s.repoRoot)
	})
	timeCh := startPoll(pollCtx, 4*time.Second, func(context.Context) tlResult {
		rows, note := readTimeline(s.repoRoot, 2000)
		return tlResult{rows: rows, note: note}
	})

	// Command output streams in on outLines; outDone signals completion.
	var outLines chan string
	var outDone chan struct{}
	var cancel context.CancelFunc
	// An ES|QL query (Kibana tab) runs off the UI goroutine; its result arrives on
	// queryCh, and queryCancel lets Ctrl-C abort an in-flight query.
	queryCh := make(chan esqlMsg, 1)
	var queryCancel context.CancelFunc
	defer func() {
		if queryCancel != nil {
			queryCancel() // release an in-flight query's context on any exit
		}
	}()
	dirty := false

	for {
		select {
		case e := <-events:
			switch e.ID {
			case "<C-c>":
				if v.querying && queryCancel != nil {
					queryCancel() // abort the in-flight ES|QL query, stay in the shell
					v.querying = false
					queryCancel = nil
					dirty = true
					continue
				}
				if v.running && cancel != nil {
					cancel() // cancel the running command, stay in the shell
					continue
				}
				return nil // idle: quit the shell
			case "<Tab>", "<Right>":
				v.tab = (v.tab + 1) % len(shellTabs)
				dirty = true
			case "<S-Tab>", "<Left>":
				// termui/termbox never reports Shift+Tab (the terminal's ESC[Z is
				// not decoded), so ← is the real "previous tab"; the <S-Tab> case is
				// harmless and fires on any terminal that does send it.
				v.tab = (v.tab - 1 + len(shellTabs)) % len(shellTabs)
				dirty = true
			case "<Resize>":
				if r, ok := e.Payload.(ui.Resize); ok {
					v.layout(r.Width, r.Height)
					ui.Clear()
					ui.Render(v.drawables()...)
				}
			case "<Enter>":
				if v.running || v.querying {
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
					if v.tab == tabKibana {
						v.kibQuery, v.kibRes = "", esqlResult{} // clear the query view
					} else {
						v.lines = nil
					}
					dirty = true
					continue
				}
				if v.tab == tabKibana {
					// The command box is the ES|QL query input on this tab: run the
					// query off the UI goroutine and render its result in the table.
					queryCancel = v.startQuery(s.repoRoot, line, queryCh)
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
				if !v.busy() && v.cmd != "" {
					r := []rune(v.cmd)
					v.cmd = string(r[:len(r)-1])
					dirty = true
				}
			case "<Space>":
				if !v.busy() {
					v.cmd += " "
					dirty = true
				}
			default:
				// A single printable rune (termui reports it as its literal id).
				if !v.busy() && len(e.ID) == 1 {
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
		case k := <-kibCh:
			v.kib = k
			if v.tab == tabKibana {
				dirty = true
			}
		case tl := <-timeCh:
			v.timeRows, v.timeNote = tl.rows, tl.note
			if v.tab == tabTimeline {
				dirty = true
			}
		case m := <-queryCh:
			v.querying = false
			if queryCancel != nil {
				queryCancel() // release its context now the result is in
				queryCancel = nil
			}
			if m.query == v.kibQuery { // ignore a superseded/cancelled query's late result
				v.kibRes = m.res
			}
			if v.tab == tabKibana {
				dirty = true
			}
		case <-ticker.C:
			if dirty || v.running || v.querying { // keep the spinner alive while busy
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

// tlResult carries one behaviour-timeline read (rows + a degradation note) over
// the poll channel — the single value startPoll delivers.
type tlResult struct {
	rows []timelineRow
	note string
}

// esqlMsg carries a finished ES|QL query back to the UI goroutine, tagged with
// the query it answers so a superseded/cancelled query's late result is ignored.
type esqlMsg struct {
	query string
	res   esqlResult
}

// busy reports whether the command box should ignore input — a dxdfir job or an
// ES|QL query is in flight.
func (v *shellView) busy() bool { return v.running || v.querying }

// startQuery launches an ES|QL query off the UI goroutine, delivering its result
// on out (tagged with the query). It returns the query's cancel func for the
// caller to hold — Ctrl-C aborts it and the caller releases it on completion.
func (v *shellView) startQuery(repoRoot, query string, out chan<- esqlMsg) context.CancelFunc {
	v.kibQuery, v.kibRes, v.querying = query, esqlResult{}, true
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		res := runESQL(ctx, repoRoot, query)
		select {
		case out <- esqlMsg{query: query, res: res}:
		case <-ctx.Done():
		}
	}()
	return cancel
}

// startPoll fetches on `interval` until ctx is cancelled, delivering each result
// on a size-1 channel (latest-wins). It is the shared shape behind every
// read-only tab's background refresh (Containers / Kibana / Timeline), so each
// bounded fetch func stays a plain function.
func startPoll[T any](ctx context.Context, interval time.Duration, fetch func(context.Context) T) <-chan T {
	ch := make(chan T, 1)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			v := fetch(ctx)
			// Latest-wins: drop any un-consumed value first so the send below
			// never blocks (single producer → after the drain the buffer has room).
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- v:
			case <-ctx.Done():
				return
			}
			select {
			case <-t.C:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch
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
