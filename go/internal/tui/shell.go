package tui

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
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

	tabpane *widgets.TabPane
	log     *widgets.List // streamed output of the last/running command
	input   *widgets.Paragraph
	hint    *widgets.Paragraph

	draw []ui.Drawable
	w, h int

	tab     int
	cmd     string   // current input buffer
	lines   []string // log lines
	running bool
	title   string
}

func newShellView(self string) *shellView {
	tp := widgets.NewTabPane(shellTabs...)
	tp.Border = true
	v := &shellView{
		self:    self,
		tabpane: tp,
		log:     widgets.NewList(),
		input:   widgets.NewParagraph(),
		hint:    widgets.NewParagraph(),
		title:   "dxdfir",
	}
	v.log.Title = "output"
	v.log.WrapText = false
	v.input.Title = "command"
	v.hint.Border = false
	v.hint.TextStyle = styleFg(colGrey)
	v.hint.Text = "type a dxdfir command, Enter to run · Tab switches view · Ctrl-C quits"
	return v
}

func (v *shellView) layout(w, h int) {
	v.w, v.h = w, h
	v.tabpane.SetRect(0, 0, w, 3)
	inputTop := h - 3
	hintTop := h - 1
	// Pipeline: the log pane fills the body for now (the gauge + queue widgets
	// slot in above it when the pipeline tab is wired to a running job).
	v.log.SetRect(0, 3, w, inputTop)
	v.input.SetRect(0, inputTop, w, hintTop)
	v.hint.SetRect(0, hintTop, w, h)
	v.refresh()
}

func (v *shellView) refresh() {
	v.tabpane.ActiveTabIndex = v.tab
	// Keep only the log lines that fit, newest at the bottom.
	if h := v.log.Inner.Dy(); h > 0 && len(v.lines) > h {
		v.log.Rows = v.lines[len(v.lines)-h:]
	} else {
		v.log.Rows = append([]string(nil), v.lines...)
	}
	prompt := "> " + v.cmd
	if v.running {
		prompt = spinnerFrame() + " running: " + v.title
	} else {
		prompt += "_" // cursor
	}
	v.input.Text = prompt

	switch v.tab {
	case tabContainers:
		v.log.Title = "containers (docker) — coming next"
	default:
		v.log.Title = "output"
	}
	v.draw = []ui.Drawable{v.tabpane, v.log, v.input, v.hint}
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
				outLines, outDone, cancel = s.start(line)
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
			v.appendLine(ln)
			dirty = true
		case <-outDoneOr(outDone):
			v.running = false
			outDone = nil
			cancel = nil
			dirty = true
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
func (s *Shell) start(line string) (chan string, chan struct{}, context.CancelFunc) {
	lines := make(chan string, 256)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())

	args := append(splitArgs(line), "--no-tui")
	cmd := exec.CommandContext(ctx, s.self, args...)
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
