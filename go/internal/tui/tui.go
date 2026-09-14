// Package tui is the termui presenter — the ONLY package that imports
// github.com/gizak/termui. It renders the shared model.Update stream as a live
// dashboard on the terminal (which termbox opens via /dev/tty, so stdout stays
// clean). The design follows the width-verified spec: ASCII-only dynamic text,
// truthful gauges only, a bounded filtered log-tail, and an exceptions panel —
// with the durable summary printed as plain text after the alternate screen is
// torn down.
package tui

import (
	"errors"
	"os"
	"strings"
	"sync"
	"unicode"

	ui "github.com/gizak/termui/v3"
	rw "github.com/mattn/go-runewidth"
)

// ErrNoTTY is returned when the terminal cannot host the dashboard (termbox init
// failed, or the window is below the minimum). The caller falls back to plain.
var ErrNoTTY = errors.New("tui: terminal unavailable")

// The "Sunset" 256-colour palette — one warm accent family (marigold → crimson);
// green/blue/cyan retired so nothing competes with the sunset and no pass/fail
// hangs on red-vs-green. The EXISTING names are kept as SEMANTIC ALIASES so the
// process / home / collection views recolour with no edits — only the values
// change. Every state still pairs its colour with a glyph/token, never hue alone.
// (Deep-purple sticker bands translate to the terminal's own dark background —
// painted by nothing.) Dark-terminal-first; borders are intentionally dim.
const (
	colBlue   = ui.Color(214) // #ffaf00 marigold  — accent / running / focus (was 68)
	colGreen  = ui.Color(172) // #d78700 amber     — done / ready             (was 71)
	colYellow = ui.Color(173) // #d7875f ochre     — warn / exceptions / mid  (was 178)
	colCyan   = ui.Color(173) // #d7875f ochre     — collection 'hash' phase  (was 74)
	colRed    = ui.Color(167) // #d75f5f vermilion — failed / error           (unchanged)
	colWhite  = ui.Color(255) // #eeeeee           — body / cell / label text (unchanged)
	colGrey   = ui.Color(245) // #8a8a8a           — secondary / dim TEXT     (unchanged)

	colTitle    = ui.Color(230) // #ffffd7 cream   — widget TITLES (text; near-white allowed)
	colCritical = ui.Color(160) // #d70000 crimson — high-load gauge fill (BAR-FILL ONLY)
	colInactive = ui.Color(130) // #af5f00 burnt amber — inactive tab (non-text chrome)
)

// colBorder is the frame tone — NON-TEXT chrome, so it must never be near-white.
// It is selectable via DXDFIR_THEME (see frameModes); initTheme sets it. The dim
// bronze default ("ember") recedes so the frame is felt, not read.
var colBorder = ui.Color(94) // #875f00 deep bronze — ember (default)

// frameModes are the selectable border tones, all at the dim/warm end of the ramp
// (none near-white). DXDFIR_THEME picks one; anything unset/unknown → ember.
var frameModes = map[string]ui.Color{
	"ember":     ui.Color(94),  // #875f00 deep bronze — most recessive (default)
	"dusk":      ui.Color(130), // #af5f00 burnt amber — a touch more present
	"driftwood": ui.Color(137), // #af875f tan         — softest (leans toward grey)
}

var themeOnce sync.Once

// ensureTheme applies the Sunset theme exactly once per process, BEFORE any widget
// is constructed. termui widgets copy ui.Theme at construction, so every view
// constructor calls this as its first statement — the ui.Init() call is unrelated
// (it sets up termbox; ui.Theme is just a package var), so this is safe to run
// before or after Init.
func ensureTheme() { themeOnce.Do(initTheme) }

// initTheme paints termui's shared Theme in the Sunset palette. It is applied via
// ensureTheme (once, before any widget is built). Text (including titles) may be
// near-white; non-text chrome (borders, tabs, gauge bars) is warm, never
// near-white.
func initTheme() {
	if c, ok := frameModes[strings.ToLower(strings.TrimSpace(os.Getenv("DXDFIR_THEME")))]; ok {
		colBorder = c
	} else {
		colBorder = frameModes["ember"]
	}
	ui.Theme.Default = styleFg(colWhite)
	ui.Theme.Block.Title = styleFg(colTitle)   // cream titles (text)
	ui.Theme.Block.Border = styleFg(colBorder) // warm frame (non-text, not near-white)
	ui.Theme.Paragraph.Text = styleFg(colWhite)
	ui.Theme.List.Text = styleFg(colWhite)
	ui.Theme.Table.Text = styleFg(colWhite)
	ui.Theme.Gauge.Bar = colBlue             // default bar fill = marigold, never white
	ui.Theme.Tab.Active = styleBold(colBlue) // bright marigold = the active view
	ui.Theme.Tab.Inactive = styleFg(colInactive)
}

// gaugeLoad ramps a LOAD gauge (Containers CPU/MEM, where more == worse) along the
// sunset by value: amber calm → ochre busy → crimson hot. PROGRESS gauges never
// use this — they key to job state so completion never reads as alarm. The numeric
// label carries the value for colour-vision-deficient reading.
func gaugeLoad(pct int) ui.Color {
	switch {
	case pct >= 85:
		return colCritical // crimson
	case pct >= 60:
		return colYellow // ochre
	default:
		return colBlue // amber / marigold
	}
}

// Minimum window the dashboard needs; below this we stay plain.
const (
	minCols = 60
	minRows = 14
)

func init() {
	// runewidth v0.0.2 mis-measures ambiguous-width runes under a CJK locale,
	// which shifts every row; force width-1 measurement (we emit ASCII anyway).
	rw.EastAsianWidth = false
	if rw.DefaultCondition != nil {
		rw.DefaultCondition.EastAsianWidth = false
	}
}

func styleFg(c ui.Color) ui.Style   { return ui.NewStyle(c) }
func styleBold(c ui.Color) ui.Style { return ui.NewStyle(c, ui.ColorClear, ui.ModifierBold) }

// sanitize makes a dynamic string safe for a termui widget: strip control runes,
// map EVERY non-ASCII rune to '?', and break the "](" adjacency that termui's
// [text](style) markup parser keys on. Mapping all non-ASCII to a single-byte
// '?' keeps byte length == column count, so the byte-slicing truncRight/truncLeft/
// padRight below can never split a multi-byte rune or miscompute a width. ASCII
// stays verbatim (forensic fidelity for paths/hashes); the full non-ASCII name
// survives in the plain summary / on-disk logs.
func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			// drop
		case r < 128:
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	return strings.ReplaceAll(b.String(), "](", "] (")
}

// truncRight cuts a string to width, appending ".." when cut.
func truncRight(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if len(s) <= width {
		return s
	}
	if width <= 2 {
		return s[:width]
	}
	return s[:width-2] + ".."
}

// truncLeft keeps the tail of a string (paths), prefixing ".." when cut.
func truncLeft(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if len(s) <= width {
		return s
	}
	if width <= 2 {
		return s[len(s)-width:]
	}
	return ".." + s[len(s)-(width-2):]
}

// padRight pads with spaces to width (so a widget row's last rune is a space,
// defusing the markup parser's end-of-string bracket hazards).
func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// cell truncates then pads to an exact column width.
func cell(s string, width int) string { return padRight(truncRight(sanitize(s), width), width) }

// asciiBar renders a "####...." progress bar of the given width.
func asciiBar(pct, width int) string {
	if width <= 0 {
		return ""
	}
	if pct < 0 {
		return strings.Repeat(" ", width)
	}
	if pct > 100 {
		pct = 100
	}
	fill := pct * width / 100
	return strings.Repeat("#", fill) + strings.Repeat(".", width-fill)
}
