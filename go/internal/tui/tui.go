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
	"strings"
	"unicode"

	ui "github.com/gizak/termui/v3"
	rw "github.com/mattn/go-runewidth"
)

// ErrNoTTY is returned when the terminal cannot host the dashboard (termbox init
// failed, or the window is below the minimum). The caller falls back to plain.
var ErrNoTTY = errors.New("tui: terminal unavailable")

// 256-colour palette translated from the Python CLI's typer vocabulary.
const (
	colGreen  = ui.Color(71)
	colYellow = ui.Color(178)
	colRed    = ui.Color(167)
	colBlue   = ui.Color(68)
	colGrey   = ui.Color(245)
	colCyan   = ui.Color(74)
	colWhite  = ui.Color(255)
)

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
// map anything wide/zero-width/emoji to '?', and break the "](" adjacency that
// termui's [text](style) markup parser keys on. ASCII stays verbatim (forensic
// fidelity for paths/hashes).
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
		case rw.RuneWidth(r) == 1 && !unicode.IsControl(r):
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
