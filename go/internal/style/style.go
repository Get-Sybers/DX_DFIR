// Package style is the single home for the terminal colour + glyph vocabulary,
// translated from the retired Python CLI's palette into an ANSI/256-colour set
// the plain presenter and all non-dashboard verbs share. Colours target STDERR
// (diagnostics); machine-readable payloads on stdout are never styled.
//
// The glyph set is deliberately ASCII-safe: termui pins go-runewidth v0.0.2,
// which mis-measures emoji and many wide runes and corrupts layout, so the
// dashboard reuses these markers rather than the emoji the old CLI printed.
package style

import "os"

// Enabled reports whether ANSI styling should be emitted (honours NO_COLOR and
// requires stderr to be a terminal).
var Enabled = colorEnabled()

func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// ANSI SGR codes for the palette. Semantics mirror the retired Python CLI:
//
//	grey   → the "→ command" echo and secondary/info lines
//	green  → success, present/non-zero counts, progress headers
//	yellow → warnings, the active-collection marker, destructive prompts
//	red    → errors (always on stderr)
//	cyan   → actionable hints
const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "\x1b[1m"
	sgrGrey   = "\x1b[90m"
	sgrGreen  = "\x1b[32m"
	sgrYellow = "\x1b[33m"
	sgrRed    = "\x1b[31m"
	sgrCyan   = "\x1b[36m"
)

func wrap(code, s string) string {
	if !Enabled {
		return s
	}
	return code + s + sgrReset
}

func Grey(s string) string   { return wrap(sgrGrey, s) }
func Green(s string) string  { return wrap(sgrGreen, s) }
func Yellow(s string) string { return wrap(sgrYellow, s) }
func Red(s string) string    { return wrap(sgrRed, s) }
func Cyan(s string) string   { return wrap(sgrCyan, s) }
func Bold(s string) string   { return wrap(sgrBold, s) }

// ASCII-safe status glyphs (the emoji translation table). These are plain
// characters that render at width 1 everywhere.
const (
	GlyphOK     = "[ok]" // success (was ✅)
	GlyphWarn   = "[!]"  // warning (was ⚠️)
	GlyphErr    = "[x]"  // error / failure (was ❌ / • in violation lists)
	GlyphInfo   = "[i]"  // info (was ℹ️)
	GlyphHash   = "[#]"  // hashing (was 🔒)
	GlyphHint   = "->"   // actionable hint (was 💡)
	GlyphStar   = "*"    // active collection (was ★)
	GlyphArrow  = "->"   // command echo prefix (was →)
	GlyphBullet = "-"    // list bullet (was •)
)
