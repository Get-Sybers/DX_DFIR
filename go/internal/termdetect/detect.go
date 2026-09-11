// Package termdetect decides whether the rich termui dashboard may be used, and
// keeps the decision in one place so the streaming layer is identical in both
// modes and only the presenter differs.
//
// The contract from the packaging investigation is strict: the dashboard renders
// to STDERR and must auto-disable whenever STDOUT is not a real terminal, so that
// `dxdfir stix ... | jq` and other piped/redirected pipelines never see UI bytes
// on the data channel.
package termdetect

import (
	"os"
)

// UseTUI reports whether the interactive termui dashboard should be used.
//
// termbox (termui's backend) opens /dev/tty directly, so the dashboard never
// touches stdout or stderr — which means a machine-readable stdout stays clean
// even while the dashboard is up, and `dxdfir process > run.json` can both show
// the dashboard and write JSON to the file. The gate is therefore: an
// interactive session (stderr is a terminal) that has not opted out. force
// (--tui) overrides the interactivity check but never an explicit opt-out.
func UseTUI(force bool) bool {
	if os.Getenv("DXDFIR_NO_TUI") != "" || os.Getenv("CI") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if force {
		return true
	}
	return isTerminal(os.Stderr)
}

// isTerminal reports whether f is attached to a character device (a TTY), using
// only the standard library — no dependency that would pin a newer Go toolchain.
// termbox performs the authoritative terminal probe on ui.Init(); this is the
// cheap pre-check that lets us pick a presenter before touching the terminal.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// StdoutIsTTY reports whether stdout specifically is a terminal — used by verbs
// whose payload is machine-readable (stix, engine passthrough) to keep stdout
// pristine regardless of the TUI decision.
func StdoutIsTTY() bool { return isTerminal(os.Stdout) }
