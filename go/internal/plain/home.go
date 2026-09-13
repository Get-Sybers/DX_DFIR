package plain

import (
	"fmt"
	"io"

	"github.com/get-sybers/dx_dfir/go/internal/model"
	"github.com/get-sybers/dx_dfir/go/internal/style"
)

// PrintHome renders the landing dashboard as plain lines — the non-TTY form of
// what tui.RunHome draws. It is what a bare `dxdfir` prints under a pipe, a dumb
// terminal, or --no-tui, and it is written to stdout (like `list`) so the
// welcome/readiness report is a first-class, greppable payload.
func PrintHome(w io.Writer, h model.Home) {
	fmt.Fprintln(w, style.Bold(fmt.Sprintf("dxdfir %s", h.Version))+"   DX_DFIR forensic pipeline")
	if h.RepoRoot != "" {
		fmt.Fprintln(w, style.Grey("repo  "+h.RepoRoot))
	} else {
		fmt.Fprintln(w, style.Yellow("repo  not located - pass --repo-root or set $DFIR_REPO_ROOT"))
	}
	fmt.Fprintln(w, "")

	// readiness banner
	total, failing := 0, 0
	for _, c := range h.Checks {
		if c.Gate {
			total++
			if c.State != model.CheckOK {
				failing++
			}
		}
	}
	if h.Ready() {
		fmt.Fprintln(w, style.Green(fmt.Sprintf("%s READY - %d/%d preconditions met.", style.GlyphOK, total, total)))
	} else {
		fmt.Fprintln(w, style.Red(fmt.Sprintf("%s NOT READY - %d of %d gate check(s) failing.", style.GlyphErr, failing, total)))
	}

	fmt.Fprintln(w, style.Bold("Readiness")+style.Grey("   (* = optional lane/capability, not a process gate)"))
	for _, c := range h.Checks {
		name := c.Name
		if !c.Gate {
			name += "*"
		}
		mark, colour := homeMark(c.State)
		fmt.Fprintf(w, "  %s %-13s %s\n", colour(mark), name, c.Detail)
	}
	fmt.Fprintln(w, "")

	// collections
	fmt.Fprintln(w, style.Bold("Collections"))
	switch {
	case h.CollErr != "":
		fmt.Fprintln(w, "  "+style.Yellow(h.CollErr))
	case len(h.Collections) == 0:
		fmt.Fprintln(w, "  "+style.Grey("none yet - register one:  dxdfir register <name>"))
	default:
		if h.CollNote != "" {
			fmt.Fprintln(w, "  "+style.Grey(h.CollNote))
		}
		for _, c := range h.Collections {
			mark := " "
			if c.Active {
				mark = style.Yellow(style.GlyphStar)
			}
			count := fmt.Sprintf("%4d", c.Total)
			switch {
			case c.Total < 0:
				count = style.Grey("   ?")
			case c.Total > 0:
				count = style.Green(count)
			default:
				count = style.Grey(count)
			}
			lanes := c.Lanes
			if lanes == "" {
				lanes = "-"
			}
			line := fmt.Sprintf(" %s %-22s %s file(s)  [%s]", mark, c.Name, count, lanes)
			if c.Sha1 != "" {
				line += "  sha1:" + c.Sha1
			}
			if c.Tag != "" {
				line += "  " + style.Yellow(c.Tag)
			}
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintln(w, "")

	// staged evidence
	fmt.Fprintln(w, style.Bold("Staged evidence")+style.Grey("   (data_store/raw/ - what `process` reads)"))
	for _, l := range h.Lanes {
		count := fmt.Sprintf("%5d", l.Count)
		note := ""
		if l.Staged {
			count = style.Green(count)
		} else {
			count = style.Grey(count)
			note = style.Grey("  (not staged)")
		}
		fmt.Fprintf(w, "  %-13s %s file(s)  %s%s\n", l.Name, count, l.Loc, note)
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, style.Cyan(style.GlyphHint+" process: dxdfir process <source>   |   register: dxdfir register <name>   |   help: dxdfir --help"))
}

func homeMark(s model.CheckState) (string, func(string) string) {
	switch s {
	case model.CheckOK:
		return style.GlyphOK, style.Green
	case model.CheckWarn:
		return style.GlyphWarn, style.Yellow
	default:
		return style.GlyphErr, style.Red
	}
}
