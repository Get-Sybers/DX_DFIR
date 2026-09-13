package tui

import (
	"fmt"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"

	"github.com/get-sybers/dx_dfir/go/internal/model"
)

// RunHome draws the landing dashboard for a bare `dxdfir`: a welcome header, the
// environment-readiness panel (green before anything can be processed), the
// tracked collections, and the staged evidence per lane. Unlike the process /
// collection dashboards it renders a single assembled snapshot and simply waits
// for the operator to dismiss it — there is no job to stream. Returns ErrNoTTY
// when the terminal cannot host it, so the caller falls back to the plain view.
func RunHome(h model.Home) (retErr error) {
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

	w, ht := ui.TerminalDimensions()
	if w < minCols || ht < minRows {
		closeUI()
		return ErrNoTTY // too small for the dashboard — render plain instead
	}

	v := newHomeView(h)
	v.layout(w, ht)
	ui.Render(v.drawables()...)

	for e := range ui.PollEvents() {
		switch e.ID {
		case "q", "<C-c>", "<Escape>", "<Enter>", "<Space>":
			return nil
		case "<Resize>":
			if r, ok := e.Payload.(ui.Resize); ok {
				if r.Width < minCols || r.Height < minRows {
					closeUI()
					return ErrNoTTY
				}
				v.layout(r.Width, r.Height)
				ui.Clear()
				ui.Render(v.drawables()...)
			}
		case "<C-l>":
			ui.Clear()
			ui.Render(v.drawables()...)
		}
	}
	return nil
}

type homeView struct {
	header *widgets.Paragraph
	banner *widgets.Paragraph
	checks *widgets.Table
	colls  *widgets.Table
	lanes  *widgets.Table
	footer *widgets.Paragraph

	h    model.Home
	w, y int
	draw []ui.Drawable
}

func newHomeView(h model.Home) *homeView {
	v := &homeView{
		header: widgets.NewParagraph(),
		banner: widgets.NewParagraph(),
		checks: widgets.NewTable(),
		colls:  widgets.NewTable(),
		lanes:  widgets.NewTable(),
		footer: widgets.NewParagraph(),
		h:      h,
	}
	v.header.Border = false
	v.banner.Border = false
	v.footer.Border = false
	v.header.TextStyle = styleFg(colWhite)
	v.footer.TextStyle = styleFg(colGrey)
	for _, t := range []*widgets.Table{v.checks, v.colls, v.lanes} {
		t.RowSeparator = false
		t.FillRow = true
	}
	v.checks.Title = "readiness - green before processing"
	v.colls.Title = "collections"
	v.lanes.Title = "staged evidence (data_store/raw)"
	return v
}

func (v *homeView) drawables() []ui.Drawable { return v.draw }

// layout budgets the vertical space top-down: the header, banner and readiness
// panel are always shown; collections and staged evidence fill whatever remains,
// so the dashboard degrades gracefully on a short terminal.
func (v *homeView) layout(w, h int) {
	v.w = w
	v.buildHeader(w)
	v.buildBanner(w)
	v.buildChecks(w)
	v.buildColls(w)
	v.buildLanes(w)
	v.buildFooter(w)

	v.header.SetRect(0, 0, w, 2)
	v.banner.SetRect(0, 2, w, 3)
	v.draw = []ui.Drawable{v.header, v.banner}
	y := 3

	footerTop := h - 1

	// readiness: always shown; height caps at what fits above the footer.
	checksH := len(v.h.Checks) + 2 // rows + top/bottom border
	if y+checksH > footerTop {
		checksH = maxInt(3, footerTop-y)
	}
	v.checks.SetRect(0, y, w, y+checksH)
	v.draw = append(v.draw, v.checks)
	y += checksH

	// collections + staged evidence share the remainder, evidence sized to its
	// own content first, collections taking the rest.
	avail := footerTop - y
	if avail >= 4 {
		lanesH := 0
		if len(v.h.Lanes) > 0 {
			lanesH = minInt(len(v.h.Lanes)+2, avail-3) // leave >=3 for collections
			lanesH = maxInt(0, lanesH)
		}
		collsH := avail - lanesH
		if collsH >= 3 {
			v.colls.SetRect(0, y, w, y+collsH)
			v.draw = append(v.draw, v.colls)
			y += collsH
		} else {
			lanesH = avail // no room to split; give it all to evidence
		}
		if lanesH >= 3 {
			v.lanes.SetRect(0, y, w, y+lanesH)
			v.draw = append(v.draw, v.lanes)
			y += lanesH
		}
	}

	v.footer.SetRect(0, footerTop, w, footerTop+1)
	v.draw = append(v.draw, v.footer)
}

func (v *homeView) buildHeader(w int) {
	root := v.h.RepoRoot
	if root == "" {
		root = "repo not located - pass --repo-root or set $DFIR_REPO_ROOT"
	}
	l1 := fmt.Sprintf("dxdfir %s   DX_DFIR forensic pipeline", v.h.Version)
	l2 := "repo  " + root
	v.header.Text = sanitize(truncRight(l1, w)) + "\n" + sanitize(truncRight(l2, w))
}

func (v *homeView) buildBanner(w int) {
	total, failing := 0, 0
	for _, c := range v.h.Checks {
		if c.Gate {
			total++
			if c.State != model.CheckOK {
				failing++
			}
		}
	}
	if v.h.Ready() {
		v.banner.Text = sanitize(truncRight(fmt.Sprintf(
			"%s READY - %d/%d preconditions met.  Process evidence:  dxdfir process <source>",
			glyphFor(model.CheckOK), total, total), w))
		v.banner.TextStyle = styleBold(colGreen)
		return
	}
	v.banner.Text = sanitize(truncRight(fmt.Sprintf(
		"%s NOT READY - %d of %d gate check(s) failing; resolve the [x] rows below.",
		glyphFor(model.CheckFail), failing, total), w))
	v.banner.TextStyle = styleBold(colRed)
}

func (v *homeView) buildChecks(w int) {
	inner := w - 2
	nameW := 12
	tokenW := 5                                // "[ok]" + a trailing space so termui's cell padding never clips it
	detailW := maxInt(6, inner-tokenW-nameW-2) // 3 cols => 2 separators
	v.checks.ColumnWidths = []int{tokenW, nameW, detailW}

	rows := make([][]string, 0, len(v.h.Checks))
	styles := map[int]ui.Style{}
	for i, c := range v.h.Checks {
		name := c.Name
		if !c.Gate {
			name = c.Name + "*" // starred: capability, not a hard gate
		}
		rows = append(rows, []string{glyphFor(c.State), name, sanitize(c.Detail)})
		styles[i] = styleFg(colorFor(c.State))
	}
	v.checks.Rows = rows
	v.checks.RowStyles = styles
	v.checks.Title = "readiness - green before processing   (* = optional lane/capability)"
}

func (v *homeView) buildColls(w int) {
	inner := w - 2
	if v.h.CollErr != "" {
		v.colls.ColumnWidths = []int{inner}
		v.colls.Rows = [][]string{{sanitize(v.h.CollErr)}}
		v.colls.RowStyles = map[int]ui.Style{0: styleFg(colYellow)}
		return
	}
	if len(v.h.Collections) == 0 {
		v.colls.ColumnWidths = []int{inner}
		v.colls.Rows = [][]string{{"no collections yet - register one:  dxdfir register <name>"}}
		v.colls.RowStyles = map[int]ui.Style{0: styleFg(colGrey)}
		return
	}
	markW, nameW, countW := 2, 22, 8
	detailW := maxInt(6, inner-markW-nameW-countW-3) // 4 cols => 3 separators
	v.colls.ColumnWidths = []int{markW, nameW, countW, detailW}

	rows := make([][]string, 0, len(v.h.Collections))
	styles := map[int]ui.Style{}
	for i, c := range v.h.Collections {
		mark := " "
		col := colWhite
		if c.Active {
			mark = "*"
			col = colYellow
		}
		detail := ""
		if c.Lanes != "" {
			detail = "[" + c.Lanes + "]"
		}
		if c.Sha1 != "" {
			detail += "  sha1:" + c.Sha1
		}
		if c.Tag != "" {
			detail += "  " + c.Tag
			if col == colWhite {
				col = colGrey
			}
		}
		count := "?"
		if c.Total >= 0 {
			count = fmt.Sprintf("%d file(s)", c.Total)
		}
		rows = append(rows, []string{mark, c.Name, count, sanitize(detail)})
		styles[i] = styleFg(col)
	}
	if v.h.CollNote != "" {
		styles[len(rows)] = styleFg(colGrey)
		rows = append(rows, []string{"", "note", "", sanitize(v.h.CollNote)})
	}
	v.colls.Rows = rows
	v.colls.RowStyles = styles
}

func (v *homeView) buildLanes(w int) {
	inner := w - 2
	nameW, countW := 14, 12
	locW := maxInt(6, inner-nameW-countW-2)
	v.lanes.ColumnWidths = []int{nameW, countW, locW}

	rows := make([][]string, 0, len(v.h.Lanes))
	styles := map[int]ui.Style{}
	for i, l := range v.h.Lanes {
		col := colGrey
		note := ""
		if l.Staged {
			col = colGreen
		} else {
			note = "  (not staged)"
		}
		rows = append(rows, []string{l.Name, fmt.Sprintf("%d file(s)", l.Count), sanitize(l.Loc + note)})
		styles[i] = styleFg(col)
	}
	v.lanes.Rows = rows
	v.lanes.RowStyles = styles
}

func (v *homeView) buildFooter(w int) {
	v.footer.Text = sanitize(truncRight(
		"q/Esc quit    process: dxdfir process <source>    collections: dxdfir register <name>    help: dxdfir --help", w))
}

// glyphFor maps a check state to the ASCII status token (runewidth-safe).
func glyphFor(s model.CheckState) string {
	switch s {
	case model.CheckOK:
		return "[ok]"
	case model.CheckWarn:
		return "[!] "
	default:
		return "[x] "
	}
}

func colorFor(s model.CheckState) ui.Color {
	switch s {
	case model.CheckOK:
		return colGreen
	case model.CheckWarn:
		return colYellow
	default:
		return colRed
	}
}
