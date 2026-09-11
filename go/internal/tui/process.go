package tui

import (
	"fmt"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"

	"github.com/get-sybers/dx_dfir/go/internal/model"
)

type processView struct {
	header  *widgets.Paragraph
	gauge   *widgets.Gauge
	table   *widgets.Table
	detailG *widgets.Gauge     // active gauge-lane detail
	detailP *widgets.Paragraph // active heartbeat/spinner detail
	log     *widgets.List
	exc     *widgets.List
	footer  *widgets.Paragraph

	snap  model.Snapshot
	start time.Time
	w, h  int
	draw  []ui.Drawable
}

func newProcessView() *processView {
	v := &processView{
		header:  widgets.NewParagraph(),
		gauge:   widgets.NewGauge(),
		table:   widgets.NewTable(),
		detailG: widgets.NewGauge(),
		detailP: widgets.NewParagraph(),
		log:     widgets.NewList(),
		exc:     widgets.NewList(),
		footer:  widgets.NewParagraph(),
	}
	v.header.Border = false
	v.footer.Border = false
	v.gauge.Title = "pipeline"
	v.table.Title = "lanes"
	v.table.RowSeparator = false
	v.table.FillRow = true
	v.log.WrapText = false
	v.exc.WrapText = false
	v.exc.Title = "exceptions"
	v.detailP.WrapText = false
	for _, b := range []*widgets.Paragraph{v.header, v.footer, v.detailP} {
		b.TextStyle = styleFg(colWhite)
	}
	return v
}

func (v *processView) final() model.Snapshot { return v.snap }

func (v *processView) apply(u model.Update) {
	if v.start.IsZero() {
		v.start = time.Now()
	}
	if u.Snapshot != nil {
		v.snap = *u.Snapshot
	}
	v.place()
	v.refresh()
}

func (v *processView) layout(w, h int) {
	v.w, v.h = w, h
	v.place()
	v.refresh()
}

func (v *processView) drawables() []ui.Drawable { return v.draw }

// activeLane returns the running lane the detail panel should track.
func (v *processView) activeLane() *model.Lane {
	for i := range v.snap.Lanes {
		if v.snap.Lanes[i].State == model.Running {
			return &v.snap.Lanes[i]
		}
	}
	return nil
}

func (v *processView) excLines() []string {
	var out []string
	for _, l := range v.snap.Lanes {
		for _, f := range l.Fails {
			out = append(out, "FAIL "+cellNB(l.Title, 10)+" "+f)
		}
		for _, n := range l.Notes {
			out = append(out, "NOTE "+cellNB(l.Title, 10)+" "+n)
		}
	}
	return out
}

// place computes the vertical line budget and selects which panes render.
func (v *processView) place() {
	w, h := v.w, v.h
	if w < minCols {
		w = minCols
	}
	if h < minRows {
		h = minRows
	}
	v.header.SetRect(0, 0, w, 1)
	v.gauge.SetRect(0, 1, w, 4)
	y := 4

	nLanes := len(v.snap.Lanes)
	if nLanes == 0 {
		nLanes = 1
	}
	tableH := nLanes + 1 + 2 // header row + N + top/bottom border
	footerTop := h - 1
	if y+tableH > footerTop-3 {
		tableH = maxInt(3, footerTop-3-y)
	}
	v.table.SetRect(0, y, w, y+tableH)
	y += tableH

	v.draw = []ui.Drawable{v.header, v.gauge, v.table}
	avail := footerTop - y

	// active-lane detail (3 rows)
	act := v.activeLane()
	if act != nil && avail >= 3 {
		if act.Kind == model.KindGauge {
			v.detailG.SetRect(0, y, w, y+3)
			v.draw = append(v.draw, v.detailG)
		} else {
			v.detailP.SetRect(0, y, w, y+3)
			v.draw = append(v.draw, v.detailP)
		}
		y += 3
		avail -= 3
	}

	// filtered log tail for the active long-pole lane
	if v.snap.Active != "" && len(v.snap.Tail) > 0 && avail >= 4 {
		lh := minInt(avail, 9)
		if ex := len(v.excLines()); ex > 0 && avail-lh < 4 {
			lh = maxInt(4, avail-4) // leave room for exceptions
		}
		v.log.SetRect(0, y, w, y+lh)
		v.draw = append(v.draw, v.log)
		y += lh
		avail -= lh
	}

	// exceptions panel
	if ex := len(v.excLines()); ex > 0 && avail >= 3 {
		eh := minInt(avail, minInt(ex+2, 8))
		v.exc.SetRect(0, y, w, y+eh)
		v.draw = append(v.draw, v.exc)
		y += eh
	}

	v.footer.SetRect(0, footerTop, w, footerTop+1)
	v.draw = append(v.draw, v.footer)
}

func (v *processView) refresh() {
	w := v.w
	if w < minCols {
		w = minCols
	}
	var done, running, failed, queued int
	for _, l := range v.snap.Lanes {
		switch l.State {
		case model.Done:
			done++
		case model.Running:
			running++
		case model.Failed:
			failed++
		case model.Skipped:
			done++
		default:
			queued++
		}
	}
	title := v.snap.Title
	if title == "" {
		title = "process"
	}
	head := fmt.Sprintf("dxdfir  %s   elapsed %s   |  %d done  %d running  %d failed  %d queued",
		title, humanElapsed(v.start), done, running, failed, queued)
	v.header.Text = sanitize(truncRight(head, w))

	// overall gauge: lane-equal with partial credit for running gauge lanes
	eligible, settled := 0, 0
	partial := 0.0
	for _, l := range v.snap.Lanes {
		if l.State == model.Skipped {
			continue
		}
		eligible++
		switch l.State {
		case model.Done, model.Failed:
			settled++
		case model.Running:
			if l.Kind == model.KindGauge && l.Total > 0 {
				partial += float64(l.Done) / float64(l.Total)
			}
		}
	}
	pct := 0
	if eligible > 0 {
		pct = int(100 * (float64(settled) + partial) / float64(eligible))
	}
	v.gauge.Percent = clampPct(pct)
	label := fmt.Sprintf("%d%%   %d/%d lanes finished (%d failed)", v.gauge.Percent, settled, eligible, failed)
	if act := v.activeLane(); act != nil {
		label += "  + " + laneShort(*act)
	}
	v.gauge.Label = sanitize(truncRight(label, w-4))
	switch {
	case running > 0:
		v.gauge.BarColor = colBlue
	case failed > 0:
		v.gauge.BarColor = colRed
	default:
		v.gauge.BarColor = colGreen
	}

	v.buildTable(w)
	v.buildDetail(w)
	v.buildLog()
	v.buildExceptions(w)

	v.footer.Text = sanitize(truncRight("q/Ctrl-C abort   Ctrl-L redraw            (dashboard on /dev/tty; summary prints on exit)", w))
	v.footer.TextStyle = styleFg(colGrey)
}

func (v *processView) buildTable(w int) {
	inner := w - 2
	// column widths: st, lane, [bar], items, elapsed, detail
	withBar := inner >= 88
	var cols []int
	if withBar {
		fixed := 4 + 10 + 9 + 8
		rem := inner - 5 - fixed // 6 cols => 5 separators
		bar := 26
		if bar > rem-10 {
			bar = maxInt(8, rem-10)
		}
		detail := rem - bar
		cols = []int{4, 10, bar, 9, 8, detail}
	} else {
		fixed := 4 + 10 + 9 + 8
		detail := maxInt(6, inner-4-fixed) // 5 cols => 4 separators
		cols = []int{4, 10, 9, 8, detail}
	}
	v.table.ColumnWidths = cols

	rows := [][]string{}
	styles := map[int]ui.Style{}
	if withBar {
		rows = append(rows, []string{"st", "lane", "progress", "items", "elapsed", "detail"})
	} else {
		rows = append(rows, []string{"st", "lane", "items", "elapsed", "detail"})
	}
	styles[0] = styleFg(colGrey)

	for i, l := range v.snap.Lanes {
		tok, col := stateToken(l.State)
		items := laneItems(l)
		el := ""
		if !l.Started.IsZero() {
			end := l.Ended
			if end.IsZero() {
				end = time.Now()
			}
			el = fmtDur(end.Sub(l.Started))
		}
		det := sanitize(laneDetail(l))
		var row []string
		if withBar {
			row = []string{tok, l.Title, asciiBar(l.Percent(), cols[2]), items, el, det}
		} else {
			row = []string{tok, l.Title, items, el, det}
		}
		rows = append(rows, row)
		styles[i+1] = styleFg(col)
	}
	v.table.Rows = rows
	v.table.RowStyles = styles
}

func (v *processView) buildDetail(w int) {
	act := v.activeLane()
	if act == nil {
		return
	}
	if act.Kind == model.KindGauge {
		v.detailG.Title = truncRight(fmt.Sprintf("%s  running %s", act.Title, fmtDur(sinceStart(act))), w-2)
		v.detailG.Percent = clampPct(act.Percent())
		v.detailG.BarColor = colBlue
		v.detailG.Label = sanitize(truncRight(fmt.Sprintf("%d/%d  %d%%   %s",
			act.Done, act.Total, clampPct(act.Percent()), act.Detail), w-4))
		return
	}
	// heartbeat / spinner
	kind := "heartbeat lane: no item gauge"
	extra := ""
	if act.Kind == model.KindSpinner {
		kind = "spinner lane: single final write, no denominator"
		extra = spinnerFrame() + "  working   "
	} else if act.Cur > 0 {
		extra = fmt.Sprintf("artefact %s   ", humanBytes(act.Cur))
	}
	v.detailP.Title = truncRight(fmt.Sprintf("%s  running %s   %s", act.Title, fmtDur(sinceStart(act)), kind), w-2)
	v.detailP.Text = sanitize(truncRight(extra+act.Detail, w-2))
}

func (v *processView) buildLog() {
	if v.snap.Active == "" {
		v.log.Rows = nil
		return
	}
	v.log.Title = fmt.Sprintf("%s log   filtered tail", v.snap.Active)
	rows := make([]string, 0, len(v.snap.Tail))
	inner := v.w - 2
	for _, t := range v.snap.Tail {
		rows = append(rows, sanitize(truncRight(t, inner)))
	}
	v.log.Rows = rows
	v.log.TextStyle = styleFg(colGrey)
	if n := len(rows); n > 0 {
		v.log.SelectedRow = n - 1
	}
}

func (v *processView) buildExceptions(w int) {
	lines := v.excLines()
	rows := make([]string, 0, len(lines))
	for _, l := range lines {
		rows = append(rows, sanitize(truncRight(l, w-2)))
	}
	v.exc.Rows = rows
	v.exc.Title = fmt.Sprintf("exceptions (%d)", len(lines))
	v.exc.TextStyle = styleFg(colYellow)
}

// ---- small helpers ----

func stateToken(s model.State) (string, ui.Color) {
	switch s {
	case model.Done:
		return "DONE", colGreen
	case model.Running:
		return "RUN ", colBlue
	case model.Failed:
		return "FAIL", colRed
	case model.Skipped:
		return "SKIP", colGrey
	default:
		return "WAIT", colGrey
	}
}

func laneItems(l model.Lane) string {
	switch l.Kind {
	case model.KindGauge:
		if l.Total > 0 {
			return fmt.Sprintf("%d/%d", l.Done, l.Total)
		}
		return fmt.Sprintf("%d", l.Done)
	case model.KindHeartbeat:
		if l.Total > 0 {
			return fmt.Sprintf("%d/%d", l.Done, l.Total)
		}
		return "-"
	default:
		return "-"
	}
}

func laneDetail(l model.Lane) string {
	if l.Detail != "" {
		return l.Detail
	}
	switch l.State {
	case model.Queued:
		return "queued"
	case model.Skipped:
		return "no inputs"
	}
	return ""
}

func laneShort(l model.Lane) string {
	switch l.Kind {
	case model.KindGauge:
		return fmt.Sprintf("%s %d/%d", l.Title, l.Done, l.Total)
	case model.KindHeartbeat:
		return fmt.Sprintf("%s running %s", l.Title, fmtDur(sinceStart(&l)))
	default:
		return fmt.Sprintf("%s running %s", l.Title, fmtDur(sinceStart(&l)))
	}
}

func sinceStart(l *model.Lane) time.Duration {
	if l.Started.IsZero() {
		return 0
	}
	end := l.Ended
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(l.Started)
}

func cellNB(s string, width int) string { return padRight(truncRight(sanitize(s), width), width) }

func clampPct(p int) int {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
