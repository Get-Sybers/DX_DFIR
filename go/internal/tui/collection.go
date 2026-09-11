package tui

import (
	"fmt"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"

	"github.com/get-sybers/dx_dfir/go/internal/model"
)

// collectionView renders the two-phase collection-creation dashboard: phase 1
// (classify: a scrolling decision list + a per-lane tally sidebar) and phase 2
// (hash: a byte gauge + a recent-files list). Phase is carried in snap.Active
// ("classify" | "hash").
type collectionView struct {
	header    *widgets.Paragraph
	gauge     *widgets.Gauge
	decisions *widgets.List
	tally     *widgets.List
	footer    *widgets.Paragraph

	snap  model.Snapshot
	start time.Time
	w, h  int
	draw  []ui.Drawable
}

func newCollectionView() *collectionView {
	v := &collectionView{
		header:    widgets.NewParagraph(),
		gauge:     widgets.NewGauge(),
		decisions: widgets.NewList(),
		tally:     widgets.NewList(),
		footer:    widgets.NewParagraph(),
	}
	v.header.Border = false
	v.footer.Border = false
	v.decisions.WrapText = false
	v.tally.WrapText = false
	v.tally.Title = "tally"
	v.header.TextStyle = styleFg(colWhite)
	v.footer.TextStyle = styleFg(colGrey)
	return v
}

func (v *collectionView) final() model.Snapshot { return v.snap }

func (v *collectionView) apply(u model.Update) {
	if v.start.IsZero() {
		v.start = time.Now()
	}
	if u.Snapshot != nil {
		v.snap = *u.Snapshot
	}
	v.place()
	v.refresh()
}

func (v *collectionView) layout(w, h int) {
	v.w, v.h = w, h
	v.place()
	v.refresh()
}

func (v *collectionView) drawables() []ui.Drawable { return v.draw }

func (v *collectionView) place() {
	w, h := v.w, v.h
	if w < minCols {
		w = minCols
	}
	if h < minRows {
		h = minRows
	}
	v.header.SetRect(0, 0, w, 1)
	v.gauge.SetRect(0, 1, w, 4)
	footerTop := h - 1
	bodyTop := 4

	classify := v.snap.Active == "classify"
	showTally := classify && w >= 96 && len(v.snap.Lanes) > 0
	if showTally {
		split := w * 72 / 100
		v.decisions.SetRect(0, bodyTop, split, footerTop)
		v.tally.SetRect(split, bodyTop, w, footerTop)
		v.draw = []ui.Drawable{v.header, v.gauge, v.decisions, v.tally, v.footer}
	} else {
		v.decisions.SetRect(0, bodyTop, w, footerTop)
		v.draw = []ui.Drawable{v.header, v.gauge, v.decisions, v.footer}
	}
	v.footer.SetRect(0, footerTop, w, footerTop+1)
}

func (v *collectionView) refresh() {
	w := v.w
	if w < minCols {
		w = minCols
	}
	phase := v.snap.Active
	if phase == "" {
		phase = "working"
	}
	title := v.snap.Title
	if title == "" {
		title = "collection"
	}
	v.header.Text = sanitize(truncRight(
		fmt.Sprintf("dxdfir  %s   elapsed %s   |  phase: %s", title, humanElapsed(v.start), phase), w))

	pct := v.snap.Overall.Pct
	v.gauge.Percent = clampPct(pct)
	v.gauge.Title = phase
	v.gauge.Label = sanitize(truncRight(v.snap.Overall.Detail, w-4))
	if phase == "hash" {
		v.gauge.BarColor = colCyan
	} else {
		v.gauge.BarColor = colBlue
	}

	// decisions / recent-files list
	inner := v.decisions.Inner.Dx()
	if inner <= 0 {
		inner = w - 2
	}
	rows := make([]string, 0, len(v.snap.Tail))
	for _, t := range v.snap.Tail {
		rows = append(rows, sanitize(truncRight(t, inner)))
	}
	v.decisions.Rows = rows
	if phase == "hash" {
		v.decisions.Title = "files (newest at bottom)"
	} else {
		v.decisions.Title = "decisions (newest at bottom)"
	}
	if n := len(rows); n > 0 {
		v.decisions.SelectedRow = n - 1
	}
	v.decisions.TextStyle = styleFg(colWhite)

	// tally sidebar (classify only)
	if v.snap.Active == "classify" {
		trows := []string{"lane             files"}
		for _, l := range v.snap.Lanes {
			trows = append(trows, fmt.Sprintf("%-14s %5d", truncRight(l.Title, 14), l.Done))
		}
		v.tally.Rows = trows
		v.tally.TextStyle = styleFg(colGreen)
	}

	v.footer.Text = sanitize(truncRight(
		fmt.Sprintf("q/Ctrl-C abort   Ctrl-L redraw            classify+hash progress; summary prints on exit"), w))
}
