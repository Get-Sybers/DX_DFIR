package plain

import (
	"strings"
	"testing"
	"time"

	"github.com/Get-Sybers/DX_DFIR/go/internal/model"
)

func TestBarLeadingEdge(t *testing.T) {
	cases := map[int]string{
		0:   "[            ]",
		100: "[============]",
	}
	for pct, want := range cases {
		if got := bar(pct); got != want {
			t.Errorf("bar(%d) = %q, want %q", pct, got, want)
		}
	}
	mid := bar(50)
	if !strings.Contains(mid, ">") || !strings.HasPrefix(mid, "[=") || !strings.HasSuffix(mid, " ]") {
		t.Errorf("bar(50) = %q, want a leading-edge partial bar", mid)
	}
}

func TestVisibleWidthSkipsEscapes(t *testing.T) {
	// "\x1b[32mok\x1b[0m" renders two visible columns.
	if got := visibleWidth("\x1b[32mok\x1b[0m"); got != 2 {
		t.Errorf("visibleWidth = %d, want 2", got)
	}
	if got := visibleWidth("plain"); got != 5 {
		t.Errorf("visibleWidth = %d, want 5", got)
	}
}

func TestRenderBlockShapesLikeDocker(t *testing.T) {
	p := &Presenter{cols: 80}
	start := time.Now().Add(-5 * time.Second)
	s := model.Snapshot{
		Title:   "process LS24",
		Overall: model.Overall{LanesDone: 1, LanesTotal: 3, Pct: -1},
		Lanes: []model.Lane{
			{ID: "zeek", Title: "zeek", Kind: model.KindGauge, State: model.Done, Done: 12, Total: 12, Started: start, Ended: time.Now()},
			{ID: "gowindowlicker", Title: "gowindowlicker", Kind: model.KindGauge, State: model.Running, Done: 4, Total: 10, Detail: "4/10 · Security.evtx", Started: start},
			{ID: "anamnesis", Title: "anamnesis", Kind: model.KindSpinner, State: model.Queued},
		},
	}
	rows := p.renderBlock(s, '/', "5s")

	if len(rows) != 4 { // header + 3 lanes
		t.Fatalf("got %d rows, want 4:\n%s", len(rows), strings.Join(rows, "\n"))
	}
	if !strings.Contains(rows[0], "process LS24") || !strings.Contains(rows[0], "(1/3)") {
		t.Errorf("header = %q, want title and (1/3)", rows[0])
	}
	if !strings.Contains(rows[1], "zeek") || !strings.Contains(rows[1], "12/12") {
		t.Errorf("done row = %q", rows[1])
	}
	run := rows[2]
	for _, want := range []string{"/", "gowindowlicker", "40%", "[=", "(4/10)", "Security.evtx"} {
		if !strings.Contains(run, want) {
			t.Errorf("running row = %q, missing %q", run, want)
		}
	}
	if !strings.Contains(rows[3], "queued") {
		t.Errorf("queued row = %q, want 'queued'", rows[3])
	}

	// No row may exceed the terminal width, or the in-place cursor math desyncs.
	for i, r := range rows {
		if w := visibleWidth(r); w > p.cols-1 {
			t.Errorf("row %d visible width %d exceeds %d: %q", i, w, p.cols-1, r)
		}
	}
}

func TestRowRightAligns(t *testing.T) {
	p := &Presenter{cols: 40}
	got := p.row("left", "9s")
	if visibleWidth(got) != p.cols-1 {
		t.Errorf("row width = %d, want %d: %q", visibleWidth(got), p.cols-1, got)
	}
	if !strings.HasPrefix(got, "left") || !strings.HasSuffix(got, "9s") {
		t.Errorf("row = %q, want left-anchored and right-anchored", got)
	}
}
