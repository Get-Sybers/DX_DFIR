package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/dx_dfir/go/internal/model"
)

// A gauge lane whose output files have all landed (Done==Total) but whose
// ansible-playbook has not yet exited is still Running; the overall bar and the
// per-lane bar must hold below 100% so the dashboard never reads "done" while
// the header clock is still ticking.
func TestRunningGaugeHeldBelowFull(t *testing.T) {
	v := newProcessView("0.0.0-test")
	v.layout(120, 30)
	snap := model.Snapshot{
		Title: "process gowindowlicker",
		Lanes: []model.Lane{{
			ID: "gowindowlicker", Title: "gowindowlicker", Kind: model.KindGauge,
			State: model.Running, Done: 10, Total: 10, Started: time.Now(),
		}},
	}
	v.apply(model.Update{Snapshot: &snap})

	if v.gauge.Percent >= 100 {
		t.Errorf("overall gauge = %d%% while lane still running, want < 100", v.gauge.Percent)
	}
	if got := laneGaugePct(snap.Lanes[0]); got >= 100 {
		t.Errorf("per-lane gauge = %d%% while running, want < 100", got)
	}

	// Once the lane settles, the full bar is allowed.
	snap.Lanes[0].State = model.Done
	snap.Lanes[0].Ended = time.Now()
	v.apply(model.Update{Snapshot: &snap, Done: true})
	if v.gauge.Percent != 100 {
		t.Errorf("overall gauge = %d%% after done, want 100", v.gauge.Percent)
	}
}

// The typographic punctuation the dashboard's own strings use must fold to ASCII,
// not the generic '?' that looked like a decode error (the middle-dot separator
// and the em dash in the "done — press q" dismiss hint).
func TestSanitizeAsciiFold(t *testing.T) {
	cases := map[string]string{
		"scanning · 1m28s": "scanning - 1m28s",
		"done — press q":   "done - press q",
		"a–b":              "a-b",
		"it’s “ok”":        "it's \"ok\"",
		"more…":            "more.",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	// A genuinely unrenderable rune still degrades to '?'.
	if got := sanitize("hi ☃"); got != "hi ?" {
		t.Errorf("sanitize snowman = %q, want %q", got, "hi ?")
	}
}

// The dashboard header shows the build version so a stale binary is obvious.
func TestHeaderShowsVersion(t *testing.T) {
	v := newProcessView("0.6.0 (abc1234, dirty)")
	v.layout(120, 30)
	v.apply(model.Update{Snapshot: &model.Snapshot{Title: "process zeek"}})
	if !strings.Contains(v.header.Text, "0.6.0 (abc1234, dirty)") {
		t.Errorf("header %q does not carry the version", v.header.Text)
	}
}

// The header's elapsed clock must freeze on the final (Done) update instead of
// ticking on past completion.
func TestHeaderClockFreezesOnDone(t *testing.T) {
	v := newProcessView("0.0.0-test")
	v.layout(120, 30)
	v.apply(model.Update{Snapshot: &model.Snapshot{Title: "process"}})
	v.apply(model.Update{Snapshot: &model.Snapshot{Title: "process"}, Done: true})

	if v.end.IsZero() {
		t.Fatal("end not recorded on Done update")
	}
	frozen := humanSpan(v.start, v.end)
	time.Sleep(1100 * time.Millisecond)
	if again := humanSpan(v.start, v.end); again != frozen {
		t.Errorf("clock advanced after done: %q -> %q", frozen, again)
	}
}
