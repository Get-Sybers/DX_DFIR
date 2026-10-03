package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/Get-Sybers/DX_DFIR/go/internal/model"
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

// A lane with no meaningful percentage (spinner / heartbeat / unknown total)
// must yield a negative fill so asciiBar renders a blank bar, not an all-'.' 0%
// bar that implies zero progress.
func TestLaneGaugePctBlankForUnknown(t *testing.T) {
	for _, k := range []model.Kind{model.KindSpinner, model.KindHeartbeat} {
		l := model.Lane{Kind: k, State: model.Running}
		if got := laneGaugePct(l); got >= 0 {
			t.Errorf("kind %v: laneGaugePct = %d, want < 0 (blank bar)", k, got)
		}
	}
	// A gauge lane with an unknown total is likewise blank.
	if got := laneGaugePct(model.Lane{Kind: model.KindGauge, State: model.Running, Total: 0}); got >= 0 {
		t.Errorf("unknown-total gauge: laneGaugePct = %d, want < 0", got)
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
	// The freeze lives entirely in humanSpan: once end is set it returns end-start
	// and never consults the wall clock, so a start/end pair far in the past reads
	// as its own span, not the (large) time elapsed since start.
	start := time.Now().Add(-90 * time.Second)
	end := start.Add(5 * time.Second)
	if got := humanSpan(start, end); got != "00:00:05" {
		t.Errorf("frozen span = %q, want 00:00:05 (clock not frozen)", got)
	}
	// While running (end zero) it does track the wall clock.
	if got := humanSpan(start, time.Time{}); got == "00:00:05" {
		t.Errorf("running span = %q, expected to track wall clock", got)
	}
}
