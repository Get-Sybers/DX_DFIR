package plain

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/get-sybers/dx_dfir/go/internal/model"
)

// TestJSONProgressRoundTrip feeds an update stream through the presenter and
// decodes its stdout back into model.ProgressEvent lines — the exact contract
// the interactive shell relies on to drive its Pipeline widgets.
func TestJSONProgressRoundTrip(t *testing.T) {
	updates := make(chan model.Update, 4)
	updates <- model.Update{Log: &model.LogLine{Text: "starting"}}
	updates <- model.Update{Snapshot: &model.Snapshot{
		Title:   "job",
		Overall: model.Overall{LanesDone: 1, LanesTotal: 3, Pct: 33},
		Lanes:   []model.Lane{{ID: "zeek", Title: "zeek", State: model.Running, Done: 2, Total: 5}},
	}}
	updates <- model.Update{Done: true, Err: errors.New("boom")}
	close(updates)

	events := runCaptured(t, updates)

	if len(events) != 3 {
		t.Fatalf("want 3 events, got %d: %+v", len(events), events)
	}
	if events[0].Log != "starting" {
		t.Errorf("event 0: want log %q, got %q", "starting", events[0].Log)
	}
	if events[1].Snapshot == nil {
		t.Fatal("event 1: want a snapshot")
	}
	if got := events[1].Snapshot.Overall.Pct; got != 33 {
		t.Errorf("event 1: want Pct 33, got %d", got)
	}
	if got := events[1].Snapshot.Lanes[0].State; got != model.Running {
		t.Errorf("event 1: want lane running, got %q", got)
	}
	if !events[2].Done || events[2].Err != "boom" {
		t.Errorf("event 2: want Done with err %q, got %+v", "boom", events[2])
	}
}

// runCaptured runs the JSON presenter with os.Stdout redirected to a pipe and
// returns the decoded events. The presenter error is asserted to match Done.Err.
func runCaptured(t *testing.T, updates <-chan model.Update) []model.ProgressEvent {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	// Drain the pipe concurrently so a large stream can't deadlock the writer.
	type result struct {
		events []model.ProgressEvent
		err    error
	}
	res := make(chan result, 1)
	go func() {
		var evs []model.ProgressEvent
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			var ev model.ProgressEvent
			if e := json.Unmarshal(sc.Bytes(), &ev); e != nil {
				res <- result{nil, e}
				return
			}
			evs = append(evs, ev)
		}
		res <- result{evs, sc.Err()}
	}()

	runErr := NewJSONProgress().Run(updates, func() {})
	w.Close()
	os.Stdout = orig

	out := <-res
	if out.err != nil {
		t.Fatalf("decode: %v", out.err)
	}
	if runErr == nil || runErr.Error() != "boom" {
		t.Errorf("Run: want error %q, got %v", "boom", runErr)
	}
	return out.events
}
