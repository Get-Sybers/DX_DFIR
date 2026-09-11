package lanes

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/get-sybers/dx_dfir/go/internal/model"
	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// LaneRun is one lane to process, with its resolved denominator inputs.
type LaneRun struct {
	Spec       Spec
	InputDirs  []string // absolute dirs to count the denominator from
	InputCount int      // known count (collection-scoped, from Python); <0 => count InputDirs
	ScopeVars  []string // extra "-e var=dir" scoping the lane to a collection
}

// Job runs a set of lanes sequentially and streams progress.
type Job struct {
	Repo      *repo.Repo
	Ansible   string
	Pipeline  string
	Force     bool
	ExtraVars []string
	Runs      []LaneRun
	Title     string

	tick time.Duration
}

const tailLines = 8

// Execute runs the lanes and returns a channel of progress updates. The channel
// is closed after a final Update{Done:true} carrying the aggregate error. A
// single goroutine owns all writes to the channel (no concurrent mutation).
func (j *Job) Execute(ctx context.Context) <-chan model.Update {
	if j.tick == 0 {
		j.tick = 500 * time.Millisecond
	}
	updates := make(chan model.Update, 64)
	go j.run(ctx, updates)
	return updates
}

func (j *Job) run(ctx context.Context, updates chan<- model.Update) {
	lanes := make([]model.Lane, len(j.Runs))
	for i, r := range j.Runs {
		total := r.InputCount
		if total < 0 {
			total = r.Spec.countInputs(r.InputDirs)
		}
		if r.Spec.PluginsPerImage > 0 {
			total *= r.Spec.PluginsPerImage
		}
		lanes[i] = model.Lane{
			ID: r.Spec.Name, Title: r.Spec.Title, Kind: r.Spec.Kind,
			State: model.Queued, Total: total,
		}
	}

	emit := func(active string, tail []string) {
		snap := model.Snapshot{
			Title:  j.Title,
			Lanes:  cloneLanes(lanes),
			Active: active,
			Tail:   tail,
		}
		done := 0
		for _, l := range lanes {
			if l.State == model.Done || l.State == model.Skipped || l.State == model.Failed {
				done++
			}
		}
		snap.Overall = model.Overall{LanesDone: done, LanesTotal: len(lanes), Pct: -1}
		if active != "" {
			snap.Overall.Detail = active
		}
		send(ctx, updates, model.Update{Snapshot: &snap})
	}

	emit("", nil)

	var failed int
	for i := range j.Runs {
		if ctx.Err() != nil {
			break
		}
		if err := j.runLane(ctx, updates, &lanes[i], j.Runs[i], emit); err != nil {
			failed++
		}
	}

	var finalErr error
	if failed > 0 {
		finalErr = fmt.Errorf("%d lane(s) failed", failed)
	}
	if ctx.Err() != nil {
		finalErr = ctx.Err()
	}
	final := model.Snapshot{Title: j.Title, Lanes: cloneLanes(lanes)}
	done := 0
	for _, l := range lanes {
		if l.State == model.Done || l.State == model.Skipped || l.State == model.Failed {
			done++
		}
	}
	final.Overall = model.Overall{LanesDone: done, LanesTotal: len(lanes), Pct: -1}
	send(ctx, updates, model.Update{Snapshot: &final, Done: true, Err: finalErr})
	close(updates)
}

// runLane drives one lane's ansible-playbook, watching the filesystem for
// progress and tailing the long-pole log. Returns non-nil if the lane failed.
func (j *Job) runLane(ctx context.Context, updates chan<- model.Update, lane *model.Lane, lr LaneRun, emit func(string, []string)) error {
	lane.State = model.Running
	lane.Started = time.Now()
	outDir := lr.Spec.outDir(j.Repo.Root, j.Pipeline)
	longPole := lr.Spec.Kind == model.KindHeartbeat || lr.Spec.Name == "volatility"

	plan := run.Plan{
		Bin:  j.Ansible,
		Args: j.ansibleArgs(lr),
		Dir:  j.Repo.Root,
		Env:  []string{"ANSIBLE_ROLES_PATH=" + j.Repo.RolesPath()},
	}
	lines, done := run.Stream(ctx, plan)

	ticker := time.NewTicker(j.tick)
	defer ticker.Stop()

	var tail []string
	refresh := func() {
		lane.Done = lr.Spec.countDone(outDir)
		if lane.Total > 0 && lane.Done > lane.Total {
			lane.Total = lane.Done // outputs can exceed a stale denominator
		}
		switch lr.Spec.Kind {
		case model.KindHeartbeat:
			lane.Cur = biggestMatch(outDir, "plaso", "*.plaso")
			lane.Detail = fmt.Sprintf("%d/%d images · %s", lane.Done, lane.Total, humanElapsed(lane.Started))
		case model.KindSpinner:
			lane.Detail = "scanning · " + humanElapsed(lane.Started)
		default:
			lane.Detail = fmt.Sprintf("%d/%d", lane.Done, lane.Total)
		}
		if longPole {
			if lg := activeLog(lr.Spec, outDir); lg != "" {
				tail = readTail(lg, tailLines, 64*1024)
			}
		}
	}
	refresh()

	active := ""
	if longPole {
		active = lane.ID
	}
	emit(active, tail)

	for {
		select {
		case <-ticker.C:
			refresh()
			emit(active, tail)
		case ln, ok := <-lines:
			if !ok {
				lines = nil
				continue
			}
			if isFatal(ln.Text) {
				lane.Fails = appendCapped(lane.Fails, ln.Text, 12)
			}
		case werr := <-done:
			refresh()
			if werr != nil {
				lane.State = model.Failed
				if run.ExitCode(werr) == 130 {
					lane.Notes = append(lane.Notes, "cancelled")
				}
			} else {
				lane.State = model.Done
			}
			lane.Ended = time.Now()
			emit("", tail)
			if werr != nil {
				return werr
			}
			return nil
		}
	}
}

// ansibleArgs mirrors cli.py._process_lane exactly.
func (j *Job) ansibleArgs(lr LaneRun) []string {
	name := lr.Spec.Name
	args := []string{
		"-i", "localhost,", "-c", "local", j.Repo.ProcessPlaybook(name),
		"-e", "dxdfir_" + name + "_pipeline=" + j.Pipeline,
		"-e", "dxdfir_" + name + "_force=" + boolStr(j.Force),
	}
	for _, kv := range lr.ScopeVars { // collection scope first (an --extra-var can override)
		args = append(args, "-e", kv)
	}
	for _, kv := range j.ExtraVars {
		args = append(args, "-e", kv)
	}
	return args
}

// activeLog returns the newest on-disk tool log for the lane's active item.
func activeLog(s Spec, outDir string) string {
	switch s.Name {
	case "volatility":
		return newestMatch(outDir, "*", "piiat_mem.log")
	case "plaso":
		return newestMatch(outDir, "logs", "*.log")
	default:
		return ""
	}
}

func isFatal(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(l, "fatal:") || strings.HasPrefix(l, "failed:") ||
		strings.Contains(l, "failed=1") || strings.Contains(l, "unreachable=1")
}

func cloneLanes(in []model.Lane) []model.Lane {
	out := make([]model.Lane, len(in))
	copy(out, in)
	for i := range out {
		out[i].Fails = append([]string(nil), in[i].Fails...)
		out[i].Notes = append([]string(nil), in[i].Notes...)
		out[i].Steps = append([]model.Step(nil), in[i].Steps...)
	}
	return out
}

func appendCapped(s []string, v string, cap int) []string {
	for _, x := range s {
		if x == v {
			return s // de-dup
		}
	}
	if len(s) >= cap {
		return s
	}
	return append(s, v)
}

func send(ctx context.Context, ch chan<- model.Update, u model.Update) {
	select {
	case ch <- u:
	case <-ctx.Done():
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func humanElapsed(start time.Time) string {
	if start.IsZero() {
		return "0s"
	}
	return time.Since(start).Round(time.Second).String()
}

// DefaultInputDirs returns the raw/ input dirs for a lane when not scoped.
func DefaultInputDirs(r *repo.Repo, s Spec) []string {
	var out []string
	for _, sub := range s.InputSubdirs {
		out = append(out, filepath.Join(r.Root, "data_store", "raw", sub))
	}
	return out
}
