// Package collect drives the collection-creation flows by shelling
// `python -m get_sybers_dxdfir.collection` (the magic-byte classify + SHA-1 hash
// stay the Python detectors, the source of truth) and translating its
// ::dxdfir:: progress sentinels into the shared model.Update stream both
// presenters consume.
package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/get-sybers/dx_dfir/go/internal/model"
	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
)

const tailCap = 300

// Runner drives one collection operation and streams its progress.
type Runner struct {
	Repo   *repo.Repo
	Python string
	Title  string
}

type state struct {
	title string
	start time.Time
	phase string // "classify" | "hash"

	// classify
	cDone, cTotal int
	tallyOrder    []string
	tally         map[string]int
	skips         int
	decisions     []string

	// hash
	hDone, hTotal    int64
	hFileIdx, hFileN int
	hCur             string
	files            []string
}

func newState(title string) *state {
	return &state{title: title, start: time.Now(), tally: map[string]int{}}
}

// Sort runs `collection sort` (classify phase), then hashes when asked.
func (r *Runner) Sort(ctx context.Context, name string, dryRun, doHash bool) <-chan model.Update {
	updates := make(chan model.Update, 64)
	go func() {
		defer close(updates)
		st := newState(r.Title)
		st.phase = "classify"
		st.send(ctx, updates)
		args := []string{"sort", name, "--progress"}
		if dryRun {
			args = append(args, "--dry-run")
		}
		sortRes, err := r.streamOp(ctx, updates, st, args)
		if err != nil {
			r.finish(ctx, updates, st, r.sortSummary(sortRes, nil, dryRun), err)
			return
		}
		var hashRes map[string]any
		moved := jsonInt(sortRes, "moved_count")
		if doHash && !dryRun && moved > 0 {
			st.phase = "hash"
			hashRes, err = r.streamOp(ctx, updates, st, []string{"hash", name, "--progress"})
		}
		r.finish(ctx, updates, st, r.sortSummary(sortRes, hashRes, dryRun), err)
	}()
	return updates
}

// Register runs `collection register` (create/promote), then hashes when asked.
func (r *Runner) Register(ctx context.Context, name, fromPath string, doHash bool) <-chan model.Update {
	updates := make(chan model.Update, 64)
	go func() {
		defer close(updates)
		st := newState(r.Title)
		st.phase = "classify"
		st.send(ctx, updates)
		args := []string{"register", name}
		if fromPath != "" {
			args = append(args, "--from", fromPath)
		}
		regRes, err := r.streamOp(ctx, updates, st, args)
		if err != nil {
			r.finish(ctx, updates, st, r.registerSummary(regRes, nil), err)
			return
		}
		var hashRes map[string]any
		if doHash {
			st.phase = "hash"
			hashRes, err = r.streamOp(ctx, updates, st, []string{"hash", name, "--progress"})
		}
		r.finish(ctx, updates, st, r.registerSummary(regRes, hashRes), err)
	}()
	return updates
}

// streamOp runs one collection subcommand, folds its sentinels into st (emitting
// a snapshot per sentinel), and returns the final JSON result printed on stdout.
func (r *Runner) streamOp(ctx context.Context, updates chan<- model.Update, st *state, args []string) (map[string]any, error) {
	full := append([]string{"-m", "get_sybers_dxdfir.collection", "--repo-root", r.Repo.Root}, args...)
	plan := run.Plan{Bin: r.Python, Args: full, Dir: r.Repo.Root}
	lines, done := run.Stream(ctx, plan)

	var result map[string]any
	for ln := range lines {
		if s, ok := run.ParseSentinel(ln.Text); ok {
			st.fold(s)
			st.send(ctx, updates)
			continue
		}
		if ln.Stream == "out" {
			var m map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(ln.Text)), &m) == nil {
				result = m
			}
		}
	}
	return result, <-done
}

func (st *state) fold(s run.Sentinel) {
	switch s.Phase {
	case "classify":
		if s.Total > 0 {
			st.cTotal = s.Total
		}
		if s.Action != "" {
			st.cDone = s.Done
			line := s.File + "  -> "
			if s.Action == "moved" {
				line += s.Lane + "/   [" + s.How + "]"
				if _, seen := st.tally[s.Lane]; !seen {
					st.tallyOrder = append(st.tallyOrder, s.Lane)
				}
				st.tally[s.Lane]++
			} else {
				st.skips++
				line += "SKIP   (" + s.How + ")"
			}
			st.decisions = appendCap(st.decisions, line)
		}
	case "hash":
		if s.TotalBytes > 0 {
			st.hTotal = s.TotalBytes
		}
		if s.FileTotal > 0 {
			st.hFileN = s.FileTotal
		}
		if s.DoneBytes > 0 {
			st.hDone = s.DoneBytes
		}
		if s.File != "" && s.FileDone > 0 {
			st.hFileIdx = s.FileDone
			if s.File != st.hCur {
				st.hCur = s.File
				st.files = appendCap(st.files, fmt.Sprintf("RUN  %s", s.File))
			}
		}
	}
}

func (st *state) send(ctx context.Context, updates chan<- model.Update) {
	snap := &model.Snapshot{Title: st.title, Active: st.phase}
	switch st.phase {
	case "classify":
		pct := -1
		if st.cTotal > 0 {
			pct = st.cDone * 100 / st.cTotal
		}
		snap.Overall = model.Overall{LanesDone: st.cDone, LanesTotal: st.cTotal, Pct: pct,
			Detail: fmt.Sprintf("%d/%d files classified   skipped %d", st.cDone, st.cTotal, st.skips)}
		for _, lane := range st.tallyOrder {
			snap.Lanes = append(snap.Lanes, model.Lane{Title: lane, Done: st.tally[lane]})
		}
		snap.Tail = tailOf(st.decisions)
	case "hash":
		pct := -1
		if st.hTotal > 0 {
			pct = int(st.hDone * 100 / st.hTotal)
		}
		rate, eta := st.rateETA()
		detail := fmt.Sprintf("%s/%s   file %d/%d %s", human(st.hDone), human(st.hTotal),
			st.hFileIdx, st.hFileN, st.hCur)
		if rate > 0 {
			detail += fmt.Sprintf("   %s/s   ETA %s", human(int64(rate)), eta)
		}
		snap.Overall = model.Overall{Pct: pct, Detail: detail}
		snap.Tail = tailOf(st.files)
	}
	sendUpdate(ctx, updates, model.Update{Snapshot: snap})
}

func (st *state) rateETA() (float64, string) {
	el := time.Since(st.start).Seconds()
	if el <= 0 || st.hDone <= 0 {
		return 0, "--"
	}
	rate := float64(st.hDone) / el
	if rate <= 0 || st.hTotal <= 0 {
		return rate, "--"
	}
	remain := float64(st.hTotal-st.hDone) / rate
	if remain < 0 {
		remain = 0
	}
	return rate, (time.Duration(remain) * time.Second).String()
}

func (r *Runner) finish(ctx context.Context, updates chan<- model.Update, st *state, summary []string, err error) {
	final := &model.Snapshot{Title: st.title, Active: st.phase, Summary: summary}
	sendUpdate(ctx, updates, model.Update{Snapshot: final, Done: true, Err: err})
}

func (r *Runner) sortSummary(sortRes, hashRes map[string]any, dryRun bool) []string {
	var b []string
	verb := "moved"
	if dryRun {
		verb = "would move"
	}
	b = append(b, fmt.Sprintf("-- %s --", r.Title))
	if sortRes != nil {
		if moved, ok := sortRes["moved"].(map[string]any); ok && len(moved) > 0 {
			b = append(b, fmt.Sprintf("  %s:", verb))
			for _, lane := range sortedKeys(moved) {
				if arr, ok := moved[lane].([]any); ok {
					b = append(b, fmt.Sprintf("    %-14s %d file(s)", lane, len(arr)))
				}
			}
		} else {
			b = append(b, "  nothing to sort (dropzone empty or all skipped)")
		}
		if sk, ok := sortRes["skipped"].([]any); ok && len(sk) > 0 {
			b = append(b, fmt.Sprintf("  skipped in dropzone (%d):", len(sk)))
			for _, e := range sk {
				if pair, ok := e.([]any); ok && len(pair) == 2 {
					b = append(b, fmt.Sprintf("    %v  (%v)", pair[0], pair[1]))
				}
			}
		}
	}
	b = append(b, hashLine(hashRes)...)
	return b
}

func (r *Runner) registerSummary(regRes, hashRes map[string]any) []string {
	var b []string
	b = append(b, fmt.Sprintf("-- %s --", r.Title))
	if regRes != nil {
		if root, ok := regRes["root"].(string); ok {
			b = append(b, "  registered at "+root)
		}
	}
	b = append(b, hashLine(hashRes)...)
	return b
}

func hashLine(hashRes map[string]any) []string {
	if hashRes == nil {
		return nil
	}
	sha, _ := hashRes["sha1"].(string)
	files := jsonInt(hashRes, "files")
	bytes := int64(jsonNum(hashRes, "bytes"))
	if sha == "" {
		return nil
	}
	return []string{fmt.Sprintf("  sha1 %s   %d files   %s   -> .collection.hashes", sha, files, human(bytes))}
}

// ---- helpers ----

func sendUpdate(ctx context.Context, ch chan<- model.Update, u model.Update) {
	select {
	case ch <- u:
	case <-ctx.Done():
	}
}

func appendCap(s []string, v string) []string {
	s = append(s, v)
	if len(s) > tailCap {
		s = s[len(s)-tailCap:]
	}
	return s
}

func tailOf(s []string) []string {
	const n = 40
	if len(s) > n {
		return append([]string(nil), s[len(s)-n:]...)
	}
	return append([]string(nil), s...)
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func jsonInt(m map[string]any, k string) int { return int(jsonNum(m, k)) }

func jsonNum(m map[string]any, k string) float64 {
	if m == nil {
		return 0
	}
	if v, ok := m[k].(float64); ok {
		return v
	}
	return 0
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}
