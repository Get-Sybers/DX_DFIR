// Package collect drives the collection-creation flows (register / promote /
// link / sort, then the SHA-1 hash) entirely in native Go via internal/collection
// (epic #174 phases 1-4) — no `python -m get_sybers_dxdfir.collection` subprocess.
// Each op's progress callbacks are folded into the shared model.Update stream, so
// the termui and plain presenters render identically.
package collect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/get-sybers/dx_dfir/go/internal/collection"
	"github.com/get-sybers/dx_dfir/go/internal/model"
	"github.com/get-sybers/dx_dfir/go/internal/repo"
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

// Sort classifies the dropzone into the collection's lanes (native), then hashes.
func (r *Runner) Sort(ctx context.Context, name string, dryRun, doHash bool) <-chan model.Update {
	updates := make(chan model.Update, 64)
	go func() {
		defer close(updates)
		st := newState(r.Title)
		st.phase = "classify"
		// denominator: the loose (non-dot) entries in the dropzone.
		if entries, err := os.ReadDir(filepath.Join(r.Repo.Root, "data_store", "raw", "sort")); err == nil {
			for _, e := range entries {
				if !strings.HasPrefix(e.Name(), ".") {
					st.cTotal++
				}
			}
		}
		st.send(ctx, updates)
		sr, err := collection.SortInto(r.Repo.Root, name, dryRun, r.classifyItem(ctx, updates, st))
		if err != nil {
			r.finish(ctx, updates, st, r.sortSummary(sr, nil, dryRun), err)
			return
		}
		var hashRes map[string]any
		if doHash && !dryRun && sr.MovedCount() > 0 {
			st.phase = "hash"
			hashRes, err = r.hashNative(ctx, updates, st, name)
		}
		r.finish(ctx, updates, st, r.sortSummary(sr, hashRes, dryRun), err)
	}()
	return updates
}

// Register creates/promotes/links the collection (native), then hashes.
func (r *Runner) Register(ctx context.Context, name, fromPath string, doHash bool) <-chan model.Update {
	updates := make(chan model.Update, 64)
	go func() {
		defer close(updates)
		st := newState(r.Title)
		st.phase = "classify"
		st.send(ctx, updates)
		// "manual" matches the retired CLI's --source default for a plain register.
		rr, err := collection.Register(r.Repo.Root, name, fromPath, "manual", r.classifyItem(ctx, updates, st))
		if err != nil {
			r.finish(ctx, updates, st, r.registerSummary(rr, nil), err)
			return
		}
		var hashRes map[string]any
		if doHash {
			st.phase = "hash"
			hashRes, err = r.hashNative(ctx, updates, st, name)
		}
		r.finish(ctx, updates, st, r.registerSummary(rr, hashRes), err)
	}()
	return updates
}

// classifyItem folds one native classify decision into st and emits a snapshot —
// the same shape the retired ::dxdfir:: classify sentinels produced, so the
// presenters render identically.
func (r *Runner) classifyItem(ctx context.Context, updates chan<- model.Update, st *state) collection.ItemFn {
	return func(item, subdir, how, action string) {
		st.cDone++
		if action == "moved" {
			if _, seen := st.tally[subdir]; !seen {
				st.tallyOrder = append(st.tallyOrder, subdir)
			}
			st.tally[subdir]++
			st.decisions = appendCap(st.decisions, item+"  -> "+subdir+"/   ["+how+"]")
		} else {
			st.skips++
			st.decisions = appendCap(st.decisions, item+"  -> SKIP   ("+how+")")
		}
		st.send(ctx, updates)
	}
}

// hashNative runs the SHA-1 manifest hash in-process (internal/collection —
// epic #174 phase 3) instead of shelling `collection hash`, folding the native
// progress callbacks into the SAME model.Update stream the ::dxdfir:: hash
// sentinels used to drive, so both presenters render identically. Returns the
// {sha1, files, bytes} map the summary builders expect (files/bytes as float64,
// matching the JSON the subprocess used to return).
func (r *Runner) hashNative(ctx context.Context, updates chan<- model.Update, st *state, name string) (map[string]any, error) {
	var emitted int64
	prog := collection.HashProgress{
		OnStart: func(files int, total int64) {
			st.hFileN = files
			st.hTotal = total
			st.send(ctx, updates)
		},
		OnFile: func(rel string, _ int64, idx, _ int) {
			st.hFileIdx = idx + 1
			if rel != "" && rel != st.hCur {
				st.hCur = rel
				st.files = appendCap(st.files, "RUN  "+rel)
			}
			st.send(ctx, updates)
		},
		OnChunk: func(n int64) {
			st.hDone += n
			// Throttle snapshots to ~8 MiB of progress (same cadence the Python
			// --progress sentinels used), so a large file doesn't flood the channel.
			if st.hDone-emitted >= (8 << 20) {
				emitted = st.hDone
				st.send(ctx, updates)
			}
		},
	}
	rollup, files, total, err := collection.WriteManifest(r.Repo.Root, name, prog)
	if err != nil {
		return nil, err
	}
	// One truthful terminal snapshot: hashing complete (done == total, all files).
	st.hDone = total
	st.hFileIdx = files
	st.send(ctx, updates)
	return map[string]any{"sha1": rollup, "files": float64(files), "bytes": float64(total)}, nil
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

func (r *Runner) sortSummary(sr collection.SortResult, hashRes map[string]any, dryRun bool) []string {
	var b []string
	verb := "moved"
	if dryRun {
		verb = "would move"
	}
	b = append(b, fmt.Sprintf("-- %s --", r.Title))
	if sr.MovedCount() > 0 {
		b = append(b, fmt.Sprintf("  %s:", verb))
		for _, lane := range sortedKeysSS(sr.Moved) {
			b = append(b, fmt.Sprintf("    %-14s %d file(s)", lane, len(sr.Moved[lane])))
		}
	} else {
		b = append(b, "  nothing to sort (dropzone empty or all skipped)")
	}
	if len(sr.Skipped) > 0 {
		b = append(b, fmt.Sprintf("  skipped in dropzone (%d):", len(sr.Skipped)))
		for _, sk := range sr.Skipped {
			b = append(b, fmt.Sprintf("    %s  (%s)", sk[0], sk[1]))
		}
	}
	b = append(b, hashLine(hashRes)...)
	return b
}

func (r *Runner) registerSummary(rr collection.RegisterResult, hashRes map[string]any) []string {
	var b []string
	b = append(b, fmt.Sprintf("-- %s --", r.Title))
	if rr.Root != "" {
		b = append(b, "  registered at "+rr.Root)
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

func sortedKeysSS(m map[string][]string) []string {
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
