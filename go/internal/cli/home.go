package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/get-sybers/dx_dfir/go/internal/collection"
	"github.com/get-sybers/dx_dfir/go/internal/health"
	"github.com/get-sybers/dx_dfir/go/internal/model"
	"github.com/get-sybers/dx_dfir/go/internal/plain"
	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/termdetect"
	"github.com/get-sybers/dx_dfir/go/internal/tui"
)

// runHome renders the landing dashboard for a bare `dxdfir`: a welcome header,
// the environment-readiness panel (the checks that must be green before evidence
// can be processed), the tracked collections, and the staged evidence per lane.
// It is deliberately tolerant — a missing repo, absent python, or an unreadable
// registry each degrade to a visible amber/red row rather than an error exit, so
// the dashboard's whole job (telling the operator what is and isn't ready) still
// works on a half-provisioned host.
func runHome(env *Env, version string) error {
	h := model.Home{Version: version}
	// Best-effort repo detection: nil is a first-class state the checks report on.
	r, _ := repo.Detect(env.RepoRoot)
	if r != nil {
		h.RepoRoot = r.Root
	}

	// Gather the three panels concurrently, each bounded, so the slowest source
	// (the collection scan over the evidence store) caps the whole wait rather
	// than summing with the readiness probes.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); h.Checks = health.Probe(r) }()
	if r != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			h.Collections, h.CollNote, h.CollErr = gatherCollections(r)
		}()
		go func() { defer wg.Done(); h.Lanes = gatherLanes(r) }()
	} else {
		h.CollErr = "repo not located - collections and evidence unavailable"
	}
	wg.Wait()

	if !env.ForcePlain && termdetect.UseTUI(env.ForceTUI) {
		if err := tui.RunHome(h); !errors.Is(err, tui.ErrNoTTY) {
			return err
		}
		// dashboard declined (not a terminal, or too small) — fall through to plain.
	}
	plain.PrintHome(os.Stdout, h)
	return nil
}

// gatherCollections reads the collection registry natively (internal/collection:
// the SQLite registry + concurrent lane walks — no Python round-trip). Returns
// (collections, note, hardErr): note accompanies a list, hardErr replaces it. If
// the native read fails it degrades to an instant listing of the collection
// directory names so tracked collections still show.
func gatherCollections(r *repo.Repo) (colls []model.CollInfo, note, hardErr string) {
	st, err := collection.GetStatus(r.Root)
	if err != nil {
		if fast := fastCollections(r); len(fast) > 0 {
			return fast, "registry unavailable (" + firstNonEmptyLine(err.Error()) + ") - names only; `dxdfir collection list` for detail", ""
		}
		return nil, "", "collection registry unavailable: " + firstNonEmptyLine(err.Error())
	}
	for _, c := range st.Registered {
		colls = append(colls, collInfo(c, st.Active, ""))
	}
	for _, c := range st.Unregistered {
		colls = append(colls, collInfo(c, st.Active, "unregistered"))
	}
	for _, name := range st.Candidates {
		colls = append(colls, model.CollInfo{Name: name, Lanes: "dropzone", Tag: "candidate"})
	}
	return colls, "", ""
}

// fastCollections lists the collection directory names under
// data_store/raw/collections/ without descending into them — the last-resort
// fallback when the native registry read itself fails. Names only; no lane
// counts or active marker.
func fastCollections(r *repo.Repo) []model.CollInfo {
	entries, err := os.ReadDir(r.Path("data_store", "raw", "collections"))
	if err != nil {
		return nil
	}
	var out []model.CollInfo
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue // skip the .registry.db and other dotfiles
		}
		// Total -1 / empty Lanes => "unknown", so renderers don't imply 0 files.
		out = append(out, model.CollInfo{Name: e.Name(), Total: -1})
	}
	return out
}

func collInfo(c collSummary, active, tag string) model.CollInfo {
	sha := ""
	if c.Sha1 != nil && *c.Sha1 != "" {
		sha = trunc(*c.Sha1, 12)
	}
	return model.CollInfo{
		Name:   c.Name,
		Total:  c.Total,
		Lanes:  laneDetail(c.Lanes),
		Sha1:   sha,
		Active: c.Name == active,
		Tag:    tag,
	}
}

// gatherLanes counts staged evidence per processing lane over data_store/raw/,
// reusing the same lane definitions `list lanes` prints.
func gatherLanes(r *repo.Repo) []model.LaneCount {
	raw := r.Path("data_store", "raw")
	out := make([]model.LaneCount, 0, len(evidenceLanes))
	for _, lane := range evidenceLanes {
		count := 0
		for _, sub := range lane.subs {
			d := filepath.Join(raw, sub)
			if dirExists(d) {
				count += countFilesByExt(d, lane.exts)
			}
		}
		out = append(out, model.LaneCount{
			Name:   lane.name,
			Count:  count,
			Loc:    strings.Join(lane.subs, ", ") + "/",
			Staged: count > 0,
		})
	}
	return out
}

func firstNonEmptyLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			return t
		}
	}
	return s
}
