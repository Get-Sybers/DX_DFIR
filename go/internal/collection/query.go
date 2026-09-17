package collection

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/get-sybers/dx_dfir/go/internal/fsx"
)

// maxWalks bounds concurrent directory walks. Over a networked evidence store
// per-stat latency dominates, so parallelism is the whole point — but an
// unbounded fan-out across dozens of collections would thrash. 32 is a healthy
// middle ground.
const maxWalks = 32

// CheckStatus mirrors `collection status`: the active collection, the registered
// collections and hand-staged unregistered ones (each with per-lane counts and
// the stored SHA-1 rollup), and the dropzone candidates.
func CheckStatus(repoRoot string) (Status, error) {
	reg, err := readRegistry(repoRoot)
	if err != nil {
		return Status{}, err
	}
	unreg := unregisteredNames(repoRoot, reg.nameSet)

	names := append(append([]string(nil), reg.names...), unreg...)
	summaries := summarise(repoRoot, names)

	st := Status{
		Active:     reg.selected,
		Candidates: dropzoneCandidates(repoRoot),
	}
	for _, n := range reg.names {
		st.Registered = append(st.Registered, summaries[n])
	}
	for _, n := range unreg {
		st.Unregistered = append(st.Unregistered, summaries[n])
	}
	return st, nil
}

// ListLanes mirrors `collection lanes`: one (lane, input_var, dir, count) row per
// lane input, scoped to the collection. Returns ok=false for an invalid name.
func ListLanes(repoRoot, name string) (Lanes, bool) {
	root, ok := collectionDir(repoRoot, name)
	if !ok {
		return Lanes{}, false
	}
	counts := laneCounts(root, evidenceSubdirs(repoRoot))
	out := Lanes{Name: name}
	for _, lane := range LANES {
		for i, sub := range lane.Subdirs {
			out.Inputs = append(out.Inputs, LaneInput{
				Lane:  lane.Name,
				Var:   lane.InputVars[i],
				Dir:   filepath.Join(root, sub),
				Count: counts[sub],
			})
		}
	}
	return out, true
}

// CheckState mirrors `collection state`: registered / detected (unregistered but
// has evidence) / exists, for one name.
func CheckState(repoRoot, name string) (State, error) {
	reg, err := readRegistry(repoRoot)
	if err != nil {
		return State{}, err
	}
	root, ok := collectionDir(repoRoot, name)
	s := State{Name: name, Registered: reg.nameSet[name]}
	if !ok {
		return s, nil // invalid name: not registered, cannot exist on disk
	}
	s.Exists = fsx.IsDir(root)
	// "detected" == in the unregistered set (valid name, not registered, has evidence).
	if !s.Registered {
		for _, u := range unregisteredNames(repoRoot, reg.nameSet) {
			if u == name {
				s.Detected = true
				break
			}
		}
	}
	return s, nil
}

// summarise builds a Summary per name concurrently: per-lane counts (from a
// single walk of the collection, bucketed by the taxonomy's lane subdirs) plus
// the stored manifest rollup.
func summarise(repoRoot string, names []string) map[string]Summary {
	types := evidenceTypesFor(repoRoot)
	subdirs := make([]string, len(types))
	for i, t := range types {
		subdirs[i] = t.subdir
	}
	out := make(map[string]Summary, len(names))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxWalks)
	for _, name := range names {
		root, ok := collectionDir(repoRoot, name)
		if !ok {
			continue
		}
		wg.Add(1)
		go func(name, root string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			counts := laneCounts(root, subdirs)
			// Break the evidence down by identified type, one file → one lane
			// (its most specific subdir), so each is counted once. Grouping by
			// processing lane instead would fold the same file into every lane
			// that reads its subdir (signatures re-reads pcaps/memory/disk).
			var tc []TypeCount
			total := 0
			for _, t := range types {
				if n := counts[t.subdir]; n > 0 {
					tc = append(tc, TypeCount{Label: t.label, Count: n})
					total += n
				}
			}
			sum := Summary{Name: name, Types: tc, Total: total, Sha1: manifestRollup(root)}

			mu.Lock()
			out[name] = sum
			mu.Unlock()
		}(name, root)
	}
	wg.Wait()
	return out
}

// laneCounts walks a collection once and buckets each evidence file into its most
// specific lane subdir (longest-prefix match), so nested lanes — other_raw_data
// and its child other_raw_data/sql — never double-count. Files that fall under no
// lane subdir (e.g. loose at the collection root) are not counted.
func laneCounts(root string, subdirs []string) map[string]int {
	walkRoot := root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		walkRoot = resolved
	}
	counts := make(map[string]int, len(subdirs))
	_ = filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !isEvidenceFile(d) {
			return nil
		}
		rel, e := filepath.Rel(walkRoot, p)
		if e != nil {
			return nil
		}
		if sub := longestLaneSubdir(rel, subdirs); sub != "" {
			counts[sub]++
		}
		return nil
	})
	return counts
}

// longestLaneSubdir returns the most specific lane subdir that rel sits under, or
// "" when rel is under none.
func longestLaneSubdir(rel string, subdirs []string) string {
	best := ""
	for _, s := range subdirs {
		if rel == s || strings.HasPrefix(rel, s+string(filepath.Separator)) {
			if len(s) > len(best) {
				best = s
			}
		}
	}
	return best
}

// isEvidenceFile reports whether a walked entry counts as staged evidence: a
// regular file that is not a dotfile. Dotfiles are placeholders or control, never
// evidence — the `.gitkeep` that keeps an empty lane subdir in git, and the
// collection's own `.collection` / `.collection.log` / `.collection.hashes`. Not
// filtering `.gitkeep` made an empty lane count as one file, so a lane with no
// real evidence showed a phantom "0/1" instead of "0/0".
func isEvidenceFile(d fs.DirEntry) bool {
	return d.Type().IsRegular() && !strings.HasPrefix(d.Name(), ".")
}

// countFiles counts evidence files anywhere beneath dir (dotfiles skipped — see
// isEvidenceFile). WalkDir does not follow symlinks (a symlinked dir is a non-dir
// entry, so it is never descended), matching Python's os.walk(followlinks=False)
// + is_symlink skip.
func countFiles(dir string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable path: skip, like the Python walk
		}
		if isEvidenceFile(d) {
			n++
		}
		return nil
	})
	return n
}

// hasEvidence reports whether a collection dir holds at least one evidence file
// (a regular non-dotfile; the control files and lane-subdir `.gitkeep`s are
// dotfiles, so they do not count). The root symlink is resolved first: an
// external `--from` collection is a symlink to its real tree, and WalkDir (unlike
// Python's os.walk on a symlinked root) will not descend a symlink entry. Inner
// symlinks are still never followed.
func hasEvidence(root string) bool {
	walkRoot := root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		walkRoot = resolved
	}
	found := false
	_ = filepath.WalkDir(walkRoot, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if isEvidenceFile(d) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// unregisteredNames mirrors unregistered(): collections/ subdirs (or symlinks)
// with a valid name, NOT in the registry, that hold evidence. Alpha-sorted.
func unregisteredNames(repoRoot string, registered map[string]bool) []string {
	root := collectionsRoot(repoRoot)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		isDirOrLink := e.IsDir() || e.Type()&fs.ModeSymlink != 0
		if !isDirOrLink || strings.HasPrefix(name, ".") ||
			registered[name] || !ValidName(name) {
			continue
		}
		if hasEvidence(filepath.Join(root, name)) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// dropzoneCandidates mirrors dropzone_candidates(): data_store/raw/sort/ subdirs
// with a valid name holding at least one file (recursive). Sorted by dir order.
func dropzoneCandidates(repoRoot string) []string {
	dz := dropzoneRoot(repoRoot)
	entries, err := os.ReadDir(dz)
	if err != nil {
		return nil
	}
	// os.ReadDir already returns entries sorted by name (matches Python's sorted).
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || strings.HasPrefix(name, ".") || !ValidName(name) {
			continue
		}
		if countFiles(filepath.Join(dz, name)) > 0 {
			out = append(out, name)
		}
	}
	return out
}

// manifestRollup mirrors manifest_rollup(): the stored collection SHA-1 from the
// .collection.hashes header (`# collection_sha1: <sha>`), or nil if never hashed.
func manifestRollup(root string) *string {
	f, err := os.Open(filepath.Join(root, manifestName))
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	const prefix = "# collection_sha1:"
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, prefix) {
			sha := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if sha == "" {
				return nil
			}
			return &sha
		}
	}
	return nil
}
