package collection

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// maxWalks bounds concurrent directory walks. Over a networked evidence store
// per-stat latency dominates, so parallelism is the whole point — but an
// unbounded fan-out across dozens of collections would thrash. 32 is a healthy
// middle ground.
const maxWalks = 32

// GetStatus mirrors `collection status`: the active collection, the registered
// collections and hand-staged unregistered ones (each with per-lane counts and
// the stored SHA-1 rollup), and the dropzone candidates.
func GetStatus(repoRoot string) (Status, error) {
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

// GetLanes mirrors `collection lanes`: one (lane, input_var, dir, count) row per
// lane input, scoped to the collection. Returns ok=false for an invalid name.
func GetLanes(repoRoot, name string) (Lanes, bool) {
	root, ok := collectionDir(repoRoot, name)
	if !ok {
		return Lanes{}, false
	}
	counts := subdirCounts(root)
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

// GetState mirrors `collection state`: registered / detected (unregistered but
// has evidence) / exists, for one name.
func GetState(repoRoot, name string) (State, error) {
	reg, err := readRegistry(repoRoot)
	if err != nil {
		return State{}, err
	}
	root, ok := collectionDir(repoRoot, name)
	s := State{Name: name, Registered: reg.nameSet[name]}
	if !ok {
		return s, nil // invalid name: not registered, cannot exist on disk
	}
	s.Exists = isDir(root)
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

// summarise builds a Summary per name concurrently: per-lane counts (from the
// collection's subdir walk) plus the stored manifest rollup.
func summarise(repoRoot string, names []string) map[string]Summary {
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

			counts := subdirCounts(root)
			lanes := map[string]int{}
			total := 0
			for _, lane := range LANES {
				n := 0
				for _, sub := range lane.Subdirs {
					n += counts[sub]
				}
				lanes[lane.Name] = n
				total += n
			}
			sum := Summary{Name: name, Lanes: lanes, Total: total, Sha1: manifestRollup(root)}

			mu.Lock()
			out[name] = sum
			mu.Unlock()
		}(name, root)
	}
	wg.Wait()
	return out
}

// subdirCounts walks each of the collection's lane subdirs once, concurrently,
// and returns the regular-file count per subdir. Walking each unique subdir once
// (rather than per lane) matches the Python counts while avoiding re-walking a
// subdir shared by several lanes.
func subdirCounts(root string) map[string]int {
	counts := make(map[string]int, len(laneSubdirs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, sub := range laneSubdirs {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			n := countFiles(filepath.Join(root, sub))
			mu.Lock()
			counts[sub] = n
			mu.Unlock()
		}(sub)
	}
	wg.Wait()
	return counts
}

// countFiles counts regular, non-symlink files anywhere beneath dir. WalkDir
// does not follow symlinks (a symlinked dir is a non-dir entry, so it is never
// descended), matching Python's os.walk(followlinks=False) + is_symlink skip.
func countFiles(dir string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable path: skip, like the Python walk
		}
		if d.Type().IsRegular() {
			n++
		}
		return nil
	})
	return n
}

// hasEvidence reports whether a collection dir holds at least one evidence file
// (any regular file except the control files), mirroring _has_evidence. The root
// symlink is resolved first: an external `--from` collection is a symlink to its
// real tree, and WalkDir (unlike Python's os.walk on a symlinked root) will not
// descend a symlink entry. Inner symlinks are still never followed.
func hasEvidence(root string) bool {
	walkRoot := root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		walkRoot = resolved
	}
	control := map[string]bool{markerName: true, logName: true, manifestName: true}
	found := false
	_ = filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if !(filepath.Dir(path) == walkRoot && control[d.Name()]) {
				found = true
				return filepath.SkipAll
			}
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

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
