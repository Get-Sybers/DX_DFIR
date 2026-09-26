package collection

import (
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/get-sybers/dx_dfir/go/internal/fsx"
	"github.com/get-sybers/dx_dfir/go/internal/identify"
)

// This file ports the collection sort + register/promote/link mechanics (epic
// #174, phase 4): moving classified evidence into a collection's lane subdirs,
// promoting a dropzone folder, symlinking an external tree, and the registry +
// on-disk-shadow bookkeeping around each — all native Go, byte-compatible with
// the retired python registry. The magic-byte classifier now lives in internal/identify;
// the SHA-1 manifest (the trailing hash pass) lives in hash.go.

// ItemFn streams one classification decision as it happens: action is "moved",
// "skip", or "directory". subdir/detectedBy match classify()'s outputs.
type ItemFn func(item, subdir, detectedBy, action string)

// SortResult mirrors SortResult: which files moved into which lane subdir, and
// what was skipped (filename, reason).
type SortResult struct {
	Moved   map[string][]string
	Skipped [][2]string
}

// MovedCount is the total files moved across all lanes.
func (s SortResult) MovedCount() int {
	n := 0
	for _, v := range s.Moved {
		n += len(v)
	}
	return n
}

// RegisterResult mirrors the register JSON: the collection name/root and whether
// it was promoted (a --from that resolved to the dropzone or an external dir).
type RegisterResult struct {
	Name       string
	Root       string
	Registered bool
	Promoted   bool
}

// SortInto organises a collection's evidence into canonical lanes WITHIN the
// collection folder, by CONTENT (identify.Classify), descending the whole tree.
// A file's identity is its magic bytes, not its path, so a mislabelled or
// oddly-foldered file is filed by what it really is; whatever nothing claims
// lands in the catch-all lane. A directory that is one multi-file evidence set
// (a VM export with a .vmx, a mobile extraction) moves WHOLE into its lane so its
// parts stay together. If the collection isn't materialised yet but a dropzone
// folder data_store/raw/sort/<name>/ is, it is promoted first, so the command
// works whether evidence was staged in the dropzone or already in the collection.
// onItem may be nil. Mirrors sort_into's contract; the recursion + content-first
// classification are the change.
func SortInto(repoRoot, name string, dryRun bool, onItem ItemFn) (SortResult, error) {
	res := SortResult{Moved: map[string][]string{}}
	tax, err := identify.Load(repoRoot)
	if err != nil {
		return res, err
	}
	root, ok := collectionDir(repoRoot, name)
	if !ok {
		return res, fmt.Errorf("invalid collection name %q — use letters/digits then . _ -", name)
	}
	subdirs := tax.Subdirs()

	// Source to walk: the materialised collection if present, else a dropzone
	// folder sort/<name>/ (promoted into the collection first, unless dry-run).
	src := root
	if !fsx.IsDir(root) && !fsx.IsSymlink(root) {
		dz := filepath.Join(dropzoneRoot(repoRoot), name)
		if !fsx.IsDir(dz) {
			return res, fmt.Errorf("no such collection %q — register it first: dxdfir register %s", name, name)
		}
		if dryRun {
			src = dz // preview the classification from the dropzone
		} else {
			if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
				return res, err
			}
			if err := os.Rename(dz, root); err != nil { // dropzone + collections share a filesystem
				return res, err
			}
			writeMarker(root, name)
		}
	}

	// Only touch the registry when the collection is registered — and never on a
	// dry run.
	var db *sql.DB
	if !dryRun {
		if reg, err := readRegistry(repoRoot); err == nil && reg.nameSet[name] {
			if db, err = openWriteDB(repoRoot); err != nil {
				return res, err
			}
			defer db.Close()
		}
	}

	note := func(item, subdir, how, action string) {
		if onItem != nil {
			onItem(item, subdir, how, action)
		}
	}
	// destRoot receives the moves; the walk reads src (which, off the dry-run
	// path, is root after any promote). Resolve a symlinked (external) source so
	// the walk descends the real tree.
	destRoot := root
	if dryRun {
		destRoot = src
	}
	walkRoot := src
	if resolved, e := filepath.EvalSymlinks(src); e == nil {
		walkRoot = resolved
	}

	// Phase 1 — plan every move from one walk, so moving files into lane subdirs
	// under the same root can't perturb the walk.
	type fileMove struct{ abs, rel, subdir, how string }
	type setMove struct{ abs, dirName, subdir string }
	var files []fileMove
	var sets []setMove
	control := map[string]bool{markerName: true, logName: true, manifestName: true}
	_ = filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || p == walkRoot {
			return nil
		}
		rel, e := filepath.Rel(walkRoot, p)
		if e != nil {
			return nil
		}
		if d.IsDir() {
			if lane := tax.SetLaneForDir(p); lane != nil {
				if !underSubdir(rel, lane.Subdir) {
					sets = append(sets, setMove{p, filepath.Base(p), lane.Subdir})
				}
				return filepath.SkipDir // a set moves whole; don't descend it
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".") || control[rel] {
			return nil
		}
		subdir, how := tax.Classify(p)
		if filepath.Dir(rel) == subdir {
			return nil // already filed directly under its lane
		}
		files = append(files, fileMove{p, rel, subdir, how})
		return nil
	})

	// Phase 2 — execute: whole evidence sets first, then loose files.
	for _, s := range sets {
		dest, derr := safeLaneDest(destRoot, s.subdir, s.dirName)
		if derr != nil {
			res.Skipped = append(res.Skipped, [2]string{s.dirName + "/", derr.Error()})
			note(s.dirName+"/", s.subdir, derr.Error(), "skip")
			continue
		}
		if fsx.Exists(dest) {
			res.Skipped = append(res.Skipped, [2]string{s.dirName + "/", "already in " + s.subdir + "/"})
			note(s.dirName+"/", s.subdir, "set", "skip")
			continue
		}
		if !dryRun {
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return res, err
			}
			if err := fsx.Move(s.abs, dest); err != nil {
				return res, err
			}
			recordSetFiles(db, name, root, dest, subdirs)
		}
		res.Moved[s.subdir] = append(res.Moved[s.subdir], s.dirName+"/")
		note(s.dirName+"/", s.subdir, "set", "moved")
	}
	for _, fm := range files {
		base := filepath.Base(fm.rel)
		dest, derr := safeLaneDest(destRoot, fm.subdir, base)
		if derr != nil {
			res.Skipped = append(res.Skipped, [2]string{fm.rel, derr.Error()})
			note(base, fm.subdir, derr.Error(), "skip")
			continue
		}
		if fsx.Exists(dest) {
			res.Skipped = append(res.Skipped, [2]string{fm.rel, "already in " + fm.subdir + "/"})
			note(base, fm.subdir, fm.how, "skip")
			continue
		}
		if !dryRun {
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return res, err
			}
			if err := fsx.Move(fm.abs, dest); err != nil {
				return res, err
			}
			if db != nil {
				recordFile(db, name, root, dest, fm.how, subdirs)
			}
		}
		res.Moved[fm.subdir] = append(res.Moved[fm.subdir], base)
		note(base, fm.subdir, fm.how, "moved")
	}
	if !dryRun {
		pruneEmptyDirs(root, subdirs)
		if res.MovedCount() > 0 && db != nil {
			logEvent(db, root, name, now(), "sorted", [][2]any{{"moved", res.MovedCount()}, {"skipped", len(res.Skipped)}})
		}
	}
	return res, nil
}

// underSubdir reports whether rel already sits at or under lane subdir sub.
func underSubdir(rel, sub string) bool {
	return rel == sub || strings.HasPrefix(rel, sub+string(filepath.Separator))
}

// recordSetFiles records every evidence file inside a just-moved set folder (now
// at dest under the collection root), so the registry sees them even though the
// set moved as a unit. Best-effort; no-op for an unregistered collection.
func recordSetFiles(db *sql.DB, name, root, dest string, subdirs []string) {
	if db == nil {
		return
	}
	_ = filepath.WalkDir(dest, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		recordFile(db, name, root, p, "set", subdirs)
		return nil
	})
}

// pruneEmptyDirs removes directories left empty after a sort (the old,
// non-canonical folders whose files moved into lanes), skipping the canonical
// lane subdirs and the collection root itself. Best-effort, deepest-first.
func pruneEmptyDirs(root string, subdirs []string) {
	keep := map[string]bool{}
	for _, s := range subdirs {
		keep[filepath.Join(root, s)] = true
	}
	var dirs []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && p != root && !keep[p] {
			dirs = append(dirs, p)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- { // deepest first
		if entries, err := os.ReadDir(dirs[i]); err == nil && len(entries) == 0 {
			_ = os.Remove(dirs[i])
		}
	}
}

// safeLaneDest returns <root>/<subdir>/<name> for a classified move, but refuses
// to write THROUGH a lane subdir that is a symlink (or that otherwise resolves
// outside the collection root). data_store is group-writable, so a hostile
// evidence stager could replace, say, collections/<c>/pcaps with a symlink to
// /etc/cron.d; without this guard the operator's `dxdfir sort` / promote would
// rename an attacker-named, attacker-content file through the link and write
// outside the tree — an arbitrary-write → host-code-execution primitive. An
// externally-linked collection (root itself a legitimate symlink) still works,
// because containment is checked against the RESOLVED root.
func safeLaneDest(root, subdir, name string) (string, error) {
	if name != filepath.Base(name) || name == "." || name == ".." {
		return "", fmt.Errorf("refusing unsafe evidence name %q (not a plain file name)", name)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("collection root unresolvable: %w", err)
	}
	laneDir := filepath.Join(root, subdir)
	fi, err := os.Lstat(laneDir)
	switch {
	case err == nil:
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing to move through symlinked lane dir %q", subdir)
		}
		realLane, err := filepath.EvalSymlinks(laneDir)
		if err != nil {
			return "", err
		}
		if realLane != realRoot && !strings.HasPrefix(realLane, realRoot+string(os.PathSeparator)) {
			return "", fmt.Errorf("lane dir %q resolves outside the collection root", subdir)
		}
	case os.IsNotExist(err):
		// Not created yet: MkdirAll will make a real dir under the resolved root
		// (subdir is a single, constant lane name), so no symlink to traverse.
	default:
		// A safety guard must not move evidence it couldn't verify (e.g. an
		// EACCES on the lane dir) — refuse rather than proceed blind.
		return "", fmt.Errorf("cannot verify lane dir %q: %w", subdir, err)
	}
	return filepath.Join(laneDir, name), nil
}

// Register is the unified register entry point (mirrors register): from=""
// ensures + registers the collection dir; from==dropzone/<name> promotes it;
// from==elsewhere symlinks an external tree. source labels the plain-register
// path (the CLI default is "manual"). onItem streams the promote classify.
func Register(repoRoot, name, fromPath, source string, onItem ItemFn) (RegisterResult, error) {
	if !ValidName(name) {
		return RegisterResult{}, fmt.Errorf("invalid collection name %q — use letters/digits then . _ -", name)
	}
	root, _ := collectionDir(repoRoot, name)
	db, err := openWriteDB(repoRoot)
	if err != nil {
		return RegisterResult{}, err
	}
	defer db.Close()

	if fromPath != "" {
		fp := resolvePath(fromPath)
		dzT := ""
		if fsx.IsDir(dropzoneRoot(repoRoot)) {
			dzT = resolvePath(filepath.Join(dropzoneRoot(repoRoot), name))
		}
		if dzT != "" && fp == dzT {
			return promote(db, repoRoot, name, onItem)
		}
		if !fsx.IsDir(fp) {
			return RegisterResult{}, fmt.Errorf("--from path is not an existing directory: %s", fp)
		}
		return linkExternal(db, repoRoot, name, fp)
	}

	if fsx.IsDir(root) || fsx.IsSymlink(root) {
		already := registeredIn(db, name)
		if !fsx.IsRegularFile(filepath.Join(root, markerName)) {
			writeMarker(root, name)
		}
		if !already {
			upsertCollection(db, repoRoot, name, source, "")
			logEvent(db, root, name, now(), "registered", [][2]any{{"source", source}})
		}
		_ = os.MkdirAll(dropzoneRoot(repoRoot), 0o755)
		return RegisterResult{Name: name, Root: root, Registered: true}, nil
	}
	return create(db, repoRoot, name)
}

// create mirrors _create: make the lane subdirs and register (idempotent). The
// taxonomy is loaded first and its failure returned, so a collection is never
// registered without its lane subdirs.
func create(db *sql.DB, repoRoot, name string) (RegisterResult, error) {
	tax, err := identify.Load(repoRoot)
	if err != nil {
		return RegisterResult{}, err
	}
	root, _ := collectionDir(repoRoot, name)
	dirExisted := fsx.IsDir(root)
	hadMarker := fsx.IsRegularFile(filepath.Join(root, markerName))
	for _, sub := range tax.Subdirs() {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			return RegisterResult{}, err
		}
	}
	if !hadMarker {
		writeMarker(root, name)
		// Match _create exactly, quirk included: registering an already-existing
		// dir logs "registered" with detail {source:"create"} while the row's
		// source is "register"; a fresh create logs "created" with no detail.
		if dirExisted {
			upsertCollection(db, repoRoot, name, "register", "")
			logEvent(db, root, name, now(), "registered", [][2]any{{"source", "create"}})
		} else {
			upsertCollection(db, repoRoot, name, "create", "")
			logEvent(db, root, name, now(), "created", nil)
		}
	}
	_ = os.MkdirAll(dropzoneRoot(repoRoot), 0o755)
	return RegisterResult{Name: name, Root: root, Registered: true}, nil
}

// promote mirrors _promote: move dropzone/<name> into collections/<name>,
// register it, classify loose files at the root into lanes, and record every
// evidence file (including those hand-staged into lane subdirs).
func promote(db *sql.DB, repoRoot, name string, onItem ItemFn) (RegisterResult, error) {
	tax, err := identify.Load(repoRoot)
	if err != nil {
		return RegisterResult{}, err
	}
	subdirs := tax.Subdirs()
	dest, _ := collectionDir(repoRoot, name)
	src := filepath.Join(dropzoneRoot(repoRoot), name)
	if !fsx.IsDir(src) {
		return RegisterResult{}, fmt.Errorf("no dropzone folder at data_store/raw/sort/%s/", name)
	}
	if fsx.Exists(dest) || fsx.IsSymlink(dest) {
		return RegisterResult{}, fmt.Errorf("collections/%s/ already exists — cannot promote over it", name)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return RegisterResult{}, err
	}
	if err := os.Rename(src, dest); err != nil { // dropzone + collections share a filesystem
		return RegisterResult{}, err
	}
	for _, sub := range subdirs {
		_ = os.MkdirAll(filepath.Join(dest, sub), 0o755)
	}
	writeMarker(dest, name)
	upsertCollection(db, repoRoot, name, "promote", "")
	logEvent(db, dest, name, now(), "registered", [][2]any{{"source", "promote"}})

	control := map[string]bool{markerName: true, logName: true, manifestName: true}
	entries, _ := os.ReadDir(dest) // sorted
	for _, e := range entries {
		nm := e.Name()
		if e.IsDir() || control[nm] || strings.HasPrefix(nm, ".") {
			continue
		}
		p := filepath.Join(dest, nm)
		subdir, how := tax.Classify(p)
		if subdir != "" {
			target, derr := safeLaneDest(dest, subdir, nm)
			if derr != nil {
				if onItem != nil {
					onItem(nm, subdir, derr.Error(), "skip")
				}
				continue
			}
			if !fsx.Exists(target) {
				if err := fsx.Move(p, target); err != nil {
					return RegisterResult{}, err
				}
				recordFile(db, name, dest, target, how, subdirs)
			}
			if onItem != nil {
				onItem(nm, subdir, how, "moved")
			}
		} else if onItem != nil {
			onItem(nm, "", how, "skip")
		}
	}
	// Every file already in a lane subdir counts as classified too.
	if rels, _, _, err := evidenceRelpaths(dest); err == nil {
		for _, rel := range rels {
			if !fileRowExists(db, name, rel) {
				recordFile(db, name, dest, filepath.Join(dest, rel), "manual", subdirs)
			}
		}
	}
	return RegisterResult{Name: name, Root: dest, Registered: true, Promoted: true}, nil
}

// linkExternal mirrors _link_external: register a collection whose evidence
// lives outside the repo via a directory symlink collections/<name> → target.
// The taxonomy is loaded before any side effect, so a load failure leaves no
// half-registered symlink behind.
func linkExternal(db *sql.DB, repoRoot, name, target string) (RegisterResult, error) {
	tax, err := identify.Load(repoRoot)
	if err != nil {
		return RegisterResult{}, err
	}
	if !fsx.IsDir(target) {
		return RegisterResult{}, fmt.Errorf("target path %s is not an existing directory", target)
	}
	dest, _ := collectionDir(repoRoot, name)
	if fsx.Exists(dest) || fsx.IsSymlink(dest) {
		return RegisterResult{}, fmt.Errorf("collections/%s/ already exists — remove or rename it first", name)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return RegisterResult{}, err
	}
	if err := os.Symlink(target, dest); err != nil {
		return RegisterResult{}, err
	}
	subdirs := tax.Subdirs()
	for _, sub := range subdirs {
		_ = os.MkdirAll(filepath.Join(target, sub), 0o755)
	}
	writeMarker(target, name)
	upsertCollection(db, repoRoot, name, "link", target)
	logEvent(db, target, name, now(), "registered", [][2]any{{"source", "link"}, {"target", target}})
	if rels, _, _, err := evidenceRelpaths(target); err == nil {
		for _, rel := range rels {
			recordFile(db, name, target, filepath.Join(target, rel), "manual", subdirs)
		}
	}
	_ = os.MkdirAll(dropzoneRoot(repoRoot), 0o755)
	return RegisterResult{Name: name, Root: dest, Registered: true, Promoted: true}, nil
}

// --- helpers ---

// recordFile upserts one files-table row at classify time (sha1 left NULL for
// the hash pass), preserving nothing on conflict but lane/detected_by/size
// (mirrors _record_file). No-op for an unregistered collection.
func recordFile(db *sql.DB, name, root, path, detectedBy string, subdirs []string) {
	if !registeredIn(db, name) {
		return
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return
	}
	var size any
	if fi, e := os.Stat(path); e == nil {
		size = fi.Size()
	}
	var lane any
	if l := laneFromRelpath(rel, subdirs); l != "" {
		lane = l
	}
	_, _ = db.Exec(
		"INSERT INTO files(collection_name, path, lane, detected_by, size, added_at) "+
			"VALUES(?, ?, ?, ?, ?, ?) "+
			"ON CONFLICT(collection_name, path) DO UPDATE SET "+
			"  lane = excluded.lane, detected_by = excluded.detected_by, size = excluded.size",
		name, rel, lane, detectedBy, size, now())
}

func fileRowExists(db *sql.DB, name, rel string) bool {
	var one int
	return db.QueryRow("SELECT 1 FROM files WHERE collection_name = ? AND path = ?", name, rel).Scan(&one) == nil
}

// upsertCollection mirrors _upsert_collection: insert the row or refresh its
// target_path. target defaults to the collection dir; resolve() it as Python does.
func upsertCollection(db *sql.DB, repoRoot, name, source, targetPath string) {
	target := targetPath
	if target == "" {
		target, _ = collectionDir(repoRoot, name)
	}
	target = resolvePath(target)
	_, _ = db.Exec(
		"INSERT INTO collections(name, target_path, registered_at, source) VALUES(?, ?, ?, ?) "+
			"ON CONFLICT(name) DO UPDATE SET target_path = excluded.target_path",
		name, target, now(), source)
}

// writeMarker writes the .collection shadow (best-effort; a read-only symlinked
// target is silently skipped, as the DB is authoritative — mirrors _write_marker).
func writeMarker(root, name string) {
	_ = os.WriteFile(filepath.Join(root, markerName),
		[]byte("name: "+name+"\nregistered_at: "+now()+"\n"), 0o644)
}

// resolvePath mirrors Path.resolve(): absolute + symlinks resolved, tolerant of
// a non-existent path (still absolutised).
func resolvePath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if rp, err := filepath.EvalSymlinks(p); err == nil {
		return rp
	}
	return p
}

// moveFile/pathExists/isSymlink/isDir/isRegularFile moved to internal/fsx
// (fsx.Move/Exists/IsSymlink/IsDir/IsRegularFile) — shared with health, repo and
// the lane walks to come.
