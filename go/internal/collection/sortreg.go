package collection

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// This file ports the collection sort + register/promote/link mechanics (epic
// #174, phase 4): moving classified evidence into a collection's lane subdirs,
// promoting a dropzone folder, symlinking an external tree, and the registry +
// on-disk-shadow bookkeeping around each — all native Go, byte-compatible with
// get_sybers_dxdfir.collection. The magic-byte classifier lives in classify.go;
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

// SortInto classifies each loose file in the dropzone and moves it into the
// named collection's matching lane subdir (mirrors sort_into). onItem may be nil.
func SortInto(repoRoot, name string, dryRun bool, onItem ItemFn) (SortResult, error) {
	res := SortResult{Moved: map[string][]string{}}
	root, ok := collectionDir(repoRoot, name)
	if !ok {
		return res, fmt.Errorf("invalid collection name %q — use letters/digits then . _ -", name)
	}
	if !isDir(root) {
		return res, fmt.Errorf("no such collection %q — create it first: dxdfir collection create --name %s", name, name)
	}
	dz := dropzoneRoot(repoRoot)
	_ = os.MkdirAll(dz, 0o755)

	// Only touch the registry when the collection is registered (recordFile /
	// the "sorted" event are no-ops otherwise) — and never on a dry run.
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
	entries, err := os.ReadDir(dz) // sorted by name
	if err != nil {
		return res, err
	}
	for _, e := range entries {
		nm := e.Name()
		if strings.HasPrefix(nm, ".") {
			continue
		}
		p := filepath.Join(dz, nm)
		if e.IsDir() {
			reason := "directory — register as its own collection or move its files up"
			res.Skipped = append(res.Skipped, [2]string{nm + "/", reason})
			note(nm+"/", "", "directory", "skip")
			continue
		}
		subdir, how := Classify(p)
		if subdir == "" {
			res.Skipped = append(res.Skipped, [2]string{nm, how})
			note(nm, "", how, "skip")
			continue
		}
		dest := filepath.Join(root, subdir, nm)
		if pathExists(dest) {
			res.Skipped = append(res.Skipped, [2]string{nm, "already in " + subdir + "/"})
			note(nm, subdir, how, "skip")
			continue
		}
		if !dryRun {
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return res, err
			}
			if err := moveFile(p, dest); err != nil {
				return res, err
			}
			if db != nil {
				recordFile(db, name, root, dest, how)
			}
		}
		res.Moved[subdir] = append(res.Moved[subdir], nm)
		note(nm, subdir, how, "moved")
	}
	if !dryRun && res.MovedCount() > 0 && db != nil {
		logEvent(db, root, name, now(), "sorted", [][2]any{{"moved", res.MovedCount()}, {"skipped", len(res.Skipped)}})
	}
	return res, nil
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
		if isDir(dropzoneRoot(repoRoot)) {
			dzT = resolvePath(filepath.Join(dropzoneRoot(repoRoot), name))
		}
		if dzT != "" && fp == dzT {
			return promote(db, repoRoot, name, onItem)
		}
		if !isDir(fp) {
			return RegisterResult{}, fmt.Errorf("--from path is not an existing directory: %s", fp)
		}
		return linkExternal(db, repoRoot, name, fp)
	}

	if isDir(root) || isSymlink(root) {
		already := registeredIn(db, name)
		if !isRegularFile(filepath.Join(root, markerName)) {
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

// create mirrors _create: make the lane subdirs and register (idempotent).
func create(db *sql.DB, repoRoot, name string) (RegisterResult, error) {
	root, _ := collectionDir(repoRoot, name)
	dirExisted := isDir(root)
	hadMarker := isRegularFile(filepath.Join(root, markerName))
	for _, sub := range laneSubdirs {
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
	dest, _ := collectionDir(repoRoot, name)
	src := filepath.Join(dropzoneRoot(repoRoot), name)
	if !isDir(src) {
		return RegisterResult{}, fmt.Errorf("no dropzone folder at data_store/raw/sort/%s/", name)
	}
	if pathExists(dest) || isSymlink(dest) {
		return RegisterResult{}, fmt.Errorf("collections/%s/ already exists — cannot promote over it", name)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return RegisterResult{}, err
	}
	if err := os.Rename(src, dest); err != nil { // dropzone + collections share a filesystem
		return RegisterResult{}, err
	}
	for _, sub := range laneSubdirs {
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
		subdir, how := Classify(p)
		if subdir != "" {
			target := filepath.Join(dest, subdir, nm)
			if !pathExists(target) {
				if err := moveFile(p, target); err != nil {
					return RegisterResult{}, err
				}
				recordFile(db, name, dest, target, how)
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
				recordFile(db, name, dest, filepath.Join(dest, rel), "manual")
			}
		}
	}
	return RegisterResult{Name: name, Root: dest, Registered: true, Promoted: true}, nil
}

// linkExternal mirrors _link_external: register a collection whose evidence
// lives outside the repo via a directory symlink collections/<name> → target.
func linkExternal(db *sql.DB, repoRoot, name, target string) (RegisterResult, error) {
	if !isDir(target) {
		return RegisterResult{}, fmt.Errorf("target path %s is not an existing directory", target)
	}
	dest, _ := collectionDir(repoRoot, name)
	if pathExists(dest) || isSymlink(dest) {
		return RegisterResult{}, fmt.Errorf("collections/%s/ already exists — remove or rename it first", name)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return RegisterResult{}, err
	}
	if err := os.Symlink(target, dest); err != nil {
		return RegisterResult{}, err
	}
	for _, sub := range laneSubdirs {
		_ = os.MkdirAll(filepath.Join(target, sub), 0o755)
	}
	writeMarker(target, name)
	upsertCollection(db, repoRoot, name, "link", target)
	logEvent(db, target, name, now(), "registered", [][2]any{{"source", "link"}, {"target", target}})
	if rels, _, _, err := evidenceRelpaths(target); err == nil {
		for _, rel := range rels {
			recordFile(db, name, target, filepath.Join(target, rel), "manual")
		}
	}
	_ = os.MkdirAll(dropzoneRoot(repoRoot), 0o755)
	return RegisterResult{Name: name, Root: dest, Registered: true, Promoted: true}, nil
}

// --- helpers ---

// recordFile upserts one files-table row at classify time (sha1 left NULL for
// the hash pass), preserving nothing on conflict but lane/detected_by/size
// (mirrors _record_file). No-op for an unregistered collection.
func recordFile(db *sql.DB, name, root, path, detectedBy string) {
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
	if l := laneFromRelpath(rel); l != "" {
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

// moveFile renames src→dst, falling back to copy+remove across filesystems.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		in.Close()
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		in.Close()
		out.Close()
		return err
	}
	in.Close()
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}

func pathExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func isSymlink(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}
