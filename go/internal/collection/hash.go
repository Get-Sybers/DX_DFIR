package collection

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// This file is the native-Go SHA-1 manifest hasher (epic #174, phase 3), a
// byte-for-byte port of get_sybers_dxdfir.collection.{hash_collection,
// write_manifest}: every evidence file is SHA-1'd, the collection rollup is the
// SHA-1 of every file's hex digest sorted and concatenated (order-independent
// change detection, NOT cryptographic integrity), the .collection.hashes
// manifest is rewritten, and the registry (collections.sha1/files + the per-file
// files rows + a "hashed" event) is updated exactly as the Python does.

// HashProgress carries optional progress hooks so a front-end can render a
// hashing gauge without reimplementing the read loop. Any field may be nil.
type HashProgress struct {
	OnStart func(files int, totalBytes int64)            // once, before hashing
	OnFile  func(rel string, size int64, idx, total int) // before each file
	OnChunk func(n int64)                                // per read chunk
}

// WriteManifest (re)computes a collection's hash manifest, persists it to
// .collection.hashes, updates the per-file registry rows + collections.sha1/
// files, and logs a "hashed" event (when registered). Returns the rollup, the
// file count, and the total bytes hashed. Mirrors write_manifest.
func WriteManifest(repoRoot, name string, p HashProgress) (rollup string, files int, totalBytes int64, err error) {
	root, ok := collectionDir(repoRoot, name)
	if !ok {
		return "", 0, 0, fmt.Errorf("invalid collection name %q — use letters/digits then . _ -", name)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", 0, 0, err
	}

	rels, sizes, total, err := evidenceRelpaths(root)
	if err != nil {
		return "", 0, 0, err
	}
	if p.OnStart != nil {
		p.OnStart(len(rels), total)
	}

	type fileHash struct{ rel, sum string }
	perFile := make([]fileHash, 0, len(rels))
	for idx, rel := range rels {
		if p.OnFile != nil {
			p.OnFile(rel, sizes[rel], idx, len(rels))
		}
		sum, herr := hashFile(filepath.Join(root, rel), p.OnChunk)
		if herr != nil {
			return "", 0, 0, herr
		}
		perFile = append(perFile, fileHash{rel, sum})
	}
	// rels are already path-sorted (manifest order). The rollup sorts the hex
	// digests (NOT the paths) and concatenates them, so it is order-independent.
	digests := make([]string, len(perFile))
	for i, f := range perFile {
		digests[i] = f.sum
	}
	sort.Strings(digests)
	rh := sha1.Sum([]byte(strings.Join(digests, "")))
	rollup = hex.EncodeToString(rh[:])

	ts := now()
	var b strings.Builder
	fmt.Fprintf(&b, "# DX_DFIR collection manifest\n# collection: %s\n# collection_sha1: %s\n# files: %d\n# generated: %s\n# columns: sha1  path\n",
		name, rollup, len(perFile), ts)
	for _, f := range perFile {
		fmt.Fprintf(&b, "%s  %s\n", f.sum, f.rel)
	}
	if err := os.WriteFile(filepath.Join(root, manifestName), []byte(b.String()), 0o644); err != nil {
		return "", 0, 0, err
	}

	db, err := openWriteDB(repoRoot)
	if err != nil {
		return "", 0, 0, err
	}
	defer db.Close()
	// UPDATE runs regardless (a no-op 0-row update for an unregistered collection).
	if _, err := db.Exec("UPDATE collections SET sha1 = ?, files = ? WHERE name = ?", rollup, len(perFile), name); err != nil {
		return "", 0, 0, err
	}
	// Per-file rows and the "hashed" event are written only for a registered
	// collection (matching _record_file_hash / write_manifest's guard; also
	// avoids a files→collections foreign-key violation for an unregistered one).
	if registeredIn(db, name) {
		for _, f := range perFile {
			recordFileHash(db, name, f.rel, f.sum, sizes[f.rel], ts)
		}
		logEvent(db, root, name, ts, "hashed", [][2]any{
			{"collection_sha1", rollup},
			{"files", len(perFile)},
		})
	}
	return rollup, len(perFile), total, nil
}

// evidenceRelpaths returns the collection's evidence files as root-relative
// paths (sorted), their sizes, and the total byte count — the same set
// evidence_files() hashes: regular non-symlink files, symlinked dirs not
// followed, the three control files excluded. The root symlink (external
// --from collections) is resolved so the walk descends into the real tree,
// exactly as Python's os.walk on a symlinked root does.
func evidenceRelpaths(root string) (rels []string, sizes map[string]int64, total int64, err error) {
	walkRoot := root
	if resolved, e := filepath.EvalSymlinks(root); e == nil {
		walkRoot = resolved
	}
	control := map[string]bool{markerName: true, logName: true, manifestName: true}
	sizes = map[string]int64{}
	err = filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, re := filepath.Rel(walkRoot, path)
		if re != nil {
			return nil
		}
		if control[rel] { // only the top-level control files (rel has no separator)
			return nil
		}
		var sz int64
		if info, ie := d.Info(); ie == nil {
			sz = info.Size()
		}
		rels = append(rels, rel)
		sizes[rel] = sz
		total += sz
		return nil
	})
	sort.Strings(rels)
	return rels, sizes, total, err
}

// hashFile returns the SHA-1 hex digest of a file, read in 1 MiB chunks (the
// same chunk size as _hash_file), invoking onChunk with each chunk's length.
func hashFile(path string, onChunk func(int64)) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha1.New()
	buf := make([]byte, 1<<20)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			if onChunk != nil {
				onChunk(int64(n))
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// laneFromRelpath infers the lane a path lives under (mirrors _lane_from_relpath);
// "" means it maps to no lane (stored as NULL).
func laneFromRelpath(rel string) string {
	for _, sub := range laneSubdirs {
		if rel == sub || strings.HasPrefix(rel, sub+"/") {
			return sub
		}
	}
	return ""
}

// recordFileHash upserts one files-table row with its fresh SHA-1 + size,
// preserving an existing detected_by and defaulting new rows to 'manual'
// (mirrors _record_file_hash). Best-effort.
func recordFileHash(db *sql.DB, name, rel, sha1hex string, size int64, ts string) {
	var lane any
	if l := laneFromRelpath(rel); l != "" {
		lane = l
	}
	_, _ = db.Exec(
		"INSERT INTO files(collection_name, path, lane, detected_by, sha1, size, added_at) "+
			"VALUES(?, ?, ?, 'manual', ?, ?, ?) "+
			"ON CONFLICT(collection_name, path) DO UPDATE SET "+
			"  lane = excluded.lane, sha1 = excluded.sha1, size = excluded.size",
		name, rel, lane, sha1hex, size, ts)
}
