package collection

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// This file is the native-Go registry WRITER for the ops that are pure row
// mutations plus their on-disk shadows — select / unselect / unregister (epic
// #174, phase 2). It stays byte-compatible with the Python writer
// (get_sybers_dxdfir.collection): the SQLite registry is authoritative for
// "registered"/"selected", and every mutation is mirrored to the collection's
// .collection.log JSONL and (for select/unselect) the events table, exactly as
// the Python does — so a collection mutated by one side is consistent for the
// other during the transition. Register/sort/hash and the classification that
// backs them remain Python for now (later phases).
//
// NOTE: unlike Python's _db(), this writer does not run the one-shot legacy
// ".collection marker -> DB" migration; the read path (registry.go) already
// treats the DB as the source of truth, and any pre-DB marker is imported the
// next time the Python register/read path touches the repo.

// schemaDDL mirrors the columns get_sybers_dxdfir.collection._SCHEMA creates. It
// is applied (IF NOT EXISTS, so a no-op against a Python-created DB) before a
// write, so a mutation never runs against a half-initialised store.
const schemaDDL = `
CREATE TABLE IF NOT EXISTS collections (
    name          TEXT PRIMARY KEY,
    target_path   TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    source        TEXT NOT NULL,
    sha1          TEXT,
    files         INTEGER,
    selected      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    ts       TEXT NOT NULL,
    event    TEXT NOT NULL,
    detail   TEXT,
    FOREIGN KEY(name) REFERENCES collections(name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_name_ts ON events(name, ts);
CREATE TABLE IF NOT EXISTS files (
    collection_name TEXT NOT NULL,
    path            TEXT NOT NULL,
    lane            TEXT,
    detected_by     TEXT NOT NULL,
    sha1            TEXT,
    size            INTEGER,
    added_at        TEXT NOT NULL,
    PRIMARY KEY (collection_name, path),
    FOREIGN KEY(collection_name) REFERENCES collections(name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_files_lane ON files(collection_name, lane);
`

// Select marks name the active collection, clearing the flag on every other row
// so exactly one is selected. Errors if name is not registered (mirrors
// select_collection's ValueError).
func Select(repoRoot, name string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid collection name %q — use letters/digits then . _ -", name)
	}
	reg, err := readRegistry(repoRoot)
	if err != nil {
		return err
	}
	if !reg.nameSet[name] {
		return fmt.Errorf("cannot select %q — not registered", name)
	}
	db, err := openWriteDB(repoRoot)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE collections SET selected = 0 WHERE selected = 1"); err != nil {
		return err
	}
	if _, err := db.Exec("UPDATE collections SET selected = 1 WHERE name = ?", name); err != nil {
		return err
	}
	ts := now()
	logEventDB(db, name, ts, "selected")
	if root, ok := collectionDir(repoRoot, name); ok {
		logEventFile(root, ts, "selected")
	}
	return nil
}

// Unselect clears the active flag and returns the previously-selected name ("" if
// none). With nothing selected it is a no-op that does not create or touch the DB.
func Unselect(repoRoot string) (string, error) {
	reg, err := readRegistry(repoRoot)
	if err != nil {
		return "", err
	}
	prev := reg.selected
	if prev == "" {
		return "", nil
	}
	db, err := openWriteDB(repoRoot)
	if err != nil {
		return "", err
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE collections SET selected = 0 WHERE selected = 1"); err != nil {
		return "", err
	}
	ts := now()
	logEventDB(db, prev, ts, "unselected")
	if root, ok := collectionDir(repoRoot, prev); ok {
		logEventFile(root, ts, "unselected")
	}
	return prev, nil
}

// Unregister drops the registry row + .collection marker so name is no longer
// tracked; the evidence and .collection.log are left in place. Returns true when
// the collection was actually registered (row or marker present). Errors if the
// collection folder does not exist (mirrors unregister's ValueError). Deleting
// the row cascades its events (foreign_keys ON), so — like the Python — the
// "unregistered" event is written only to the on-disk log, not the DB.
func Unregister(repoRoot, name string) (bool, error) {
	root, ok := collectionDir(repoRoot, name)
	if !ok {
		return false, fmt.Errorf("invalid collection name %q — use letters/digits then . _ -", name)
	}
	// is_dir() (follows a symlinked collection) OR is_symlink() (incl. a dangling one).
	li, lerr := os.Lstat(root)
	isLink := lerr == nil && li.Mode()&os.ModeSymlink != 0
	if !isDir(root) && !isLink {
		return false, fmt.Errorf("no such collection %q", name)
	}
	reg, err := readRegistry(repoRoot)
	if err != nil {
		return false, err
	}
	wasInDB := reg.nameSet[name]
	marker := filepath.Join(root, markerName)
	hadMarker := isRegularFile(marker)
	if !wasInDB && !hadMarker {
		return false, nil
	}
	ts := now()
	logEventFile(root, ts, "unregistered")
	if wasInDB {
		db, err := openWriteDB(repoRoot)
		if err != nil {
			return false, err
		}
		defer db.Close()
		if _, err := db.Exec("DELETE FROM collections WHERE name = ?", name); err != nil {
			return false, err
		}
	}
	if hadMarker {
		_ = os.Remove(marker)
	}
	return true, nil
}

// --- helpers ---

// openWriteDB opens the registry read-write with foreign keys enforced (so a
// row delete cascades its events, as the Python's PRAGMA foreign_keys=ON does)
// and ensures the schema exists.
func openWriteDB(repoRoot string) (*sql.DB, error) {
	if err := os.MkdirAll(collectionsRoot(repoRoot), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+registryPath(repoRoot)+"?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schemaDDL); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// logEventDB appends one detail-less event row; best-effort, like the on-disk log.
func logEventDB(db *sql.DB, name, ts, event string) {
	_, _ = db.Exec("INSERT INTO events(name, ts, event, detail) VALUES(?, ?, ?, NULL)", name, ts, event)
}

// logEventFile appends one JSONL record to the collection's .collection.log,
// byte-for-byte as the Python's _log_event_file does: json.dumps default
// separators (a space after ':' and ','), key order ts then event. Best-effort
// (a read-only symlinked target is silently skipped, matching the Python).
func logEventFile(root, ts, event string) {
	f, err := os.OpenFile(filepath.Join(root, logName), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	tsB, _ := json.Marshal(ts)
	evB, _ := json.Marshal(event)
	_, _ = fmt.Fprintf(f, "{\"ts\": %s, \"event\": %s}\n", tsB, evB)
}

// now is the registry timestamp format: UTC, second precision, trailing Z —
// matching get_sybers_dxdfir.collection._now().
func now() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func isRegularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}
