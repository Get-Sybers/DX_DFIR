package collection

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
// Like Python's _db(), opening the registry for a write also (a) evolves an
// older schema that predates the `selected` column and (b) imports any pre-DB
// ".collection" markers (+ their JSONL logs) into the registry, so a legacy
// collection is registered — and selectable — exactly as it is under Python.

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
// select_collection's ValueError). openWriteDB migrates any legacy .collection
// markers into the registry first, so a pre-DB collection is registered — and
// thus selectable — exactly as the Python's _db() path makes it.
func Select(repoRoot, name string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid collection name %q — use letters/digits then . _ -", name)
	}
	db, err := openWriteDB(repoRoot)
	if err != nil {
		return err
	}
	defer db.Close()
	var one int
	switch err := db.QueryRow("SELECT 1 FROM collections WHERE name = ?", name).Scan(&one); err {
	case nil: // registered (possibly just migrated in)
	case sql.ErrNoRows:
		return fmt.Errorf("cannot select %q — not registered", name)
	default:
		return err
	}
	// Both flag updates in ONE transaction: a crash between them must not leave
	// the registry with nothing selected (parity with the Python's single txn).
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE collections SET selected = 0 WHERE selected = 1"); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec("UPDATE collections SET selected = 1 WHERE name = ?", name); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
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
		// Surface a marker-removal failure rather than swallowing it (parity with
		// the Python's marker.unlink()): the row is already gone, so a silent
		// failure would leave the on-disk shadow inconsistent under a "success".
		if err := os.Remove(marker); err != nil {
			return true, fmt.Errorf("unregistered %q but could not remove its .collection marker: %w", name, err)
		}
	}
	return true, nil
}

// --- helpers ---

// openWriteDB opens the registry read-write with foreign keys enforced (so a
// row delete cascades its events, as the Python's PRAGMA foreign_keys=ON does),
// ensures the schema exists, evolves an older schema missing the `selected`
// column, and imports any legacy .collection markers — mirroring Python's _db().
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
	// Schema evolution: CREATE TABLE IF NOT EXISTS won't add a column to an
	// existing table, so an older registry created before `selected` existed
	// would fail every UPDATE with "no such column: selected".
	if !hasColumn(db, "collections", "selected") {
		if _, err := db.Exec("ALTER TABLE collections ADD COLUMN selected INTEGER NOT NULL DEFAULT 0"); err != nil {
			db.Close()
			return nil, err
		}
	}
	migrateMarkers(db, repoRoot)
	return db, nil
}

// hasColumn reports whether table has a column named col.
func hasColumn(db *sql.DB, table, col string) bool {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err == nil && name == col {
			return true
		}
	}
	return false
}

// migrateMarkers imports pre-DB ".collection" markers (and their .collection.log
// JSONL) into the registry, mirroring get_sybers_dxdfir.collection._migrate_
// markers so upgrading to the SQLite registry keeps every existing case. It only
// touches markers not already represented by a row, so it is idempotent and a
// no-op on an already-migrated store. Best-effort throughout.
func migrateMarkers(db *sql.DB, repoRoot string) {
	root := collectionsRoot(repoRoot)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		marker := filepath.Join(root, name, markerName)
		if !isRegularFile(marker) {
			continue
		}
		var one int
		if db.QueryRow("SELECT 1 FROM collections WHERE name = ?", name).Scan(&one) == nil {
			continue // already in the registry
		}
		regAt := now()
		if data, err := os.ReadFile(marker); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "registered_at:") {
					if v := strings.TrimSpace(line[len("registered_at:"):]); v != "" {
						regAt = v
					}
					break
				}
			}
		}
		target := filepath.Join(root, name)
		if rp, err := filepath.EvalSymlinks(target); err == nil {
			target = rp
		} else if ap, err := filepath.Abs(target); err == nil {
			target = ap
		}
		if _, err := db.Exec(
			"INSERT INTO collections(name, target_path, registered_at, source) VALUES(?, ?, ?, ?)",
			name, target, regAt, "migrated"); err != nil {
			continue
		}
		importEventLog(db, name, filepath.Join(root, name, logName))
	}
}

// importEventLog folds a collection's .collection.log JSONL into the events
// table (ts/event promoted to columns, the rest kept as the detail JSON).
func importEventLog(db *sql.DB, name, logPath string) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		ts, _ := rec["ts"].(string)
		ev, _ := rec["event"].(string)
		delete(rec, "ts")
		delete(rec, "event")
		if ts == "" {
			ts = now()
		}
		if ev == "" {
			ev = "?"
		}
		var detail any
		if len(rec) > 0 {
			if b, err := json.Marshal(rec); err == nil {
				detail = string(b)
			}
		}
		_, _ = db.Exec("INSERT INTO events(name, ts, event, detail) VALUES(?, ?, ?, ?)", name, ts, ev, detail)
	}
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
