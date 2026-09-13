package collection

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// touch creates an empty file, making parent dirs as needed.
func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// seedRegistry writes a minimal .registry.db with the collections table and the
// given registered rows (name -> selected), matching the schema the Python
// writer uses for the columns this reader reads.
func seedRegistry(t *testing.T, path string, rows map[string]bool) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE collections (
		name TEXT PRIMARY KEY, target_path TEXT, registered_at TEXT,
		source TEXT, sha1 TEXT, files INTEGER, selected INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	for name, sel := range rows {
		s := 0
		if sel {
			s = 1
		}
		if _, err := db.Exec(
			"INSERT INTO collections(name,target_path,registered_at,source,selected) VALUES(?,?,?,?,?)",
			name, "collections/"+name, "2026-01-01T00:00:00Z", "create", s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReader(t *testing.T) {
	repo := t.TempDir()
	colls := filepath.Join(repo, "data_store", "raw", "collections")

	// Registered + selected collection "reg" with a spread of evidence.
	touch(t, filepath.Join(colls, "reg", "pcaps", "a.pcap"))
	touch(t, filepath.Join(colls, "reg", "disk_images", "d1.e01"))
	touch(t, filepath.Join(colls, "reg", "disk_images", "d2.e01"))
	touch(t, filepath.Join(colls, "reg", "memory", "m.raw"))
	// Control files at the collection root must never count as evidence.
	touch(t, filepath.Join(colls, "reg", ".collection"))
	touch(t, filepath.Join(colls, "reg", ".collection.log"))
	if err := os.WriteFile(filepath.Join(colls, "reg", ".collection.hashes"),
		[]byte("# collection_sha1: abc123def456\n/pcaps/a.pcap  deadbeef\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Hand-staged, unregistered collection "hand" (valid name, has evidence).
	touch(t, filepath.Join(colls, "hand", "pcaps", "x.pcap"))
	// A dotfile dir must be ignored as a collection.
	touch(t, filepath.Join(colls, ".junk", "pcaps", "y.pcap"))
	// A dropzone candidate.
	touch(t, filepath.Join(repo, "data_store", "raw", "sort", "cand", "f.bin"))

	seedRegistry(t, filepath.Join(colls, registryName), map[string]bool{"reg": true})

	st, err := GetStatus(repo)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if st.Active != "reg" {
		t.Errorf("active = %q, want reg", st.Active)
	}
	if len(st.Registered) != 1 || st.Registered[0].Name != "reg" {
		t.Fatalf("registered = %+v, want one [reg]", st.Registered)
	}
	reg := st.Registered[0]
	// Per-lane counts: zeek=pcaps(1), evtx=winevt(0), volatility=memory(1),
	// plaso=disk_images(2)+VM_files(0)=2, zimmerman=2, signatures=pcaps(1)+
	// disk_images(2)+memory(1)=4. Total = sum with overlaps = 10.
	want := map[string]int{"zeek": 1, "evtx": 0, "volatility": 1, "plaso": 2, "zimmerman": 2, "signatures": 4}
	for lane, n := range want {
		if reg.Lanes[lane] != n {
			t.Errorf("reg lane %s = %d, want %d", lane, reg.Lanes[lane], n)
		}
	}
	if reg.Total != 10 {
		t.Errorf("reg total = %d, want 10", reg.Total)
	}
	if reg.Sha1 == nil || *reg.Sha1 != "abc123def456" {
		t.Errorf("reg sha1 = %v, want abc123def456", reg.Sha1)
	}
	if len(st.Unregistered) != 1 || st.Unregistered[0].Name != "hand" {
		t.Errorf("unregistered = %+v, want one [hand]", st.Unregistered)
	}
	if len(st.Candidates) != 1 || st.Candidates[0] != "cand" {
		t.Errorf("candidates = %v, want [cand]", st.Candidates)
	}

	// Lanes: one row per (lane, input_var) pair, signatures has three subdirs.
	ln, ok := GetLanes(repo, "reg")
	if !ok {
		t.Fatal("GetLanes ok=false for valid name")
	}
	sig := 0
	for _, in := range ln.Inputs {
		if in.Lane == "signatures" {
			sig += in.Count
		}
	}
	if sig != 4 {
		t.Errorf("signatures lane inputs sum = %d, want 4", sig)
	}

	// State.
	for _, tc := range []struct {
		name                  string
		reg, detected, exists bool
	}{
		{"reg", true, false, true},
		{"hand", false, true, true},
		{"nope", false, false, false},
	} {
		s, err := GetState(repo, tc.name)
		if err != nil {
			t.Fatalf("GetState(%s): %v", tc.name, err)
		}
		if s.Registered != tc.reg || s.Detected != tc.detected || s.Exists != tc.exists {
			t.Errorf("state %s = %+v, want reg=%v detected=%v exists=%v",
				tc.name, s, tc.reg, tc.detected, tc.exists)
		}
	}

	// An invalid name is rejected at the choke point.
	if ValidName("../escape") || ValidName(".") || ValidName("") {
		t.Error("ValidName accepted an invalid name")
	}
	if _, ok := GetLanes(repo, "../escape"); ok {
		t.Error("GetLanes accepted an invalid name")
	}
}

// TestNoRegistry: a repo with no .registry.db yet is not an error — nothing is
// registered, but filesystem-derived unregistered/candidates still work.
func TestNoRegistry(t *testing.T) {
	repo := t.TempDir()
	touch(t, filepath.Join(repo, "data_store", "raw", "collections", "hand", "memory", "m.raw"))
	st, err := GetStatus(repo)
	if err != nil {
		t.Fatalf("GetStatus with no DB: %v", err)
	}
	if st.Active != "" || len(st.Registered) != 0 {
		t.Errorf("expected empty registry, got active=%q registered=%+v", st.Active, st.Registered)
	}
	if len(st.Unregistered) != 1 || st.Unregistered[0].Name != "hand" {
		t.Errorf("unregistered = %+v, want [hand]", st.Unregistered)
	}
}

// eventCount returns the number of rows in the events table for name/event.
func eventCount(t *testing.T, repo, name, event string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(repo, "data_store", "raw", "collections", registryName)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE name=? AND event=?", name, event).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWrites(t *testing.T) {
	repo := t.TempDir()
	colls := filepath.Join(repo, "data_store", "raw", "collections")
	for _, n := range []string{"a", "b"} {
		touch(t, filepath.Join(colls, n, ".collection"))     // marker shadow
		touch(t, filepath.Join(colls, n, "pcaps", "x.pcap")) // evidence
	}
	// "a" starts selected, "b" not.
	seedRegistry(t, filepath.Join(colls, registryName), map[string]bool{"a": true, "b": false})

	// --- Select ---
	if err := Select(repo, "b"); err != nil {
		t.Fatalf("Select(b): %v", err)
	}
	if st, _ := GetStatus(repo); st.Active != "b" {
		t.Errorf("after Select(b) active=%q, want b", st.Active)
	}
	// The on-disk log line must match the Python json.dumps spacing exactly.
	logB, _ := os.ReadFile(filepath.Join(colls, "b", ".collection.log"))
	if !strings.Contains(string(logB), `, "event": "selected"}`) {
		t.Errorf("b .collection.log missing well-formed selected event: %q", logB)
	}
	if eventCount(t, repo, "b", "selected") != 1 {
		t.Errorf("events table: want 1 'selected' row for b, got %d", eventCount(t, repo, "b", "selected"))
	}
	// Selecting an unregistered name is an error.
	if err := Select(repo, "nope"); err == nil {
		t.Error("Select(nope) should error (not registered)")
	}

	// --- Unselect ---
	prev, err := Unselect(repo)
	if err != nil {
		t.Fatalf("Unselect: %v", err)
	}
	if prev != "b" {
		t.Errorf("Unselect prev=%q, want b", prev)
	}
	if st, _ := GetStatus(repo); st.Active != "" {
		t.Errorf("after Unselect active=%q, want empty", st.Active)
	}
	if eventCount(t, repo, "b", "unselected") != 1 {
		t.Error("events table: want 1 'unselected' row for b")
	}
	// Unselect with nothing active is a no-op returning "".
	if p, err := Unselect(repo); err != nil || p != "" {
		t.Errorf("Unselect(none) = (%q, %v), want (\"\", nil)", p, err)
	}

	// --- Unregister ---
	removed, err := Unregister(repo, "a")
	if err != nil {
		t.Fatalf("Unregister(a): %v", err)
	}
	if !removed {
		t.Error("Unregister(a) removed=false, want true")
	}
	s, _ := GetState(repo, "a")
	if s.Registered {
		t.Error("a still registered after Unregister")
	}
	if !s.Exists || !s.Detected {
		t.Errorf("a after Unregister: exists=%v detected=%v, want both true (dir+evidence remain)", s.Exists, s.Detected)
	}
	if isRegularFile(filepath.Join(colls, "a", ".collection")) {
		t.Error("a .collection marker should be removed")
	}
	if !isRegularFile(filepath.Join(colls, "a", ".collection.log")) {
		t.Error("a .collection.log should be preserved")
	}
	if !isRegularFile(filepath.Join(colls, "a", "pcaps", "x.pcap")) {
		t.Error("a evidence should be preserved")
	}
	// Second unregister: no row, no marker => false, no error.
	if r2, err := Unregister(repo, "a"); err != nil || r2 {
		t.Errorf("second Unregister(a) = (%v, %v), want (false, nil)", r2, err)
	}
	// Unregister a non-existent folder is an error.
	if _, err := Unregister(repo, "ghost"); err == nil {
		t.Error("Unregister(ghost) should error (no such collection)")
	}
}

func containsName(cs []Summary, name string) bool {
	for _, c := range cs {
		if c.Name == name {
			return true
		}
	}
	return false
}

// TestSelectMigratesLegacyMarker: a collection present only as a pre-DB
// .collection marker is migrated into the registry by Select (as Python's _db()
// does) and then selectable — the regression Copilot flagged.
func TestSelectMigratesLegacyMarker(t *testing.T) {
	repo := t.TempDir()
	colls := filepath.Join(repo, "data_store", "raw", "collections")
	touch(t, filepath.Join(colls, "other", "pcaps", "o.pcap"))
	seedRegistry(t, filepath.Join(colls, registryName), map[string]bool{"other": false})
	// "leg": a marker (with a registered_at) + evidence, but NO registry row.
	touch(t, filepath.Join(colls, "leg", "memory", "m.raw")) // creates leg/ first
	if err := os.WriteFile(filepath.Join(colls, "leg", ".collection"),
		[]byte("name: leg\nregistered_at: 2020-01-02T03:04:05Z\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Precondition: the read path (no migration) sees leg as unregistered.
	if st, _ := GetStatus(repo); !containsName(st.Unregistered, "leg") {
		t.Fatal("precondition: leg should read as unregistered before select")
	}
	// Select migrates the marker in, then selects it.
	if err := Select(repo, "leg"); err != nil {
		t.Fatalf("Select(leg): %v", err)
	}
	st, _ := GetStatus(repo)
	if st.Active != "leg" {
		t.Errorf("active=%q, want leg", st.Active)
	}
	if !containsName(st.Registered, "leg") {
		t.Errorf("leg should be registered after migrate+select; registered=%+v", st.Registered)
	}
	// The migrated row keeps the marker's registered_at and is sourced "migrated".
	db, _ := sql.Open("sqlite", "file:"+filepath.Join(colls, registryName)+"?mode=ro")
	defer db.Close()
	var regAt, source string
	if err := db.QueryRow("SELECT registered_at, source FROM collections WHERE name='leg'").Scan(&regAt, &source); err != nil {
		t.Fatal(err)
	}
	if regAt != "2020-01-02T03:04:05Z" {
		t.Errorf("migrated registered_at=%q, want the marker's value", regAt)
	}
	if source != "migrated" {
		t.Errorf("migrated source=%q, want migrated", source)
	}
}

// TestSchemaEvolutionAddsSelected: a registry created before the `selected`
// column exists is evolved by openWriteDB so the UPDATE does not fail with
// "no such column: selected".
func TestSchemaEvolutionAddsSelected(t *testing.T) {
	repo := t.TempDir()
	colls := filepath.Join(repo, "data_store", "raw", "collections")
	if err := os.MkdirAll(colls, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(colls, registryName))
	if err != nil {
		t.Fatal(err)
	}
	// Legacy schema: no `selected` column.
	if _, err := db.Exec("CREATE TABLE collections(name TEXT PRIMARY KEY, target_path TEXT, registered_at TEXT, source TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO collections(name,target_path,registered_at,source) VALUES('old','x','t','create')"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if err := Select(repo, "old"); err != nil {
		t.Fatalf("Select(old) on a pre-`selected` registry: %v", err)
	}
	if st, _ := GetStatus(repo); st.Active != "old" {
		t.Errorf("active=%q, want old", st.Active)
	}
}
