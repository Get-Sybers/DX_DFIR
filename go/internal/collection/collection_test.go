package collection

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
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

func TestHash(t *testing.T) {
	repo := t.TempDir()
	colls := filepath.Join(repo, "data_store", "raw", "collections")
	write := func(rel string, data []byte) {
		p := filepath.Join(colls, "h", rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("pcaps/a.pcap", []byte("AAAA"))     // 4 bytes
	write("memory/m.raw", []byte("BBBBBB"))   // 6 bytes
	write(".collection", []byte("name: h\n")) // control file — must NOT be hashed
	seedRegistry(t, filepath.Join(colls, registryName), map[string]bool{"h": true})

	sh := func(b []byte) string { s := sha1.Sum(b); return hex.EncodeToString(s[:]) }
	hA, hM := sh([]byte("AAAA")), sh([]byte("BBBBBB"))
	ds := []string{hA, hM}
	sort.Strings(ds)
	rr := sha1.Sum([]byte(strings.Join(ds, "")))
	wantRollup := hex.EncodeToString(rr[:])

	var startedTotal, chunkSum int64
	var startedFiles, onFileCalls int
	prog := HashProgress{
		OnStart: func(files int, total int64) { startedFiles, startedTotal = files, total },
		OnFile:  func(rel string, size int64, idx, total int) { onFileCalls++ },
		OnChunk: func(n int64) { chunkSum += n },
	}
	rollup, files, total, err := WriteManifest(repo, "h", prog)
	if err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	if rollup != wantRollup {
		t.Errorf("rollup=%s want %s", rollup, wantRollup)
	}
	if files != 2 || total != 10 {
		t.Errorf("files=%d total=%d want 2/10", files, total)
	}
	if startedFiles != 2 || startedTotal != 10 || onFileCalls != 2 || chunkSum != 10 {
		t.Errorf("progress: start(%d,%d) onFile=%d chunkSum=%d want 2/10/2/10", startedFiles, startedTotal, onFileCalls, chunkSum)
	}

	man, _ := os.ReadFile(filepath.Join(colls, "h", manifestName))
	ms := string(man)
	for _, want := range []string{
		"# DX_DFIR collection manifest\n", "# collection: h\n",
		"# collection_sha1: " + wantRollup + "\n", "# files: 2\n", "# columns: sha1  path\n",
	} {
		if !strings.Contains(ms, want) {
			t.Errorf("manifest missing %q", want)
		}
	}
	// body is path-sorted (memory/m.raw < pcaps/a.pcap) as "sha1  path"
	wantBody := hM + "  memory/m.raw\n" + hA + "  pcaps/a.pcap\n"
	if !strings.HasSuffix(ms, wantBody) {
		t.Errorf("manifest body mismatch:\n%q\nwant suffix:\n%q", ms, wantBody)
	}
	if strings.Contains(ms, "  .collection\n") {
		t.Error(".collection control file must not be hashed into the manifest")
	}
	if r := manifestRollup(filepath.Join(colls, "h")); r == nil || *r != wantRollup {
		t.Errorf("manifestRollup reader = %v, want %s", r, wantRollup)
	}

	db, _ := sql.Open("sqlite", "file:"+filepath.Join(colls, registryName)+"?mode=ro")
	defer db.Close()
	var dsha string
	var dfiles int
	if err := db.QueryRow("SELECT sha1, files FROM collections WHERE name='h'").Scan(&dsha, &dfiles); err != nil {
		t.Fatal(err)
	}
	if dsha != wantRollup || dfiles != 2 {
		t.Errorf("collections row: sha1=%s files=%d", dsha, dfiles)
	}
	var lane string
	if err := db.QueryRow("SELECT lane FROM files WHERE collection_name='h' AND path='pcaps/a.pcap'").Scan(&lane); err != nil {
		t.Fatalf("files row for pcaps/a.pcap missing: %v", err)
	}
	if lane != "pcaps" {
		t.Errorf("pcaps/a.pcap lane=%q want pcaps", lane)
	}
	var detail string
	if err := db.QueryRow("SELECT detail FROM events WHERE name='h' AND event='hashed'").Scan(&detail); err != nil {
		t.Fatalf("no hashed event: %v", err)
	}
	if !strings.Contains(detail, `"collection_sha1": "`+wantRollup+`"`) || !strings.Contains(detail, `"files": 2`) {
		t.Errorf("hashed event detail=%s", detail)
	}
	logb, _ := os.ReadFile(filepath.Join(colls, "h", logName))
	if !strings.Contains(string(logb), `"event": "hashed"`) || !strings.Contains(string(logb), `"files": 2}`) {
		t.Errorf("log missing well-formed hashed event: %s", logb)
	}
}

// TestHashUnregistered: hashing a collection not in the registry writes the
// manifest but records NO files rows and NO "hashed" event (mirrors the
// _record_file_hash / write_manifest guards).
func TestHashUnregistered(t *testing.T) {
	repo := t.TempDir()
	colls := filepath.Join(repo, "data_store", "raw", "collections")
	p := filepath.Join(colls, "u", "pcaps", "x.pcap")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("zzz"), 0o644); err != nil {
		t.Fatal(err)
	}
	seedRegistry(t, filepath.Join(colls, registryName), map[string]bool{}) // DB exists, "u" not in it

	rollup, files, _, err := WriteManifest(repo, "u", HashProgress{})
	if err != nil {
		t.Fatalf("WriteManifest(unregistered): %v", err)
	}
	if files != 1 || rollup == "" {
		t.Errorf("files=%d rollup=%q", files, rollup)
	}
	if !isRegularFile(filepath.Join(colls, "u", manifestName)) {
		t.Error("manifest should still be written for an unregistered collection")
	}
	db, _ := sql.Open("sqlite", "file:"+filepath.Join(colls, registryName)+"?mode=ro")
	defer db.Close()
	var n int
	db.QueryRow("SELECT COUNT(*) FROM files WHERE collection_name='u'").Scan(&n)
	if n != 0 {
		t.Errorf("unregistered collection must record no files rows, got %d", n)
	}
	db.QueryRow("SELECT COUNT(*) FROM events WHERE name='u'").Scan(&n)
	if n != 0 {
		t.Errorf("unregistered collection must record no events, got %d", n)
	}
}

func TestClassify(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ewf := append([]byte{0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00, 0x00}, []byte{0x01, 0x00}...) // EVF hdr + seg=1
	cases := []struct {
		file       string
		data       []byte
		wantSubdir string
		wantBy     string
	}{
		{"cap.bin", []byte{0xa1, 0xb2, 0xc3, 0xd4, 0x00}, "pcaps", "magic"},   // pcap magic
		{"img.e01", ewf, "disk_images", "magic"},                              // EWF magic (seg 1)
		{"vm.kdmv", []byte("KDMV____"), "VM_files", "magic"},                  // VMDK sparse magic
		{"log.evtx", []byte("ElfFile\x00"), "logs/winevt", "ext"},             // evtx by ext
		{"dump.mem", []byte("no magic here"), "memory", "ext"},                // memory by ext
		{"disk.e01x", []byte("no magic"), "", "unknown"},                      // .e01x: no magic, no ext claim
		{"raw.raw", []byte("headerless"), "", "ambiguous:disk_images,memory"}, // .raw: disk (ext) + memory (ext)
		{"notes.txt", []byte("hello"), "", "unknown"},                         // nothing recognises it
	}
	for _, c := range cases {
		sub, by := Classify(mk(c.file, c.data))
		if sub != c.wantSubdir || by != c.wantBy {
			t.Errorf("Classify(%s) = (%q, %q), want (%q, %q)", c.file, sub, by, c.wantSubdir, c.wantBy)
		}
	}
}

func TestSortRegisterPromoteLink(t *testing.T) {
	repo := t.TempDir()
	colls := filepath.Join(repo, "data_store", "raw", "collections")
	dz := filepath.Join(repo, "data_store", "raw", "sort")
	stage := func(p string, data []byte) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pcap := []byte{0xa1, 0xb2, 0xc3, 0xd4, 0x01, 0x02}

	// --- promote: a dropzone folder with a loose pcap + a hand-staged memory file ---
	stage(filepath.Join(dz, "promoted", "capture.bin"), pcap)              // loose, classifies to pcaps by magic
	stage(filepath.Join(dz, "promoted", "memory", "m.mem"), []byte("mem")) // already in a lane
	rr, err := Register(repo, "promoted", filepath.Join(dz, "promoted"), "manual", nil)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if !rr.Promoted {
		t.Error("promote: Promoted=false")
	}
	if !isRegularFile(filepath.Join(colls, "promoted", "pcaps", "capture.bin")) {
		t.Error("promote: loose pcap not moved into pcaps/")
	}
	db, _ := sql.Open("sqlite", "file:"+filepath.Join(colls, registryName)+"?mode=ro")
	assertRow := func(q string, args ...any) int {
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if assertRow("SELECT COUNT(*) FROM collections WHERE name='promoted' AND source='promote'") != 1 {
		t.Error("promote: no registry row with source=promote")
	}
	if assertRow("SELECT COUNT(*) FROM files WHERE collection_name='promoted'") != 2 {
		t.Error("promote: expected 2 files rows (moved pcap + hand-staged memory)")
	}
	if assertRow("SELECT COUNT(*) FROM events WHERE name='promoted' AND event='registered'") != 1 {
		t.Error("promote: no 'registered' event")
	}
	db.Close()

	// --- sort: drop a loose evtx into the dropzone, sort into the registered coll ---
	stage(filepath.Join(dz, "win.evtx"), []byte("ElfFile\x00"))
	sr, err := SortInto(repo, "promoted", false, nil)
	if err != nil {
		t.Fatalf("sort: %v", err)
	}
	if len(sr.Moved["logs/winevt"]) != 1 {
		t.Errorf("sort: evtx not moved to logs/winevt; moved=%v", sr.Moved)
	}
	if !isRegularFile(filepath.Join(colls, "promoted", "logs/winevt", "win.evtx")) {
		t.Error("sort: evtx not on disk in logs/winevt/")
	}
	db, _ = sql.Open("sqlite", "file:"+filepath.Join(colls, registryName)+"?mode=ro")
	if assertRow("SELECT COUNT(*) FROM events WHERE name='promoted' AND event='sorted'") != 1 {
		t.Error("sort: no 'sorted' event")
	}
	db.Close()

	// --- link: register an external dir via symlink ---
	ext := filepath.Join(repo, "external_evidence")
	stage(filepath.Join(ext, "pcaps", "e.pcap"), pcap)
	if _, err := Register(repo, "linked", ext, "manual", nil); err != nil {
		t.Fatalf("link: %v", err)
	}
	if !isSymlink(filepath.Join(colls, "linked")) {
		t.Error("link: collections/linked is not a symlink")
	}
	db, _ = sql.Open("sqlite", "file:"+filepath.Join(colls, registryName)+"?mode=ro")
	defer db.Close()
	var src, target string
	if err := db.QueryRow("SELECT source, target_path FROM collections WHERE name='linked'").Scan(&src, &target); err != nil {
		t.Fatal(err)
	}
	if src != "link" {
		t.Errorf("link: source=%q want link", src)
	}
	if assertRow("SELECT COUNT(*) FROM files WHERE collection_name='linked'") != 1 {
		t.Error("link: external evidence not recorded")
	}
}
