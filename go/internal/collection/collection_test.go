package collection

import (
	"database/sql"
	"os"
	"path/filepath"
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
