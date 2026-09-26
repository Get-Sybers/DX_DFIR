package lanes

import (
	"os"
	"path/filepath"
	"testing"
)

func touch(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveNamesAliasesAndGroups(t *testing.T) {
	cases := map[string][]string{
		"zeek":           {"zeek"},
		"gowindowlicker": {"gowindowlicker"},
		"evtx":           {"gowindowlicker"}, // the retired lane name
		"windowlicker":   {"gowindowlicker"}, // the image alias
		"lick":           {"gowindowlicker"},
		"godaemonhunter": {"godaemonhunter"},
		"daemonhunter":   {"godaemonhunter"},
		"hunt":           {"godaemonhunter"},
		"anamnesis":      {"anamnesis"},
		"memory":         {"anamnesis"},
		"plaso":          {"plaso"},
		"log2timeline":   {"plaso"},
		"signatures":     {"signatures"},
		"godfir-toolz":   {"gowindowlicker", "godaemonhunter"},
		"all":            {"zeek", "gowindowlicker", "godaemonhunter", "anamnesis", "plaso", "signatures"},
	}
	for word, want := range cases {
		got, ok := Resolve(word)
		if !ok {
			t.Fatalf("%q: not a lane word", word)
		}
		if len(got) != len(want) {
			t.Fatalf("%q: got %v, want %v", word, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q: got %v, want %v", word, got, want)
			}
		}
	}
	if _, ok := Resolve("my-case"); ok {
		t.Fatal("a collection name resolved as a lane")
	}
	for _, s := range Specs {
		if _, ok := SpecByName(s.Name); !ok {
			t.Fatalf("%s: SpecByName misses its own name", s.Name)
		}
	}
}

func TestOutDirScopesToTheCollection(t *testing.T) {
	s, _ := SpecByName("gowindowlicker")
	if got := s.outDir("/r", ""); got != filepath.Join("/r", "data_store", "processed", "windowlicker") {
		t.Fatal(got)
	}
	if got := s.outDir("/r", "case-a"); got != filepath.Join("/r", "data_store", "processed", "windowlicker", "case-a") {
		t.Fatal(got)
	}
	// the detection lane nests the collection under each sub-tool: its dir is always the leaf
	d, _ := SpecByName("signatures")
	if got := d.outDir("/r", "case-a"); got != filepath.Join("/r", "data_store", "processed", "detections") {
		t.Fatal(got)
	}
}

// The done markers each tool writes, counted at any depth of the
// processed/<tool>/[<collection>/]<host>/… tree — never inside staging.
func TestCountDoneReadsTheToolLeafLayout(t *testing.T) {
	root := t.TempDir()
	p := func(parts ...string) string {
		return filepath.Join(append([]string{root, "data_store", "processed"}, parts...)...)
	}

	touch(t, p("zeek", "case-a", "cap1", "conn.json"), 3)
	touch(t, p("zeek", "case-a", "cap1", "zeek.jsonl"), 3)
	touch(t, p("zeek", "case-a", "cap2", "conn.json"), 3) // still running: no index yet

	touch(t, p("windowlicker", "case-a", "goevtx", "HOST01", "Security.evtx", "goevtx.jsonl"), 3)
	touch(t, p("windowlicker", "case-a", "gore", "img.E01", "Windows_System32_config_SYSTEM", "gore.jsonl"), 3)
	touch(t, p("windowlicker", "case-a", "goese", "img.E01", "SRUDB.dat", "NetworkDataUsage.jsonl"), 3) // a table, not an item
	touch(t, p("windowlicker", "case-a", "goese", "img.E01", "SRUDB.dat", "goese.jsonl"), 3)
	touch(t, p("windowlicker", "case-a", "gomft", "img.E01", "MFT", "gomft.jsonl.part"), 3) // being written

	touch(t, p("daemonhunter", "case-a", "knowledge", "srv.E01", "etc_os-release", "gohost.jsonl"), 3)
	touch(t, p("daemonhunter", "case-a", "gojournal", "srv.E01", "var_log_journal_x", "gojournal.jsonl"), 3)

	touch(t, p("anamnesis", "case-a", "dump.raw", "plugins", "processes.jsonl"), 3)
	touch(t, p("anamnesis", "case-a", "dump.raw", "plugins", "net.jsonl"), 3)
	touch(t, p("anamnesis", "case-a", "dump.raw", "anamnesis.log"), 3)

	touch(t, p("log2timeline", "case-a", "img.E01", "img.E01.plaso"), 9)
	touch(t, p("log2timeline", "case-a", "img.E01", "log2timeline.jsonl"), 3)
	touch(t, p("log2timeline", "case-a", "img.E01", "timeline.jsonl"), 3)
	touch(t, p("log2timeline", "case-a", "img2.E01", "img2.E01.plaso"), 40) // still running

	touch(t, p("detections", "suricata", "case-a", "cap1", "suricata.jsonl"), 3)
	touch(t, p("detections", "hayabusa", "case-a", "HOST01", "hayabusa.jsonl"), 3)
	touch(t, p("detections", "yara", "case-a", "img.E01", "scan.jsonl"), 3)

	// staging is never counted
	touch(t, p("_extracted", "case-a", "img.E01", "export", "Windows", "gore.jsonl"), 3)
	touch(t, p("windowlicker", "case-a", "_extracted", "x", "goevtx.jsonl"), 3)

	want := map[string]int{
		"zeek": 1, "gowindowlicker": 3, "godaemonhunter": 2, "anamnesis": 2, "plaso": 1, "signatures": 3,
	}
	for name, n := range want {
		s, _ := SpecByName(name)
		if got := s.countDone(s.outDir(root, "case-a"), "case-a"); got != n {
			t.Errorf("%s: done = %d, want %d", name, got, n)
		}
		// a loose run counts from the leaf, where the scoped folders also sit
		if got := s.countDone(s.outDir(root, ""), ""); got != n {
			t.Errorf("%s (leaf): done = %d, want %d", name, got, n)
		}
	}
	// the plaso heartbeat follows the biggest storage file, wherever it sits
	ps, _ := SpecByName("plaso")
	if got := largestFileMatching(ps.outDir(root, "case-a"), func(n string) bool { return filepath.Ext(n) == ".plaso" }); got != 40 {
		t.Errorf("plaso heartbeat = %d, want 40", got)
	}
	if got := activeLog(ps, ps.outDir(root, "case-a")); got != "" {
		t.Errorf("plaso active log = %q, want none written yet", got)
	}
	as, _ := SpecByName("anamnesis")
	if got := filepath.Base(activeLog(as, as.outDir(root, "case-a"))); got != "anamnesis.log" {
		t.Errorf("anamnesis active log = %q", got)
	}
}
