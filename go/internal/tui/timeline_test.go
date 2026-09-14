package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadTimeline(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, carSubdir, "zeek-conn")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	// Two object events + one relationship edge, deliberately out of order on disk.
	lines := []string{
		`{"timestamp":"2024-01-01T00:00:01Z","kind":"object","object":"process","hostname":"HOST1","exe":"C:\\evil.exe","command_line":"evil.exe -run"}`,
		`{"timestamp":"2024-01-01T00:00:03Z","kind":"object","object":"flow","hostname":"HOST1","src_ip":"10.0.0.5","src_port":"5000","dest_ip":"93.1.2.3","dest_port":"443","application_protocol":"tls"}`,
		`{"timestamp":"2024-01-01T00:00:02Z","kind":"relationship","source_host":"HOST1","relationship":"connected_to","source_object":"process","target_object":"flow","method":"pid","confidence":"0.9"}`,
		`   `,             // blank line: skipped
		`{not valid json`, // malformed: skipped, not fatal
	}
	if err := os.WriteFile(filepath.Join(src, "timeline.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rows, note := readTimeline(root, 100)
	if note != "" {
		t.Fatalf("unexpected note: %q", note)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (blank + malformed skipped), got %d: %+v", len(rows), rows)
	}
	// Newest first: the flow (…:03) leads, the process (…:01) trails.
	if rows[0].object != "flow" || rows[len(rows)-1].object != "process" {
		t.Errorf("wrong order: %q … %q", rows[0].object, rows[len(rows)-1].object)
	}
	if got := rows[len(rows)-1].summary; !strings.Contains(got, "evil.exe -run") {
		t.Errorf("process summary missing command line: %q", got)
	}
	if got := rows[0].summary; !strings.Contains(got, "10.0.0.5:5000") || !strings.Contains(got, "93.1.2.3:443") {
		t.Errorf("flow summary missing endpoints: %q", got)
	}
	var edge *timelineRow
	for i := range rows {
		if rows[i].kind == "relationship" {
			edge = &rows[i]
		}
	}
	if edge == nil {
		t.Fatal("relationship edge not read")
	}
	if !strings.Contains(edge.object, "connected_to") {
		t.Errorf("edge object should name the verb: %q", edge.object)
	}
}

func TestReadTimelineDegrades(t *testing.T) {
	if _, note := readTimeline(t.TempDir(), 100); note == "" {
		t.Error("want a note when no timeline.jsonl exists")
	}
	if _, note := readTimeline("", 100); note == "" {
		t.Error("want a note when repo root is unlocated")
	}
}

func TestReadElasticEnv(t *testing.T) {
	root := t.TempDir()
	envDir := filepath.Join(root, "docker", "elastic")
	if err := os.MkdirAll(envDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "# creds\nexport ELASTIC_PASSWORD=\"s3cret\"\nELASTICSEARCH_USERNAME='sleuth'\n"
	if err := os.WriteFile(filepath.Join(envDir, ".env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	user, pass, ok := readElasticEnv(root)
	if !ok || user != "sleuth" || pass != "s3cret" {
		t.Fatalf("got user=%q pass=%q ok=%v", user, pass, ok)
	}

	// No file → not ok, default user, empty pass.
	if _, _, ok := readElasticEnv(t.TempDir()); ok {
		t.Error("want ok=false when .env is absent")
	}
}
