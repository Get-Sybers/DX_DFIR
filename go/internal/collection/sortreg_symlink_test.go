package collection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSafeLaneDest_RefusesSymlinkedLaneDir guards the arbitrary-write primitive:
// a lane subdir that is a symlink out of the collection must never be written
// through (it would turn `collection sort` into a host write, e.g. into /etc/cron.d).
func TestSafeLaneDest_RefusesSymlinkedLaneDir(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir() // stands in for /etc/cron.d

	// A normal, real lane subdir is fine.
	if err := os.MkdirAll(filepath.Join(root, "pcaps"), 0o755); err != nil {
		t.Fatal(err)
	}
	dest, err := safeLaneDest(root, "pcaps", "capture.pcap")
	if err != nil {
		t.Fatalf("real lane dir rejected: %v", err)
	}
	if want := filepath.Join(root, "pcaps", "capture.pcap"); dest != want {
		t.Errorf("dest = %q, want %q", dest, want)
	}

	// Replace the lane subdir with a symlink pointing outside the collection.
	if err := os.RemoveAll(filepath.Join(root, "pcaps")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "pcaps")); err != nil {
		t.Fatal(err)
	}
	if _, err := safeLaneDest(root, "pcaps", "capture.pcap"); err == nil {
		t.Fatal("symlinked lane dir was NOT refused — arbitrary-write primitive is open")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("unexpected refusal reason: %v", err)
	}
}

func TestSafeLaneDest_RefusesTraversalName(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "pcaps"), 0o755)
	for _, bad := range []string{"../evil", "a/b", "..", "."} {
		if _, err := safeLaneDest(root, "pcaps", bad); err == nil {
			t.Errorf("name %q was accepted; want refusal", bad)
		}
	}
}
