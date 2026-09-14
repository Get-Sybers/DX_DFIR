package fsx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPredicates(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "l")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "d")
	if err := os.Symlink(filepath.Join(dir, "nope"), dangling); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")

	// IsDir
	if !IsDir(dir) || IsDir(file) || IsDir(missing) {
		t.Error("IsDir: want dir=true file=false missing=false")
	}
	// IsRegularFile
	if !IsRegularFile(file) || IsRegularFile(dir) || IsRegularFile(missing) {
		t.Error("IsRegularFile: want file=true dir=false missing=false")
	}
	// IsSymlink (the link itself, not its target)
	if !IsSymlink(link) || IsSymlink(file) || IsSymlink(dir) {
		t.Error("IsSymlink: want link=true file=false dir=false")
	}
	// Exists via Lstat — a dangling symlink still exists; a missing path does not.
	if !Exists(file) || !Exists(dangling) || Exists(missing) {
		t.Error("Exists: want file=true dangling-symlink=true missing=false")
	}
}

func TestMove(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "sub", "dst")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Move(src, dst); err != nil {
		t.Fatalf("Move: %v", err)
	}
	if Exists(src) {
		t.Error("Move left the source in place")
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "payload" {
		t.Errorf("Move: dst content = %q, err %v; want %q", got, err, "payload")
	}
}
