package repo

import (
	"os"
	"path/filepath"
	"testing"
)

// A checkout marker + a venv with an executable ansible-playbook.
func fakeRepo(t *testing.T, withVenv bool) *Repo {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, CollectionPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if withVenv {
		bin := filepath.Join(root, VenvDir, "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &Repo{Root: root}
}

func TestAnsiblePlaybookPrefersRepoVenv(t *testing.T) {
	t.Setenv("DXDFIR_VENV", "")
	// a PATH ansible-playbook that must NOT win over the checkout's venv
	pathDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pathDir, "ansible-playbook"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir)

	r := fakeRepo(t, true)
	got, err := r.AnsiblePlaybook()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(r.Root, VenvDir, "bin", "ansible-playbook"); got != want {
		t.Fatalf("got %q, want the repo venv %q", got, want)
	}
}

func TestAnsiblePlaybookFallsBackToPATH(t *testing.T) {
	t.Setenv("DXDFIR_VENV", "")
	pathDir := t.TempDir()
	onPath := filepath.Join(pathDir, "ansible-playbook")
	if err := os.WriteFile(onPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir)

	r := fakeRepo(t, false)
	got, err := r.AnsiblePlaybook()
	if err != nil {
		t.Fatal(err)
	}
	if got != onPath {
		t.Fatalf("got %q, want the PATH fallback %q", got, onPath)
	}
}

func TestAnsiblePlaybookHonoursDXDFIRVenv(t *testing.T) {
	venv := t.TempDir()
	bin := filepath.Join(venv, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DXDFIR_VENV", venv)
	t.Setenv("PATH", t.TempDir())

	r := fakeRepo(t, true) // the in-repo venv exists but the override wins
	got, err := r.AnsiblePlaybook()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(bin, "ansible-playbook"); got != want {
		t.Fatalf("got %q, want $DXDFIR_VENV's %q", got, want)
	}
}

func TestAnsiblePlaybookIgnoresALegacyPrefixOverride(t *testing.T) {
	// a stale DXDFIR_VENV from an earlier release's shell must not resurrect /opt/dxdfir
	t.Setenv("DXDFIR_VENV", "/opt/dxdfir/venv")
	t.Setenv("PATH", t.TempDir())
	r := fakeRepo(t, true)
	got, err := r.AnsiblePlaybook()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(r.Root, VenvDir, "bin", "ansible-playbook"); got != want {
		t.Fatalf("got %q, want the repo venv %q", got, want)
	}
}

func TestAnsiblePlaybookMissingNamesTheVenv(t *testing.T) {
	t.Setenv("DXDFIR_VENV", "")
	t.Setenv("PATH", t.TempDir())
	r := fakeRepo(t, false)
	if _, err := r.AnsiblePlaybook(); err == nil {
		t.Fatal("expected an error with no ansible-playbook anywhere")
	}
}
