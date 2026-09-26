package repo

import (
	"os"
	"path/filepath"
	"strings"
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
	// a stale DXDFIR_VENV from an earlier release's shell must not resurrect
	// /opt/dxdfir — the prefix itself or anything beneath it, on a path boundary
	for _, legacy := range []string{"/opt/dxdfir/venv", "/opt/dxdfir", "/opt/dxdfir/", "/opt/dxdfir//venv/"} {
		t.Setenv("DXDFIR_VENV", legacy)
		t.Setenv("PATH", t.TempDir())
		r := fakeRepo(t, true)
		got, err := r.AnsiblePlaybook()
		if err != nil {
			t.Fatal(legacy, err)
		}
		if want := filepath.Join(r.Root, VenvDir, "bin", "ansible-playbook"); got != want {
			t.Fatalf("%s: got %q, want the repo venv %q", legacy, got, want)
		}
	}
	// a sibling path is an ordinary override
	if underLegacyPrefix("/opt/dxdfir-old/venv") {
		t.Fatal("/opt/dxdfir-old is not the retired prefix")
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

// TestRolesPathCarriesTheBuildGalaxy pins the ANSIBLE_ROLES_PATH the front-end
// exports: it overrides ansible.cfg's roles_path, so a play including
// godfir_build (dxdfir build-docker, the lanes' image preflight) resolves the
// submodule's roles only if the variable carries them itself.
func TestRolesPathCarriesTheBuildGalaxy(t *testing.T) {
	r := fakeRepo(t, false)
	got := strings.Split(r.RolesPath(), string(os.PathListSeparator))
	want := []string{
		filepath.Join(r.Root, "ansible", "collections", "get_sybers.dxdfir", "roles"),
		filepath.Join(r.Root, "docker", "GoDFIR-toolz", "roles"),
		filepath.Join(r.Root, ".ansible", "collections", "ansible_collections", "get_sybers", "godfir_toolz", "roles"),
	}
	if len(got) != len(want) {
		t.Fatalf("RolesPath = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("RolesPath[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRolesPathMatchesAnsibleCfg keeps the exported variable and the checkout's
// ansible.cfg roles_path identical, entry for entry: a bare ansible-playbook
// from the repo root and a dxdfir verb must search the same roles in the same
// order, or a role resolves one way and not the other (the godfir_build
// regression).
func TestRolesPathMatchesAnsibleCfg(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "ansible.cfg"))
	if err != nil {
		t.Skipf("no checkout ansible.cfg beside the module: %v", err)
	}
	var cfg string
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "roles_path" {
			cfg = strings.TrimSpace(v)
		}
	}
	if cfg == "" {
		t.Fatal("ansible.cfg sets no roles_path")
	}
	r := &Repo{Root: root}
	want := make([]string, 0, 3)
	for _, rel := range strings.Split(cfg, ":") {
		want = append(want, filepath.Join(root, rel))
	}
	if got := strings.Split(r.RolesPath(), string(os.PathListSeparator)); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("RolesPath() = %v\nansible.cfg roles_path = %v — keep them identical", got, want)
	}
}
