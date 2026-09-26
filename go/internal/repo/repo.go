// Package repo locates the DX_DFIR repository and the interpreters/tools the
// front-end shells out to, mirroring the discovery contract the Python CLI
// established (--repo-root, $DFIR_REPO_ROOT, walk up from cwd) so muscle memory
// and scripts keep working unchanged.
package repo

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/get-sybers/dx_dfir/go/internal/fsx"
)

// CollectionPath is the marker that identifies a DX_DFIR checkout: a directory
// is the repo root iff this path exists beneath it (the same test the retired
// Python CLI used).
const CollectionPath = "ansible/collections/get_sybers.dxdfir"

// Repo is a resolved DX_DFIR checkout.
type Repo struct {
	Root string
}

// Detect resolves the repo root. Order: explicit (--repo-root), $DFIR_REPO_ROOT,
// the current directory and its parents, then the directory of the running
// binary and its parents (so an in-repo build at <repo>/go/dxdfir resolves too).
func Detect(explicit string) (*Repo, error) {
	var candidates []string
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	if v := os.Getenv("DFIR_REPO_ROOT"); v != "" {
		candidates = append(candidates, v)
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, ancestors(cwd)...)
	}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		candidates = append(candidates, ancestors(filepath.Dir(exe))...)
	}
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if fsx.IsDir(filepath.Join(abs, CollectionPath)) {
			return &Repo{Root: abs}, nil
		}
	}
	return nil, fmt.Errorf(
		"could not locate the DX_DFIR repo (no %s found). Pass --repo-root or set $DFIR_REPO_ROOT",
		CollectionPath)
}

// Path joins segments beneath the repo root.
func (r *Repo) Path(parts ...string) string {
	return filepath.Join(append([]string{r.Root}, parts...)...)
}

// CollectionDir is the collection root beneath the repo.
func (r *Repo) CollectionDir() string { return r.Path(CollectionPath) }

// RolesPath is the value for ANSIBLE_ROLES_PATH so a play resolves the roles
// without the collection being installed (the contract the retired Python CLI
// established).
func (r *Repo) RolesPath() string { return r.Path(CollectionPath, "roles") }

// ProcessPlaybook returns the per-source process playbook path.
func (r *Repo) ProcessPlaybook(source string) string {
	return r.Path(CollectionPath, "playbooks", "dxdfir-process-"+source+".yml")
}

// Playbook returns an arbitrary collection playbook path by filename.
func (r *Repo) Playbook(name string) string {
	return r.Path(CollectionPath, "playbooks", name)
}

// AnsiblePlaybook returns the ansible-playbook that drives the collection:
// the first on PATH (scripts/setup-environment.sh installs the pinned
// ansible-core from requirements.txt into the managed venv and shims it onto
// PATH). There is no host python package any more — everything the CLI
// fronts is ansible + the tool containers.
func AnsiblePlaybook() (string, error) {
	if p, err := exec.LookPath("ansible-playbook"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf(
		"ansible-playbook not found. Run scripts/setup-environment.sh (or " +
			"`pip install -r requirements.txt`) — it installs the pinned ansible-core")
}

// Require returns an error if a tool is not on PATH (fail loud, as the retired
// Python CLI did).
func Require(tool string) error {
	if _, err := exec.LookPath(tool); err != nil {
		return fmt.Errorf("required tool not on PATH: %s", tool)
	}
	return nil
}

func ancestors(p string) []string {
	var out []string
	cur := p
	for {
		out = append(out, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return out
}
