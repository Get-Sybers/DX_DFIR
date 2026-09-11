package cli

import (
	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// ansiblePlan builds a run.Plan that drives one collection playbook the same way
// the process lanes are driven: localhost/local, ANSIBLE_ROLES_PATH set so the
// roles resolve without the collection being installed, cwd = repo root (so
// ansible.cfg and the roles' repo_root defaults resolve). extraVars are passed
// as repeated -e KEY=VALUE; check adds --check for a dry run.
func ansiblePlan(r *repo.Repo, ap, playbook string, extraVars []string, check bool) run.Plan {
	args := []string{"-i", "localhost,", "-c", "local", r.Playbook(playbook)}
	if check {
		args = append(args, "--check")
	}
	for _, kv := range extraVars {
		args = append(args, "-e", kv)
	}
	return run.Plan{
		Bin:  ap,
		Args: args,
		Dir:  r.Root,
		Env:  []string{"ANSIBLE_ROLES_PATH=" + r.RolesPath()},
	}
}

// ansibleRepo resolves both the repo and the ansible-playbook binary, returning
// the CLI error contract on failure (2 for no repo, 127 for missing tool).
func (e *Env) ansibleRepo() (*repo.Repo, string, error) {
	r, err := e.resolveRepo()
	if err != nil {
		return nil, "", err
	}
	ap, err := repo.AnsiblePlaybook()
	if err != nil {
		return nil, "", Fail(127, "%v", err)
	}
	return r, ap, nil
}
