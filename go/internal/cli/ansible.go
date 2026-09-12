package cli

import (
	playbook "github.com/apenella/go-ansible/v2/pkg/playbook"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// ansiblePlan builds a run.Plan that drives one collection playbook the same way
// the process lanes are driven: localhost/local, ANSIBLE_ROLES_PATH set so the
// roles resolve without the collection being installed, cwd = repo root (so
// ansible.cfg and the roles' repo_root defaults resolve).
//
// The base argv (binary, inventory, connection, --check, playbook path) comes
// from the go-ansible typed builder. The extra vars are deliberately NOT fed
// through AnsiblePlaybookOptions.ExtraVars: that field serializes the whole map
// as ONE JSON --extra-vars blob, which loses the ordered last-wins override
// contract (a user --extra-var must override collection scope vars via
// ansible's last-wins across repeated -e) and breaks "-e @file.yml" values. So
// extraVars are appended manually as ordered, repeated -e KEY=VALUE pairs;
// check adds --check for a dry run.
func ansiblePlan(r *repo.Repo, ap, name string, extraVars []string, check bool) (run.Plan, error) {
	cmd := playbook.NewAnsiblePlaybookCmd(
		playbook.WithBinary(ap),
		playbook.WithPlaybooks(r.Playbook(name)),
		playbook.WithPlaybookOptions(&playbook.AnsiblePlaybookOptions{
			Inventory:  "localhost,",
			Connection: "local",
			Check:      check,
		}),
	)
	argv, err := cmd.Command()
	if err != nil {
		// Cannot happen with a binary and playbook set; keep the CLI's
		// usage-error contract if go-ansible ever starts validating more.
		return run.Plan{}, Fail(2, "building ansible-playbook command: %v", err)
	}
	args := append([]string(nil), argv[1:]...)
	for _, kv := range extraVars {
		args = append(args, "-e", kv)
	}
	return run.Plan{
		Bin:  argv[0],
		Args: args,
		Dir:  r.Root,
		Env:  []string{"ANSIBLE_ROLES_PATH=" + r.RolesPath()},
	}, nil
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
