package cli

import (
	playbook "github.com/apenella/go-ansible/v2/pkg/playbook"

	"github.com/Get-Sybers/DX_DFIR/go/internal/repo"
	"github.com/Get-Sybers/DX_DFIR/go/internal/run"
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
	return ansiblePlanOpts(r, ap, name, extraVars, check, false)
}

// ansiblePlanOpts is ansiblePlan with the extra privilege knob: askBecomePass
// emits --ask-become-pass so ansible prompts once for the sudo password on the
// TTY. We deliberately do NOT set a global Become — only the role's per-task
// `become` escalates (the TLS key lifecycle + docker-engine setup), so the rest
// of the play still runs as the operator. With NOPASSWD sudo the prompt is
// skipped; with a password and a non-interactive (piped) stdin it fails, which
// is the correct, visible outcome.
func ansiblePlanOpts(r *repo.Repo, ap, name string, extraVars []string, check, askBecomePass bool) (run.Plan, error) {
	cmd := playbook.NewAnsiblePlaybookCmd(
		playbook.WithBinary(ap),
		playbook.WithPlaybooks(r.Playbook(name)),
		playbook.WithPlaybookOptions(&playbook.AnsiblePlaybookOptions{
			Inventory:     "localhost,",
			Connection:    "local",
			Check:         check,
			AskBecomePass: askBecomePass,
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
	ap, err := r.AnsiblePlaybook()
	if err != nil {
		return nil, "", Fail(127, "%v", err)
	}
	return r, ap, nil
}
