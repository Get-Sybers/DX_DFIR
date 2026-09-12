package cli

import (
	"strings"
	"testing"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
)

// flagValue scans args for a flag under any accepted spelling (short, long,
// and long with =VALUE) and returns its value. go-ansible has changed flag
// spellings across v2 minors, so the tests assert semantics, not exact argv.
func flagValue(args []string, spellings ...string) (string, bool) {
	for i, a := range args {
		for _, s := range spellings {
			if a == s && i+1 < len(args) {
				return args[i+1], true
			}
			if strings.HasPrefix(a, s+"=") {
				return strings.TrimPrefix(a, s+"="), true
			}
		}
	}
	return "", false
}

// extraVarPairs returns, in order, the values of every repeated -e pair, and
// the index of the first one (-1 if none).
func extraVarPairs(args []string) ([]string, int) {
	var vals []string
	first := -1
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-e" {
			if first < 0 {
				first = i
			}
			vals = append(vals, args[i+1])
			i++
		}
	}
	return vals, first
}

func indexOf(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func TestAnsiblePlanSemantics(t *testing.T) {
	r := &repo.Repo{Root: "/fake/repo"}
	extra := []string{"scope_var=/coll/a", "user_var=1", "@overrides.yml"}

	plan, err := ansiblePlan(r, "/venv/bin/ansible-playbook", "dxdfir-cleanup.yml", extra, false)
	if err != nil {
		t.Fatalf("ansiblePlan: %v", err)
	}

	if plan.Bin != "/venv/bin/ansible-playbook" {
		t.Errorf("Bin = %q, want the given binary (never go-ansible's bare default)", plan.Bin)
	}
	if plan.Dir != r.Root {
		t.Errorf("Dir = %q, want repo root %q", plan.Dir, r.Root)
	}
	wantEnv := []string{"ANSIBLE_ROLES_PATH=" + r.RolesPath()}
	if len(plan.Env) != 1 || plan.Env[0] != wantEnv[0] {
		t.Errorf("Env = %v, want %v", plan.Env, wantEnv)
	}

	pb := r.Playbook("dxdfir-cleanup.yml")
	pbIdx := indexOf(plan.Args, pb)
	if pbIdx < 0 {
		t.Fatalf("playbook path %q not in args %v", pb, plan.Args)
	}

	if v, ok := flagValue(plan.Args, "-i", "--inventory"); !ok || v != "localhost," {
		t.Errorf("inventory = %q (found=%v), want %q; args %v", v, ok, "localhost,", plan.Args)
	}
	if v, ok := flagValue(plan.Args, "-c", "--connection"); !ok || v != "local" {
		t.Errorf("connection = %q (found=%v), want %q; args %v", v, ok, "local", plan.Args)
	}
	if indexOf(plan.Args, "--check") >= 0 {
		t.Errorf("--check present without check=true: %v", plan.Args)
	}

	vals, firstE := extraVarPairs(plan.Args)
	if len(vals) != len(extra) {
		t.Fatalf("extra var pairs = %v, want %v in order", vals, extra)
	}
	for i := range extra {
		if vals[i] != extra[i] {
			t.Fatalf("extra var order broken: got %v, want %v", vals, extra)
		}
	}
	// The ordered -e pairs must come after every builder-emitted arg (the
	// playbook path is the builder's last arg) so last-wins stays intact.
	if firstE < pbIdx {
		t.Errorf("-e pairs start at %d, before builder args ending at %d: %v", firstE, pbIdx, plan.Args)
	}
}

func TestAnsiblePlanCheckFlag(t *testing.T) {
	r := &repo.Repo{Root: "/fake/repo"}
	plan, err := ansiblePlan(r, "ap", "dxdfir-cleanup.yml", nil, true)
	if err != nil {
		t.Fatalf("ansiblePlan: %v", err)
	}
	if indexOf(plan.Args, "--check") < 0 {
		t.Errorf("--check missing with check=true: %v", plan.Args)
	}
	if vals, _ := extraVarPairs(plan.Args); len(vals) != 0 {
		t.Errorf("unexpected -e pairs with nil extraVars: %v", vals)
	}
}
