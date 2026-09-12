package lanes

import (
	"strings"
	"testing"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
)

// laneFlagValue scans args for a flag under any accepted spelling (short,
// long, long=VALUE). go-ansible has changed flag spellings across v2 minors,
// so the tests assert semantics, not exact argv text.
func laneFlagValue(args []string, spellings ...string) (string, bool) {
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

// laneExtraVars returns, in order, the values of every repeated -e pair, and
// the index of the first one (-1 if none).
func laneExtraVars(args []string) ([]string, int) {
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

func laneIndexOf(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func TestAnsibleArgsVarLayering(t *testing.T) {
	j := &Job{
		Repo:     &repo.Repo{Root: "/fake/repo"},
		Ansible:  "/venv/bin/ansible-playbook",
		Pipeline: "sofelk",
		Force:    true,
		// user vars LAST — must win over everything via ansible last-wins
		ExtraVars: []string{"dxdfir_zeek_pipeline=elastic", "user=1"},
	}
	lr := LaneRun{
		Spec:      Spec{Name: "zeek"},
		ScopeVars: []string{"dxdfir_zeek_pcaps_dir=/coll/pcaps", "scope=a"},
	}

	args, err := j.ansibleArgs(lr)
	if err != nil {
		t.Fatalf("ansibleArgs: %v", err)
	}

	pb := j.Repo.ProcessPlaybook("zeek")
	pbIdx := laneIndexOf(args, pb)
	if pbIdx < 0 {
		t.Fatalf("process playbook %q not in args %v", pb, args)
	}
	if v, ok := laneFlagValue(args, "-i", "--inventory"); !ok || v != "localhost," {
		t.Errorf("inventory = %q (found=%v), want %q; args %v", v, ok, "localhost,", args)
	}
	if v, ok := laneFlagValue(args, "-c", "--connection"); !ok || v != "local" {
		t.Errorf("connection = %q (found=%v), want %q; args %v", v, ok, "local", args)
	}
	if laneIndexOf(args, "--check") >= 0 {
		t.Errorf("process lanes must never run with --check: %v", args)
	}

	// Full ordered layering: pipeline, force, collection scope, user extra LAST.
	want := []string{
		"dxdfir_zeek_pipeline=sofelk",
		"dxdfir_zeek_force=true",
		"dxdfir_zeek_pcaps_dir=/coll/pcaps",
		"scope=a",
		"dxdfir_zeek_pipeline=elastic",
		"user=1",
	}
	vals, firstE := laneExtraVars(args)
	if len(vals) != len(want) {
		t.Fatalf("-e values = %v, want %v", vals, want)
	}
	for i := range want {
		if vals[i] != want[i] {
			t.Fatalf("-e ordering broken at %d: got %v, want %v", i, vals, want)
		}
	}
	// The ordered -e pairs must come after every builder-emitted arg (the
	// playbook path is the builder's last) so the last-wins contract holds.
	if firstE < pbIdx {
		t.Errorf("-e pairs start at %d, before builder args ending at %d: %v", firstE, pbIdx, args)
	}
}

func TestAnsibleArgsForceFalseNoUserVars(t *testing.T) {
	j := &Job{
		Repo:     &repo.Repo{Root: "/fake/repo"},
		Ansible:  "ansible-playbook",
		Pipeline: "elastic",
		Force:    false,
	}
	args, err := j.ansibleArgs(LaneRun{Spec: Spec{Name: "plaso"}})
	if err != nil {
		t.Fatalf("ansibleArgs: %v", err)
	}
	want := []string{"dxdfir_plaso_pipeline=elastic", "dxdfir_plaso_force=false"}
	vals, _ := laneExtraVars(args)
	if len(vals) != len(want) || vals[0] != want[0] || vals[1] != want[1] {
		t.Fatalf("-e values = %v, want %v", vals, want)
	}
}
