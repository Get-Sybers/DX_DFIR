package collection

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var laneVarRe = regexp.MustCompile(`^(dxdfir_[a-z0-9_]+):`)

// Every raw-tree geography var (playbooks/group_vars/all.yml — the godfir
// lanes read their inputs from these) must be scoped by LANES: a var missing
// there keeps its LOOSE default under a collection-scoped run and reads
// evidence from outside the collection.
func TestLanesScopeEveryRawInput(t *testing.T) {
	repo := filepath.Join("..", "..", "..")
	b, err := os.ReadFile(filepath.Join(repo, "ansible", "collections",
		"get_sybers.dxdfir", "playbooks", "group_vars", "all.yml"))
	if err != nil {
		t.Fatalf("group_vars: %v", err)
	}
	scoped := map[string]bool{}
	for _, lane := range LANES {
		for _, v := range lane.InputVars {
			scoped[v] = true
		}
	}
	current := ""
	for _, line := range strings.Split(string(b), "\n") {
		if m := laneVarRe.FindStringSubmatch(line); m != nil {
			current = m[1]
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// the shared base var is not itself a lane input
		if current == "" || current == "dxdfir_raw_dir" {
			continue
		}
		if !strings.Contains(line, "dxdfir_raw_dir") && !strings.Contains(line, "data_store/raw") {
			continue
		}
		if !scoped[current] {
			t.Errorf("group_vars reads the raw tree via %s, but LANES does not scope it — "+
				"a collection-scoped run would read loose evidence instead", current)
		}
	}
	if current == "" {
		t.Fatal("no dxdfir_* vars parsed from group_vars/all.yml")
	}
}
