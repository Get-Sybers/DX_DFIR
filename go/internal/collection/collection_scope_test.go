package collection

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var laneVarRe = regexp.MustCompile(`^(dxdfir_[a-z0-9_]+):`)

// Every raw-tree input dir a lane role declares must be scoped by LANES: a var
// missing there keeps its LOOSE default under a collection-scoped run and reads
// evidence from outside the collection.
func TestLanesScopeEveryRawInput(t *testing.T) {
	repo := filepath.Join("..", "..", "..")
	for _, lane := range LANES {
		role := "dxdfir_" + strings.ReplaceAll(lane.Name, "-", "_")
		b, err := os.ReadFile(filepath.Join(repo, "ansible", "collections",
			"get_sybers.dxdfir", "roles", role, "defaults", "main.yml"))
		if err != nil {
			t.Fatalf("%s defaults: %v", role, err)
		}
		scoped := map[string]bool{}
		for _, v := range lane.InputVars {
			scoped[v] = true
		}
		current := ""
		for _, line := range strings.Split(string(b), "\n") {
			if m := laneVarRe.FindStringSubmatch(line); m != nil {
				current = m[1]
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || !strings.Contains(line, "data_store/raw") {
				continue
			}
			if current != "" && !scoped[current] {
				t.Errorf("%s reads the raw tree via %s, but LANES does not scope it — "+
					"a collection-scoped run would read loose evidence instead", role, current)
			}
		}
	}
}
