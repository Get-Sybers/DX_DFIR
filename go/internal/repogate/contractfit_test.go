package repogate

// Lane roles must fit the pinned GoDFIR-toolz tool contracts.
//
// Every lane role drives its hardened container from a contract.yml in the
// GoDFIR-toolz submodule: the env vars it sets and the container paths it
// mounts exist only if the pinned submodule commit declares them. A role and
// the submodule gitlink can only move together — these tests fail the build
// when a role speaks a contract the pin does not carry (env keys the
// contract does not declare, mount paths it does not define, or required
// mounts the role never binds).

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	// A contract reference in a role's defaults/tasks:
	// .../GoDFIR-toolz/<tool>/contract.yml (also matched when the submodule
	// path itself is behind a variable).
	contractRef = regexp.MustCompile(`([a-z0-9_-]+)/contract\.yml`)
	// An env key set on a run: quoted (Jinja dict literal) or bare (YAML mapping).
	envKey = regexp.MustCompile(`['"]?([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)['"]?\s*:`)
	// A container mount path on a run: {host: ..., path: /x} or 'path': '/x'.
	// Multi-segment paths are real (anamnesis mounts /opt/anamnesis/lib/Symbols).
	mountPath = regexp.MustCompile(`['"]?path['"]?\s*:\s*['"]?(/[A-Za-z0-9_/.-]*[A-Za-z0-9_])['"]?`)
	// A bare container path literal (inside a fact value, a Jinja expression, …).
	pathLiteral = regexp.MustCompile(`/[A-Za-z0-9_/.-]*[A-Za-z0-9_]`)
	// A container path an env value names (an env-named mount) — allowed like
	// the runtime preflight, but only when the naming env KEY is itself
	// declared by a referenced contract, so an undeclared mount cannot vouch
	// for itself through its own env var. The value may open inline
	// (`: '/x'`), parenthesised (`: ('/x' if …`), or as a folded Jinja scalar
	// (`: >-` newline `{{ '/x' if …`).
	envNamed = regexp.MustCompile(`['"]?([A-Z][A-Z0-9_]+)['"]?\s*:\s*(?:>-?\s*)?\(?\s*(?:\{\{\s*)?['"]?(/[A-Za-z0-9_/.-]*[A-Za-z0-9_])`)
	// A declared env key whose value is a role fact: one indirection hop —
	// the fact's own value (its line plus deeper-indented continuations) may
	// vouch for path literals.
	envFactRef = regexp.MustCompile(`['"]?([A-Z][A-Z0-9_]+)['"]?\s*:\s*([a-z_][a-z0-9_]*)\b`)
)

type contractDoc struct {
	Env    map[string]any   `yaml:"env"`
	Mounts []map[string]any `yaml:"mounts"`
}

func rolesDir(t *testing.T) string {
	return filepath.Join(repoRoot(t), "ansible", "collections", "get_sybers.dxdfir", "roles")
}

func toolzDir(t *testing.T) string {
	return filepath.Join(repoRoot(t), "docker", "GoDFIR-toolz")
}

func loadContract(t *testing.T, tool string) contractDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(toolzDir(t), tool, "contract.yml"))
	if err != nil {
		t.Fatalf("contract %s: %v", tool, err)
	}
	var doc contractDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("contract %s: %v", tool, err)
	}
	return doc
}

// roleContracts returns the tool names whose contracts the role references
// (defaults + tasks), split into (present at the pin, missing at the pin).
func roleContracts(t *testing.T, role string) (present, missing []string) {
	t.Helper()
	seenP, seenM := map[string]bool{}, map[string]bool{}
	for _, part := range []string{"defaults", "tasks"} {
		files, _ := filepath.Glob(filepath.Join(role, part, "*.yml"))
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range contractRef.FindAllStringSubmatch(string(raw), -1) {
				tool := m[1]
				if _, err := os.Stat(filepath.Join(toolzDir(t), tool, "contract.yml")); err == nil {
					seenP[tool] = true
				} else {
					seenM[tool] = true
				}
			}
		}
	}
	for k := range seenP {
		present = append(present, k)
	}
	for k := range seenM {
		missing = append(missing, k)
	}
	sort.Strings(present)
	sort.Strings(missing)
	return present, missing
}

func roleText(t *testing.T, role string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(role, "tasks", "*.yml"))
	sort.Strings(files)
	var parts []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, string(raw))
	}
	return strings.Join(parts, "\n")
}

func allRoles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(rolesDir(t))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(rolesDir(t), e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// laneRoles returns every role that references at least one contract present
// at the pin, with those tool names.
func laneRoles(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, role := range allRoles(t) {
		present, _ := roleContracts(t, role)
		if len(present) > 0 {
			out[role] = present
		}
	}
	return out
}

// factPaths mirrors the python gate's one indirection hop: the value of a
// role fact (its assignment line plus any deeper-indented continuation
// lines) yields the path literals a declared env key set from it vouches for.
func factPaths(text, varName string) []string {
	lineRe := regexp.MustCompile(`^([ \t]*)['"]?` + regexp.QuoteMeta(varName) + `['"]?\s*:(.*)$`)
	lines := strings.Split(text, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		m := lineRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		indent, val := m[1], m[2]
		for j := i + 1; j < len(lines); j++ {
			rest := strings.TrimPrefix(lines[j], indent)
			if rest != lines[j] && len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
				val += "\n" + lines[j]
			} else {
				break
			}
		}
		out = append(out, pathLiteral.FindAllString(val, -1)...)
	}
	return out
}

func TestLaneRolesReferenceExistingContracts(t *testing.T) {
	if _, err := os.Stat(filepath.Join(toolzDir(t), "anamnesis", "contract.yml")); err != nil {
		t.Fatal("the GoDFIR-toolz submodule is not checked out — run `git submodule update --init --recursive docker/GoDFIR-toolz`")
	}
	if len(laneRoles(t)) == 0 {
		t.Fatal("no lane role references a GoDFIR-toolz contract")
	}
}

func TestReferencedContractsExistAtThePin(t *testing.T) {
	for _, role := range allRoles(t) {
		_, missing := roleContracts(t, role)
		if len(missing) > 0 {
			t.Errorf("%s references contract(s) %v that the pinned GoDFIR-toolz checkout does not carry — the submodule pin and the role have diverged", filepath.Base(role), missing)
		}
	}
}

func TestEnvKeysAreDeclaredByThePinnedContracts(t *testing.T) {
	for role, tools := range laneRoles(t) {
		declared := map[string]bool{}
		prefixes := map[string]bool{}
		for _, tool := range tools {
			for k := range loadContract(t, tool).Env {
				declared[k] = true
				prefixes[strings.SplitN(k, "_", 2)[0]] = true
			}
		}
		var undeclared []string
		for _, m := range envKey.FindAllStringSubmatch(roleText(t, role), -1) {
			k := m[1]
			if prefixes[strings.SplitN(k, "_", 2)[0]] && !declared[k] {
				undeclared = append(undeclared, k)
			}
		}
		if len(undeclared) > 0 {
			sort.Strings(undeclared)
			t.Errorf("%s sets env %v that no referenced pinned contract (%v) declares — the GoDFIR-toolz submodule pin and the role have diverged", filepath.Base(role), undeclared, tools)
		}
	}
}

func TestMountPathsAreDeclaredByThePinnedContracts(t *testing.T) {
	for role, tools := range laneRoles(t) {
		declared := map[string]bool{}
		declaredEnv := map[string]bool{}
		for _, tool := range tools {
			doc := loadContract(t, tool)
			for _, m := range doc.Mounts {
				if p, ok := m["path"].(string); ok {
					declared[p] = true
				}
			}
			for k := range doc.Env {
				declaredEnv[k] = true
			}
		}
		if len(declared) == 0 {
			continue
		}
		text := roleText(t, role)
		envNamedPaths := map[string]bool{}
		for _, m := range envNamed.FindAllStringSubmatch(text, -1) {
			if declaredEnv[m[1]] {
				envNamedPaths[m[2]] = true
			}
		}
		for _, m := range envFactRef.FindAllStringSubmatch(text, -1) {
			if !declaredEnv[m[1]] {
				continue
			}
			for _, p := range factPaths(text, m[2]) {
				envNamedPaths[p] = true
			}
		}
		var undeclared []string
		for _, m := range mountPath.FindAllStringSubmatch(text, -1) {
			p := m[1]
			if envNamedPaths[p] {
				continue
			}
			// A bind inside a declared mount is within contract (e.g. an
			// operator ruleset file mounted under the declared /rules dir).
			within := false
			for d := range declared {
				if p == d || strings.HasPrefix(p, d+"/") {
					within = true
					break
				}
			}
			if !within {
				undeclared = append(undeclared, p)
			}
		}
		if len(undeclared) > 0 {
			sort.Strings(undeclared)
			t.Errorf("%s mounts %v that no referenced pinned contract (%v) defines — the GoDFIR-toolz submodule pin and the role have diverged", filepath.Base(role), undeclared, tools)
		}
	}
}

func TestRequiredMountsAreBoundByTheRole(t *testing.T) {
	for role, tools := range laneRoles(t) {
		text := roleText(t, role)
		for _, tool := range tools {
			var unbound []string
			for _, m := range loadContract(t, tool).Mounts {
				p, ok := m["path"].(string)
				req, _ := m["required"].(bool)
				if !ok || !req {
					continue
				}
				// the path, not followed by more path (RE2 has no lookahead:
				// match path + a non-[word/] rune or end)
				re := regexp.MustCompile(`(?m)` + regexp.QuoteMeta(p) + `([^A-Za-z0-9_/]|$)`)
				if !re.MatchString(text) {
					unbound = append(unbound, p)
				}
			}
			if len(unbound) > 0 {
				sort.Strings(unbound)
				t.Errorf("%s never binds required mount(s) %v of the pinned %s contract", filepath.Base(role), unbound, tool)
			}
		}
	}
}
