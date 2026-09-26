package repogate

// DX_DFIR must not house what Byakugan owns. Byakugan (the standalone
// get-sybers/byakugan engine) owns the MITRE CAR object model, its reference
// documentation, the CAR correctness gate and the STIX/CTI exchange; the
// detections outside the engine are GoDFIR-toolz's, baked into its images at
// build time. DX_DFIR only ORCHESTRATES (ansible + this Go front-end) and
// links out. These tests fail if the boundary regresses: a Byakugan-owned
// doc tree reappears, the retired host-python package grows back, or the
// engine's DISK OUTPUT inside this repo becomes commit-able — what Byakugan
// writes onto disk here (the materialised CAR tree, the load bundles, the
// exchange products) is engine-owned and stays ignored, never DX_DFIR
// content.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// repoRoot resolves the repository root from this file's own location
// (go/internal/repogate/ -> three levels up).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this file's path")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// git runs git against the repo with repo rules only: a machine's global
// excludes must never satisfy the gate.
func git(t *testing.T, root string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "core.excludesFile=/dev/null"}, args...)...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		exit, isExit := err.(*exec.ExitError)
		if !isExit {
			t.Fatalf("git %v: %v", args, err)
		}
		code = exit.ExitCode()
	}
	return string(out), code
}

// Byakugan-owned reference documentation. DX_DFIR references it in the
// Byakugan repo and must not house it again. (docs/architecture/car-pipeline.md
// is DX_DFIR's own CAR-lane architecture doc and is intentionally NOT listed.)
var forbiddenPaths = []string{
	"docs/CAR-CrossSource.md",
	"docs/CAR-Extraction-Rules.md",
	"docs/CAR-Pipeline.md",
	"docs/CAR-Relations.md",
	"docs/car-provenance",
	"docs/research/cross-source-linkage",
}

func TestNoByakuganOwnedDocPaths(t *testing.T) {
	root := repoRoot(t)
	var present []string
	for _, p := range forbiddenPaths {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			present = append(present, p)
		}
	}
	if len(present) > 0 {
		t.Fatalf("Byakugan-owned reference paths reappeared in DX_DFIR; they belong in the Byakugan repo, not here: %v", present)
	}
}

// The host-python package is retired: byakugan owns the engine logic, the
// detections outside it are baked into GoDFIR-toolz images at build time.
// Nothing brings a python/ tree or tracked host .py files back — the one
// sanctioned home for python is the CI harness under .github/tests/ (and
// whatever the GoDFIR-toolz submodule bakes into images from its own tree).
func TestTheHostPythonPackageStaysRetired(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "python")); err == nil {
		t.Fatal("python/ exists again — the host-python package is retired: engine logic lives in byakugan, detections in GoDFIR-toolz, orchestration in ansible")
	}
	out, _ := git(t, root, "ls-files", "--", "*.py")
	var stray []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" || strings.HasPrefix(line, ".github/tests/") {
			continue
		}
		stray = append(stray, line)
	}
	if len(stray) > 0 {
		t.Fatalf("tracked python outside the CI harness: %v — host logic belongs in ansible tasks, the engine, or the build galaxy", stray)
	}
}

// Byakugan WRITES into this repo only under these data_store roots (the lane
// roles' out-dir defaults): the materialised CAR tree, the load bundles and
// the exchange products. Everything the engine writes is ENGINE-OWNED
// output: data_store/.gitignore's deny-by-default keeps every byte of it
// un-commit-able here, and these tests keep THAT enforced. A new lane that
// lands engine output must join this list and stay under data_store/processed/.
var engineWriteRoots = []string{
	"data_store/processed/byakugan",
	"data_store/processed/byakugan-load",
	"data_store/processed/exchange",
}

func TestEngineWrittenOutputIsNeverCommittable(t *testing.T) {
	root := repoRoot(t)
	names := []string{
		"car_flow.jsonl", "stix_bundle.json", "verify.txt",
		"bundle.json", "cti-bulk.ndjson", "sightings.json",
		"elastic/logs-car.process.bulk.ndjson",
		"a-format-nobody-thought-of.new",
	}
	for _, engineRoot := range engineWriteRoots {
		for _, name := range names {
			probe := engineRoot + "/case-x/" + name
			if _, code := git(t, root, "check-ignore", "-q", probe); code != 0 {
				t.Errorf("%s is commit-able — engine-written output is Byakugan-owned and must stay ignored (data_store/.gitignore, deny-by-default)", probe)
			}
		}
	}
}

func TestNoEngineOutputIsTrackedBeyondTheSkeleton(t *testing.T) {
	root := repoRoot(t)
	for _, engineRoot := range engineWriteRoots {
		out, _ := git(t, root, "ls-files", "--", engineRoot)
		var stray []string
		for _, p := range strings.Split(strings.TrimSpace(out), "\n") {
			if p != "" && !strings.HasSuffix(p, ".gitkeep") {
				stray = append(stray, p)
			}
		}
		if len(stray) > 0 {
			t.Errorf("engine-owned output is committed under %s: %v — what Byakugan writes, DX_DFIR never houses", engineRoot, stray)
		}
	}
}

func TestEngineOutDirDefaultsStayUnderTheIgnoredStore(t *testing.T) {
	// a refactor must not silently move an engine out-dir default into
	// commit-able tree space
	root := repoRoot(t)
	defaults := map[string]string{
		"dxdfir_byakugan_dir":     "ansible/collections/get_sybers.dxdfir/roles/dxdfir_byakugan/defaults/main.yml",
		"dxdfir_car_load_dir":     "ansible/collections/get_sybers.dxdfir/roles/dxdfir_car_load/defaults/main.yml",
		"dxdfir_car_load_out_dir": "ansible/collections/get_sybers.dxdfir/roles/dxdfir_car_load/defaults/main.yml",
		"dxdfir_exchange_out_dir": "ansible/collections/get_sybers.dxdfir/roles/dxdfir_exchange/defaults/main.yml",
	}
	for varName, rel := range defaults {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		value, _ := doc[varName].(string)
		if value == "" {
			t.Errorf("%s: %s default not found", rel, varName)
			continue
		}
		if !strings.Contains(value, "/data_store/processed/") {
			t.Errorf("%s defaults outside data_store/processed/ (%s) — the engine would write commit-able files into the repo", varName, value)
		}
	}
}

func TestThePinnedDockerfilePinsTheByakuganEngine(t *testing.T) {
	// The reference to Byakugan must not be silently dropped or loosened: the
	// engine pin lives as the BYAKUGAN_REF ARG default in the byakugan
	// Dockerfile the GoDFIR-toolz submodule pin carries, and it is always a
	// reproducible full-sha commit.
	root := repoRoot(t)
	dockerfile := filepath.Join(root, "docker", "GoDFIR-toolz", "byakugan", "Dockerfile")
	raw, err := os.ReadFile(dockerfile)
	if err != nil {
		t.Fatal("the GoDFIR-toolz submodule is not checked out — run `git submodule update --init --recursive docker/GoDFIR-toolz`")
	}
	m := regexp.MustCompile(`(?m)^ARG BYAKUGAN_REF=(\S+)$`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("the byakugan Dockerfile must default ARG BYAKUGAN_REF (the engine pin)")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(m[1]) {
		t.Fatalf("BYAKUGAN_REF must default to a full 40-hex commit sha (never a branch or tag, so the engine pin is reproducible), got %q", m[1])
	}
}
