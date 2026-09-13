// Package health probes the local environment for the preconditions the DX_DFIR
// pipeline needs before it can process evidence, so the home dashboard can show
// a green/amber/red readiness panel. Every probe is bounded by a short timeout
// and they run concurrently, so a slow or hung tool (a stuck docker daemon, say)
// never holds the whole dashboard hostage.
package health

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/get-sybers/dx_dfir/go/internal/model"
	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// probeTimeout bounds any single external probe (a --version call, docker info).
// Generous enough for a cold python/ansible start, short enough that the whole
// concurrent sweep still returns promptly when one tool is wedged.
const probeTimeout = 5 * time.Second

// Probe runs every readiness check concurrently against the resolved repo (which
// may be nil when the checkout could not be located) and returns them in a
// stable display order: gating preconditions first, lane-specific capabilities
// last.
func Probe(r *repo.Repo) []model.Check {
	probes := []func(*repo.Repo) model.Check{
		checkRepo,
		checkPython,
		checkProcessors,
		checkAnsible,
		checkCollection,
		checkDocker,
		checkPiiatMem,
		checkByakugan,
	}
	out := make([]model.Check, len(probes))
	var wg sync.WaitGroup
	for i, fn := range probes {
		wg.Add(1)
		go func(i int, fn func(*repo.Repo) model.Check) {
			defer wg.Done()
			out[i] = fn(r)
		}(i, fn)
	}
	wg.Wait()
	return out
}

// --- gating preconditions (must be green before `process`) ---

func checkRepo(r *repo.Repo) model.Check {
	c := model.Check{Name: "repo", Gate: true}
	if r == nil {
		c.State = model.CheckFail
		c.Detail = "no DX_DFIR checkout found - pass --repo-root or set $DFIR_REPO_ROOT"
		return c
	}
	c.State = model.CheckOK
	c.Detail = r.Root
	return c
}

func checkPython(r *repo.Repo) model.Check {
	c := model.Check{Name: "python3", Gate: true}
	py, err := repo.Python()
	if err != nil {
		c.State = model.CheckFail
		c.Detail = "no python interpreter on PATH (set $DXDFIR_PYTHON or install python3)"
		return c
	}
	out, _, ok := capture(py, "--version")
	if !ok {
		// Found on PATH but it will not even print its version — a wedged or
		// broken interpreter. Warn (a gate that is not OK blocks READY) rather
		// than claim the environment is usable.
		c.State = model.CheckWarn
		c.Detail = "found at " + py + ", but `" + filepath.Base(py) + " --version` failed or timed out"
		return c
	}
	c.State = model.CheckOK
	if ver := strings.TrimSpace(firstLine(out)); ver != "" {
		c.Detail = ver + " (" + py + ")"
	} else {
		c.Detail = py
	}
	return c
}

// checkProcessors verifies the get_sybers_dxdfir package is importable — the
// processor package every lane and the collection registry depend on. It imports
// exactly as a driven child would: PYTHONPATH-prepended <repo>/python.
func checkProcessors(r *repo.Repo) model.Check {
	c := model.Check{Name: "processors", Gate: true}
	py, err := repo.Python()
	if err != nil {
		c.State = model.CheckFail
		c.Detail = "python interpreter unavailable"
		return c
	}
	var env []string
	if r != nil {
		env = []string{"PYTHONPATH=" + pythonPath(r)}
	}
	const script = "import get_sybers_dxdfir as m,sys; sys.stdout.write(getattr(m,'__version__',''))"
	out, errOut, ok := captureEnv(env, py, "-c", script)
	if !ok {
		// Keep the actionable remediation; fold the traceback tail in as context
		// rather than replacing the hint with it.
		c.State = model.CheckFail
		c.Detail = "not importable - run scripts/setup-environment.sh (pip install ./python)"
		if msg := lastMeaningful(errOut); msg != "" {
			c.Detail = "not importable (" + msg + ") - run scripts/setup-environment.sh (pip install ./python)"
		}
		return c
	}
	c.State = model.CheckOK
	if v := strings.TrimSpace(out); v != "" {
		c.Detail = "get_sybers_dxdfir " + v
	} else {
		c.Detail = "get_sybers_dxdfir importable"
	}
	return c
}

func checkAnsible(r *repo.Repo) model.Check {
	c := model.Check{Name: "ansible", Gate: true}
	ap, err := repo.AnsiblePlaybook()
	if err != nil {
		c.State = model.CheckFail
		c.Detail = "ansible-playbook not found - it ships with the get_sybers_dxdfir install"
		return c
	}
	out, _, ok := capture(ap, "--version")
	if !ok {
		c.State = model.CheckWarn
		c.Detail = "found at " + ap + ", but `ansible-playbook --version` failed or timed out"
		return c
	}
	c.State = model.CheckOK
	if ver := strings.TrimSpace(firstLine(out)); ver != "" {
		c.Detail = ver
	} else {
		c.Detail = ap
	}
	return c
}

func checkCollection(r *repo.Repo) model.Check {
	c := model.Check{Name: "collection", Gate: true}
	if r == nil {
		c.State = model.CheckFail
		c.Detail = "repo not located"
		return c
	}
	dir := r.CollectionDir()
	if isDir(dir) {
		c.State = model.CheckOK
		c.Detail = "get_sybers.dxdfir (" + repo.CollectionPath + ")"
		return c
	}
	c.State = model.CheckFail
	c.Detail = "get_sybers.dxdfir collection missing at " + dir
	return c
}

// checkDocker gates on both the CLI being present and the daemon being
// reachable: the processing lanes run in the pipeline's docker images, so a
// missing daemon blocks `process` even though the binary is installed.
func checkDocker(r *repo.Repo) model.Check {
	c := model.Check{Name: "docker", Gate: true}
	if _, err := exec.LookPath("docker"); err != nil {
		c.State = model.CheckFail
		c.Detail = "docker not on PATH"
		return c
	}
	out, _, ok := capture("docker", "info", "--format", "{{.ServerVersion}}")
	if ok && strings.TrimSpace(out) != "" {
		c.State = model.CheckOK
		c.Detail = "engine " + strings.TrimSpace(firstLine(out))
		return c
	}
	c.State = model.CheckFail
	c.Detail = "daemon unreachable - is dockerd running / are you in the docker group?"
	return c
}

// --- lane-specific capabilities (warn, not a hard gate) ---

// checkPiiatMem reports whether the vendored PIIAT-Mem submodule is initialised;
// the volatility lane reads its tree, so an uninitialised submodule narrows the
// pipeline to the other lanes rather than blocking it.
func checkPiiatMem(r *repo.Repo) model.Check {
	c := model.Check{Name: "piiat-mem", Gate: false}
	if r == nil {
		c.State = model.CheckWarn
		c.Detail = "repo not located"
		return c
	}
	dir := r.Path("third_party", "piiat-mem")
	if isNonEmptyDir(dir) {
		c.State = model.CheckOK
		c.Detail = "submodule initialised (volatility lane)"
		return c
	}
	c.State = model.CheckWarn
	c.Detail = "submodule not initialised - volatility lane unavailable (git submodule update --init)"
	return c
}

// checkByakugan reports whether the external Byakugan engine is provisioned and
// its parse binary built. It is needed only for the CAR build/timeline verbs, so
// its absence is a warning, never a process gate. Resolution mirrors the python
// seam and setup script: $BYAKUGAN_ROOT, else the `byakugan` dir beside the repo.
func checkByakugan(r *repo.Repo) model.Check {
	c := model.Check{Name: "byakugan", Gate: false}
	root := byakuganRoot(r)
	if root == "" {
		c.State = model.CheckWarn
		c.Detail = "engine root unknown (repo not located)"
		return c
	}
	if !isDir(root) {
		c.State = model.CheckWarn
		c.Detail = "engine not provisioned at " + root + " (needed for build-car)"
		return c
	}
	if !isExecutable(filepath.Join(root, "go", "bin", "byakugan-parse")) {
		c.State = model.CheckWarn
		c.Detail = "engine present, parse binary not built (make -C " + root + "/go build)"
		return c
	}
	c.State = model.CheckOK
	c.Detail = "engine at " + root
	return c
}

// byakuganRoot resolves the engine checkout the same way mitrecar.py does.
func byakuganRoot(r *repo.Repo) string {
	if v := os.Getenv("BYAKUGAN_ROOT"); v != "" {
		return v
	}
	if r == nil {
		return ""
	}
	return filepath.Join(filepath.Dir(r.Root), "byakugan")
}

// --- helpers ---

func pythonPath(r *repo.Repo) string {
	pp := r.Path("python")
	if cur := os.Getenv("PYTHONPATH"); cur != "" {
		pp += string(os.PathListSeparator) + cur
	}
	return pp
}

func capture(bin string, args ...string) (stdout, stderr string, ok bool) {
	return captureEnv(nil, bin, args...)
}

func captureEnv(env []string, bin string, args ...string) (stdout, stderr string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	out, errOut, err := run.Capture(ctx, run.Plan{Bin: bin, Args: args, Env: env})
	return out, errOut, err == nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// lastMeaningful returns the last non-blank line of a python traceback — the
// "ModuleNotFoundError: ..." line, not the framing above it.
func lastMeaningful(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func isNonEmptyDir(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	names, _ := f.Readdirnames(1)
	return len(names) > 0
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}
