// Package cli assembles the dxdfir command tree (cobra), one file per verb
// group. Commands stay thin: they build a run.Plan or drive an orchestrator and
// hand the resulting model.Update stream to a presenter chosen by the terminal
// context. All heavy work lives in internal/{run,lanes,collect,tui,plain}.
package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
)

// Env holds the persistent, cross-verb flags.
type Env struct {
	RepoRoot   string
	ForcePlain bool // --no-tui
	ForceTUI   bool // --tui
}

// ExitError carries a specific process exit code up to main, preserving the
// Python CLI's exit-status contract (propagate subprocess rc; 2 usage/lookup;
// 127 missing tool; 0 success).
type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// Fail is a convenience for returning an ExitError after printing a red message.
func Fail(code int, format string, a ...any) error {
	fmt.Fprintln(os.Stderr, redf(format, a...))
	return ExitError{Code: code}
}

// resolveRepo is the shared repo lookup with the CLI error contract (exit 2).
func (e *Env) resolveRepo() (*repo.Repo, error) {
	r, err := repo.Detect(e.RepoRoot)
	if err != nil {
		return nil, Fail(2, "%v", err)
	}
	return r, nil
}

// NewRootCmd builds the full dxdfir command tree.
func NewRootCmd(version string) *cobra.Command {
	env := &Env{}

	root := &cobra.Command{
		Use:   "dxdfir",
		Short: "DX_DFIR forensic pipeline front-end",
		Long: "DX_DFIR forensic processing pipeline — process evidence, build + verify CAR, validate.\n\n" +
			"A Go/termui front-end over the get_sybers.dxdfir Ansible collection and the\n" +
			"get_sybers_dxdfir Python processors. Long-running processing and collection\n" +
			"creation render a live dashboard on a terminal; output stays plain when piped.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		// Make the get_sybers_dxdfir package importable by every child python we
		// shell out to, from a bare checkout as well as an installed environment:
		// prepend <repo>/python to PYTHONPATH once, before any verb runs. Silent
		// if the repo cannot be located here — the verb's own resolveRepo reports it.
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if r, err := repo.Detect(env.RepoRoot); err == nil {
				pp := filepath.Join(r.Root, "python")
				if cur := os.Getenv("PYTHONPATH"); cur != "" {
					pp += string(os.PathListSeparator) + cur
				}
				_ = os.Setenv("PYTHONPATH", pp)
			}
		},
	}
	// Match the Python CLI's ergonomics: -h and --help everywhere (cobra default),
	// a bare group prints help, and no shell-completion subcommand clutters help.
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetVersionTemplate("dxdfir (get_sybers_dxdfir) {{.Version}}\n")

	pf := root.PersistentFlags()
	pf.StringVar(&env.RepoRoot, "repo-root", "", "DX_DFIR repo (auto-detected otherwise).")
	pf.BoolVar(&env.ForcePlain, "no-tui", false, "Force plain line output (never the dashboard).")
	pf.BoolVar(&env.ForceTUI, "tui", false, "Force the dashboard even when auto-detection is unsure.")

	root.AddCommand(
		newProcessCmd(env),
		newListCmd(env),
		newRegisterCmd(env),
		newCollectionCmd(env),
		newBuildCarCmd(env),
		newVerifyCarCmd(env),
		newCarTimelineCmd(env),
		newBuildDockerCmd(env),
		newVerifyImagesCmd(env),
		newValidateCmd(env),
		newStackCmd(env),
		newCleanupCmd(env),
		newStixCmd(env),
	)
	return root
}
