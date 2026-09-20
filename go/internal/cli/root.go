// Package cli assembles the dxdfir command tree (cobra), one file per verb
// family. Commands stay thin: they build a run.Plan or drive an orchestrator and
// hand the resulting model.Update stream to a presenter chosen by the terminal
// context. All heavy work lives in internal/{run,lanes,collect,tui,plain}.
//
// The grammar is verb first: `<verb> <noun> [NAME]` (`register collection LS24`,
// `deploy stack`, `list collections`). The collection verbs also take a bare
// NAME in place of the noun (`register LS24`). The former noun-first spellings
// (`collection register`, `stack deploy`) still run as hidden, deprecated
// aliases — each verb body is a plain run function wrapped by both spellings,
// never one *cobra.Command under two parents.
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
// exit-status contract (propagate subprocess rc; 2 usage/lookup; 127 missing
// tool; 0 success).
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

// Root-help groups, mirroring the sections of docs/getting-started/commands.md
// so `dxdfir --help` reads like the reference. Every visible root command
// carries one (root_test.go enforces it).
const (
	groupSetup      = "setup"
	groupEvidence   = "evidence"
	groupProcessing = "processing"
	groupCAR        = "car"
	groupStack      = "stack"
	groupHousekeep  = "housekeeping"
	groupSelf       = "self"
)

// nounGroup builds a parent whose children are the targets it acts on — a
// verb-first group (`deploy` → `stack`) or a hidden noun-first alias group
// (`collection` → `register`…). A bare group prints its help; an unrecognised
// child (a typo like `sellect`) errors clearly instead of silently falling
// through to help.
func nounGroup(use, short, long string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				return Fail(2, "unknown command %q for %q — see: %s --help",
					args[0], c.CommandPath(), c.CommandPath())
			}
			return c.Help()
		},
	}
}

// NewRootCmd builds the full dxdfir command tree.
func NewRootCmd(version string) *cobra.Command {
	env := &Env{}

	root := &cobra.Command{
		Use:   "dxdfir",
		Short: "DX_DFIR forensic pipeline front-end",
		Long: "DX_DFIR forensic processing pipeline — process evidence, build + verify CAR, validate.\n\n" +
			"A Go/termui front-end over the get_sybers.dxdfir Ansible collection, whose roles\n" +
			"run the GoDFIR-toolz tool containers from their contracts. Long-running processing\n" +
			"and collection creation render a live dashboard on a terminal; output stays plain\n" +
			"when piped.\n\n" +
			"Commands read verb first — `register collection NAME`, `deploy stack`,\n" +
			"`list collections`. The collection verbs also take a bare NAME in place of\n" +
			"the noun: `register NAME`, `sort NAME`, `select NAME`.\n\n" +
			"Run `dxdfir` with no command for a landing dashboard: environment readiness\n" +
			"(the checks that must be green before processing), tracked collections, and\n" +
			"staged evidence.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		// A bare `dxdfir` (no subcommand) renders the landing dashboard: version,
		// environment readiness, tracked collections, staged evidence. An unknown
		// verb still errors as before rather than silently opening the dashboard.
		Args: cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return Fail(2, "unknown command %q for dxdfir — see `dxdfir --help`", args[0])
			}
			return runHome(env, version)
		},
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
	// -h and --help everywhere (cobra default), a bare group prints help, and no
	// shell-completion subcommand clutters help.
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetVersionTemplate("dxdfir (get_sybers_dxdfir) {{.Version}}\n")

	pf := root.PersistentFlags()
	pf.StringVar(&env.RepoRoot, "repo-root", "", "DX_DFIR repo (auto-detected otherwise).")
	pf.BoolVar(&env.ForcePlain, "no-tui", false, "Force plain line output (never the dashboard).")
	pf.BoolVar(&env.ForceTUI, "tui", false, "Force the dashboard even when auto-detection is unsure.")

	root.AddGroup(
		&cobra.Group{ID: groupSetup, Title: "Setup:"},
		&cobra.Group{ID: groupEvidence, Title: "Evidence and collections:"},
		&cobra.Group{ID: groupProcessing, Title: "Processing:"},
		&cobra.Group{ID: groupCAR, Title: "CAR (normalisation):"},
		&cobra.Group{ID: groupStack, Title: "Analysis stack:"},
		&cobra.Group{ID: groupHousekeep, Title: "Housekeeping:"},
		&cobra.Group{ID: groupSelf, Title: "The command itself:"},
	)
	root.SetHelpCommandGroupID(groupSelf)

	root.AddCommand(
		// Setup
		newBuildDockerCmd(env),
		newVerifyImagesCmd(env),
		// Evidence and collections
		newListCmd(env),
		newRegisterCmd(env),
		newUnregisterCmd(env),
		newSelectCmd(env),
		newUnselectCmd(env),
		newSortCmd(env),
		// Processing
		newProcessCmd(env),
		// CAR
		newBuildCarCmd(env),
		newVerifyCarCmd(env),
		newLoadCarCmd(env),
		newCarTimelineCmd(env),
		newStixCmd(env),
		newStampDetectionsCmd(env),
		// Analysis stack
		newDeployCmd(env),
		newDestroyCmd(env),
		newStartCmd(env),
		newStopCmd(env),
		newStatusCmd(env),
		// Housekeeping
		newCleanupCmd(env),
		newValidateCmd(env),
		// Hidden, deprecated noun-first aliases (retired next minor).
		newCollectionCmd(env),
		newStackCmd(env),
	)
	return root
}
