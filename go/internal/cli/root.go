// Package cli assembles the dx command tree (cobra), one file per area. Commands
// stay thin: they build a run.Plan or drive an orchestrator and hand the
// resulting model.Update stream to the plain presenter. All heavy work lives in
// internal/{run,lanes,collect,plain}.
//
// The grammar is verb first — `<verb> <noun> [NAME]` (`deploy stack`,
// `register evidence LS24`, `list evidence`). The evidence verbs also take a
// bare NAME in place of the noun (`select LS24`). `byakugan` is the one
// noun-first exception: it is a tool namespace whose subcommands are its own
// verbs (`byakugan build`, `byakugan export-stix`), the way `dotnet tool`
// groups `install`/`list`.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Get-Sybers/DX_DFIR/go/internal/repo"
)

// Env holds the persistent, cross-verb flags.
type Env struct {
	RepoRoot string // DX_DFIR repo (auto-detected otherwise)
	Version  string // build version string, shown atop the landing readout
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
// so `dx --help` reads like the reference. Every visible root command carries
// one (root_test.go enforces it).
const (
	groupSetup     = "setup"
	groupStack     = "stack"
	groupEvidence  = "evidence"
	groupByakugan  = "byakugan"
	groupHousekeep = "housekeeping"
	groupSelf      = "self"
)

// nounGroup builds a parent whose children are the targets it acts on — a
// verb-first group (`deploy` → `stack`) or a tool namespace (`byakugan` →
// `build`…). A bare group prints its help; an unrecognised child (a typo like
// `sellect`) errors clearly instead of silently falling through to help.
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

// NewRootCmd builds the full dx command tree.
func NewRootCmd(version string) *cobra.Command {
	env := &Env{Version: version}

	root := &cobra.Command{
		Use:   "dx",
		Short: "DX_DFIR forensic pipeline front-end",
		Long: "DX_DFIR forensic processing pipeline — process evidence, build + verify CAR, validate.\n\n" +
			"A Go front-end over the get_sybers.dxdfir Ansible collection, whose roles run the\n" +
			"GoDFIR-toolz tool containers from their contracts. Progress streams as plain line\n" +
			"output on stderr, so a redirected stdout stays a clean data channel.\n\n" +
			"The grammar is verb first: `<verb> <noun>` — `deploy stack`, `register evidence LS24`,\n" +
			"`list evidence`. The evidence verbs also take a bare NAME in place of the noun:\n" +
			"`select LS24`, `sort LS24`. `byakugan` is a tool namespace: `byakugan build`,\n" +
			"`byakugan export-stix`.\n\n" +
			"Run `dx` with no command for a landing readout: environment readiness (the checks\n" +
			"that must be green before processing), tracked collections, and staged evidence.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		// A bare `dx` (no subcommand) renders the landing readout: version,
		// environment readiness, tracked collections, staged evidence. An unknown
		// verb still errors as before rather than silently opening the readout.
		Args: cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return Fail(2, "unknown command %q for dx — see `dx --help`", args[0])
			}
			return runHome(env, version)
		},
	}
	// -h and --help everywhere (cobra default), a bare group prints help, and no
	// shell-completion subcommand clutters help.
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetVersionTemplate("dx {{.Version}}\n")

	pf := root.PersistentFlags()
	pf.StringVar(&env.RepoRoot, "repo-root", "", "DX_DFIR repo (auto-detected otherwise).")

	root.AddGroup(
		&cobra.Group{ID: groupSetup, Title: "Setup:"},
		&cobra.Group{ID: groupStack, Title: "Analysis stack:"},
		&cobra.Group{ID: groupEvidence, Title: "Evidence:"},
		&cobra.Group{ID: groupByakugan, Title: "Byakugan (CAR + CTI):"},
		&cobra.Group{ID: groupHousekeep, Title: "Housekeeping:"},
		&cobra.Group{ID: groupSelf, Title: "The command itself:"},
	)
	root.SetHelpCommandGroupID(groupSelf)

	root.AddCommand(
		// Setup
		newBuildCmd(env),
		newVerifyCmd(env),
		// Analysis stack
		newDeployCmd(env),
		newStartCmd(env),
		newStopCmd(env),
		newRestartCmd(env),
		newStatusCmd(env),
		newUpdateCmd(env),
		// Evidence
		newRegisterCmd(env),
		newSelectCmd(env),
		newUnselectCmd(env),
		newUnregisterCmd(env),
		newSortCmd(env),
		newListCmd(env),
		newProcessCmd(env),
		// Byakugan (CAR normalisation + CTI exchange)
		newByakuganCmd(env),
		// Housekeeping
		newPurgeCmd(env),
		newValidateCmd(env),
	)
	return root
}
