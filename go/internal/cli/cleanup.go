package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// Cleanup is Ansible-orchestrated (dxdfir_cleanup role): each verb fronts
// dxdfir-cleanup.yml with -e dxdfir_cleanup_action. The front-end keeps the
// destructive confirmation and maps --dry-run to ansible --check.

// newCleanupCmd builds the `dxdfir cleanup` group.
func newCleanupCmd(env *Env) *cobra.Command {
	parent := &cobra.Command{
		Use:   "cleanup",
		Short: "Wipe processed evidence, CAR stores, or dxdfir/* docker images.",
	}
	parent.AddCommand(
		newCleanupActionCmd(env, "processed",
			"Wipe everything under data_store/processed/ (all lanes + CAR).",
			"Wipe everything under data_store/processed/? [y/N]: ", nil),
		newCleanupActionCmd(env, "car",
			"Wipe the materialised CAR (data_store/processed/car/).",
			"Wipe the CAR tree under data_store/processed/car/? [y/N]: ", nil),
		newCleanupDockerCmd(env),
	)
	return parent
}

// newCleanupActionCmd builds a cleanup subcommand that runs one dxdfir_cleanup
// action. extraVars (may be nil) contributes action-specific -e vars, evaluated
// at run time so it can read the subcommand's own flags.
func newCleanupActionCmd(env *Env, action, short, promptMsg string, extraVars func() []string) *cobra.Command {
	var dryRun, yes bool
	cmd := &cobra.Command{
		Use:   action,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			if !dryRun && !yes {
				if !confirmYes(promptMsg) {
					return Fail(1, "Aborted.")
				}
			}
			vars := []string{"dxdfir_cleanup_action=" + action}
			if extraVars != nil {
				vars = append(vars, extraVars()...)
			}
			plan, err := ansiblePlan(r, ap, "dxdfir-cleanup.yml", vars, dryRun)
			if err != nil {
				return err
			}
			code := run.Passthrough(context.Background(), plan, true)
			return exitCode(code)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be removed (ansible --check).")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Do not prompt.")
	return cmd
}

// newCleanupDockerCmd builds `dxdfir cleanup docker` with its extra flags/vars.
func newCleanupDockerCmd(env *Env) *cobra.Command {
	var dangling, allDxdfir bool
	cmd := newCleanupActionCmd(env, "docker",
		"Remove built dxdfir/* tool images so the next build is clean.",
		"Remove the dxdfir/* tool images? [y/N]: ",
		func() []string {
			var v []string
			if dangling {
				v = append(v, "dxdfir_cleanup_dangling=true")
			}
			if allDxdfir {
				v = append(v, "dxdfir_cleanup_all_dxdfir=true")
			}
			return v
		})
	cmd.Long = "Remove built dxdfir/* tool images (dxdfir_cleanup role, docker action).\n\n" +
		"By default only the hardened tool set is removed (the source of truth is the\n" +
		"Python get_sybers_dxdfir.images.HARDENED_IMAGES). --all-dxdfir removes EVERY\n" +
		"dxdfir/* image present; --dangling also prunes dangling layers."
	cmd.Flags().BoolVar(&dangling, "dangling", false, "Also prune dangling layers.")
	cmd.Flags().BoolVar(&allDxdfir, "all-dxdfir", false, "Remove EVERY dxdfir/* image (default: only the hardened tool set).")
	return cmd
}
