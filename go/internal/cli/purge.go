package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Get-Sybers/DX_DFIR/go/internal/run"
	"github.com/Get-Sybers/DX_DFIR/go/internal/style"
)

// purge is the one destructive verb, over several noun targets:
//
//	purge stack     — stop + remove the analysis stack's containers/networks
//	                  (and, with --volumes, its data). Ansible: dxdfir-stack-destroy.yml.
//	purge evidence  — wipe everything under data_store/processed/ (all lanes + CAR).
//	purge car       — wipe just the materialised CAR (data_store/processed/byakugan/).
//	purge images    — remove the built get-sybers/* tool images.
//
// The evidence/car/images targets front dxdfir-cleanup.yml with
// -e dxdfir_cleanup_action; --dry-run maps to ansible --check. Every target
// confirms before acting unless -y is given.
func newPurgeCmd(env *Env) *cobra.Command {
	parent := nounGroup("purge",
		"Destructive teardown: the stack, processed evidence, the CAR tree, or tool images.",
		"Destructive teardown, one noun target each:\n\n"+
			"  purge stack      stop + remove the analysis stack's containers/networks.\n"+
			"  purge evidence   wipe everything under data_store/processed/ (all lanes + CAR).\n"+
			"  purge car        wipe just the materialised CAR (data_store/processed/byakugan/).\n"+
			"  purge images     remove the built get-sybers/* tool images.\n\n"+
			"Each confirms before acting unless -y is given.")
	parent.GroupID = groupHousekeep
	parent.AddCommand(
		newPurgeStackCmd(env),
		newCleanupActionCmd(env, "evidence", "processed",
			"Wipe everything under data_store/processed/ (all lanes + CAR).",
			"Wipe everything under data_store/processed/? [y/N]: ", nil),
		newCleanupActionCmd(env, "car", "car",
			"Wipe the materialised CAR (data_store/processed/byakugan/).",
			"Wipe the CAR tree under data_store/processed/byakugan/? [y/N]: ", nil),
		newPurgeImagesCmd(env),
	)
	return parent
}

// newPurgeStackCmd builds `dx purge stack` — the stack teardown (was `destroy
// stack`), driven by dxdfir-stack-destroy.yml.
func newPurgeStackCmd(env *Env) *cobra.Command {
	var volumes, yes bool
	cmd := &cobra.Command{
		Use:     "stack",
		Aliases: []string{"stacks"},
		Short:   "Stop and remove the stack's containers/networks (optionally its volumes).",
		Long:    "Stop and remove the stack's containers/networks (optionally its volumes).\n\n" + stackLong,
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if volumes && !yes {
				if !confirmYes(
					"Remove the elastic stack's containers AND named volumes? This DELETES ingested data. [y/N]: ") {
					return Fail(1, "Aborted.")
				}
			}
			vars := []string{"dxdfir_stack_remove_volumes=" + boolVar(volumes)}
			if err := env.runStackAction("destroy", vars); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " elastic stack purged."))
			return nil
		},
	}
	cmd.Flags().BoolVar(&volumes, "volumes", false, "Also remove named volumes (WIPES stack data).")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Do not prompt.")
	return cmd
}

// newCleanupActionCmd builds a purge subcommand that runs one dxdfir_cleanup
// action. use is the noun the user types; action is the role action it maps to.
// extraVars (may be nil) contributes action-specific -e vars, evaluated at run
// time so it can read the subcommand's own flags.
func newCleanupActionCmd(env *Env, use, action, short, promptMsg string, extraVars func() []string) *cobra.Command {
	var dryRun, yes bool
	cmd := &cobra.Command{
		Use:   use,
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
			return exitCode(run.Passthrough(context.Background(), plan, true))
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be removed (ansible --check).")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Do not prompt.")
	return cmd
}

// newPurgeImagesCmd builds `dx purge images` with its extra flags/vars.
func newPurgeImagesCmd(env *Env) *cobra.Command {
	var dangling, allDxdfir bool
	cmd := newCleanupActionCmd(env, "images", "docker",
		"Remove built get-sybers/* tool images so the next build is clean.",
		"Remove the get-sybers/* tool images? [y/N]: ",
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
	cmd.Aliases = []string{"docker"}
	cmd.Long = "Remove built get-sybers/* tool images (dxdfir_cleanup role, docker action).\n\n" +
		"By default only the hardened tool set is removed (the source of truth is the\n" +
		"GoDFIR-toolz submodule's images.yml manifest). --all-dxdfir removes EVERY\n" +
		"get-sybers/* image present; --dangling also prunes dangling layers."
	cmd.Flags().BoolVar(&dangling, "dangling", false, "Also prune dangling layers.")
	cmd.Flags().BoolVar(&allDxdfir, "all-dxdfir", false, "Remove EVERY get-sybers/* image (default: only the hardened tool set).")
	return cmd
}
