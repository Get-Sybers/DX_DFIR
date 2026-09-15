package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/run"
	"github.com/get-sybers/dx_dfir/go/internal/style"
)

// The analysis-stack lifecycle is Ansible-orchestrated (dxdfir_stack role): each
// verb fronts a thin dxdfir-stack-<action>.yml play driving the Elastic stack
// under docker/elastic.

// runStackAction drives one dxdfir-stack-<action>.yml with any action-specific
// vars.
func (env *Env) runStackAction(action string, vars []string) error {
	r, ap, err := env.ansibleRepo()
	if err != nil {
		return err
	}
	plan, err := ansiblePlan(r, ap, "dxdfir-stack-"+action+".yml", vars, false)
	if err != nil {
		return err
	}
	code := run.Passthrough(context.Background(), plan, true)
	return exitCode(code)
}

// newStackCmd builds the `dxdfir stack` group (deploy/destroy/start/stop/status),
// each driving the dxdfir_stack role around the Elastic stack.
func newStackCmd(env *Env) *cobra.Command {
	parent := &cobra.Command{
		Use:   "stack",
		Short: "Bring the Elastic analysis stack up/down (dxdfir_stack role around docker/elastic).",
		Long: "Bring the Elastic analysis stack up/down via the dxdfir_stack Ansible role.\n\n" +
			"Lifecycle for the stack under docker/elastic. Deploy requires docker/elastic/.env.",
	}

	var build, noBuild bool
	deploy := &cobra.Command{
		Use:   "deploy",
		Short: "Build (if needed) and bring the stack up, then verify it is running.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			vars := []string{"dxdfir_stack_build=" + boolVar(build && !noBuild)}
			if err := env.runStackAction("deploy", vars); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " Elastic stack deployed."))
			return nil
		},
	}
	deploy.Flags().BoolVar(&build, "build", true, "Build images before starting.")
	deploy.Flags().BoolVar(&noBuild, "no-build", false, "Do not build images before starting.")

	var volumes, destroyYes bool
	destroy := &cobra.Command{
		Use:   "destroy",
		Short: "Stop and remove the stack's containers/networks (optionally its volumes).",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if volumes && !destroyYes {
				if !confirmYes(
					"Remove Elastic stack containers AND named volumes? This DELETES ingested data. [y/N]: ") {
					return Fail(1, "Aborted.")
				}
			}
			vars := []string{"dxdfir_stack_remove_volumes=" + boolVar(volumes)}
			if err := env.runStackAction("destroy", vars); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " Elastic stack destroyed."))
			return nil
		},
	}
	destroy.Flags().BoolVar(&volumes, "volumes", false, "Also remove named volumes (WIPES stack data).")
	destroy.Flags().BoolVarP(&destroyYes, "yes", "y", false, "Do not prompt.")

	start := &cobra.Command{
		Use: "start", Short: "Start EXISTING stopped containers.", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runStackAction("start", nil); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " Elastic stack started."))
			return nil
		},
	}
	stop := &cobra.Command{
		Use: "stop", Short: "Stop containers but keep them.", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runStackAction("stop", nil); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " Elastic stack stopped."))
			return nil
		},
	}
	status := &cobra.Command{
		Use: "status", Short: "Show container status.", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return env.runStackAction("status", nil)
		},
	}

	parent.AddCommand(deploy, destroy, start, stop, status)
	return parent
}

func boolVar(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
