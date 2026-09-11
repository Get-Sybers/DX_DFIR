package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/run"
	"github.com/get-sybers/dx_dfir/go/internal/style"
)

// The analysis-stack lifecycle is Ansible-orchestrated (dxdfir_stack role): each
// verb fronts a thin dxdfir-stack-<action>.yml play. The stack (elastic|sofelk)
// rides on -e dxdfir_stack_name.

var validStacks = map[string]bool{"elastic": true, "sofelk": true}

// runStackAction drives one dxdfir-stack-<action>.yml with the stack selection
// and any action-specific vars.
func (env *Env) runStackAction(stack, action string, vars []string) error {
	if !validStacks[stack] {
		return Fail(2, "unknown stack %q — use one of: elastic, sofelk", stack)
	}
	r, ap, err := env.ansibleRepo()
	if err != nil {
		return err
	}
	all := append([]string{"dxdfir_stack_name=" + stack}, vars...)
	code := run.Passthrough(context.Background(),
		ansiblePlan(r, ap, "dxdfir-stack-"+action+".yml", all, false), true)
	return exitCode(code)
}

// newStackCmd builds the `dxdfir stack` group (deploy/destroy/start/stop/status),
// each driving the dxdfir_stack role. --stack/-s selects the stack.
func newStackCmd(env *Env) *cobra.Command {
	var stack string
	parent := &cobra.Command{
		Use:   "stack",
		Short: "Bring the analysis stack up/down (dxdfir_stack role around docker/elastic or docker/sof-elk).",
		Long: "Bring the analysis stack up/down via the dxdfir_stack Ansible role.\n\n" +
			"Lifecycle for the stacks under docker/elastic and docker/sof-elk. Select one\n" +
			"with --stack/-s (elastic|sofelk). Elastic requires docker/elastic/.env.",
	}
	parent.PersistentFlags().StringVarP(&stack, "stack", "s", "elastic", "Which stack to drive (elastic|sofelk).")

	var build, noBuild bool
	deploy := &cobra.Command{
		Use:   "deploy",
		Short: "Build (if needed) and bring the stack up, then verify it is running.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			vars := []string{"dxdfir_stack_build=" + boolVar(build && !noBuild)}
			if err := env.runStackAction(stack, "deploy", vars); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " " + stack + " stack deployed."))
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
				if !confirmYes(fmt.Sprintf(
					"Remove '%s' containers AND named volumes? This DELETES ingested data. [y/N]: ", stack)) {
					return Fail(1, "Aborted.")
				}
			}
			vars := []string{"dxdfir_stack_remove_volumes=" + boolVar(volumes)}
			if err := env.runStackAction(stack, "destroy", vars); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " " + stack + " stack destroyed."))
			return nil
		},
	}
	destroy.Flags().BoolVar(&volumes, "volumes", false, "Also remove named volumes (WIPES stack data).")
	destroy.Flags().BoolVarP(&destroyYes, "yes", "y", false, "Do not prompt.")

	start := &cobra.Command{
		Use: "start", Short: "Start EXISTING stopped containers.", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runStackAction(stack, "start", nil); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " " + stack + " stack started."))
			return nil
		},
	}
	stop := &cobra.Command{
		Use: "stop", Short: "Stop containers but keep them.", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runStackAction(stack, "stop", nil); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " " + stack + " stack stopped."))
			return nil
		},
	}
	status := &cobra.Command{
		Use: "status", Short: "Show container status.", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return env.runStackAction(stack, "status", nil)
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
