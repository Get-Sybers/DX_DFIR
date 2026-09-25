package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/run"
	"github.com/get-sybers/dx_dfir/go/internal/style"
)

// The analysis-stack lifecycle is Ansible-orchestrated (dxdfir_stack role): each
// verb fronts a thin dxdfir-stack-<action>.yml play around the dxdfir_stack role.
//
// The verbs read verb first — `deploy stack`, `destroy stack`, `start stack`,
// `stop stack`, `status stack` — with `stack` the noun child of each verb. The
// noun is required (a bare verb prints its targets), so a later target such as
// another service cannot collide. Each action's leaf builder returns a fresh
// *cobra.Command so the hidden `stack <verb>` alias group can wrap the same
// body under its own instance.

// runStackAction drives one dxdfir-stack-<action>.yml with any action-specific vars.
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

// stackLong is the shared description of the stack the verbs act on.
const stackLong = "The Elastic analysis stack, deployed by the dxdfir_stack Ansible role from\n" +
	"inventory data (ansible/collections/.../playbooks/group_vars/all.yml; secrets\n" +
	"generated into ansible/inventory/secrets/<host>/, vault-overridable). Preflight\n" +
	"reads the host first: status reports a host with no stack, start/stop/destroy\n" +
	"flag it, and deploy installs docker when missing, then converges the stack —\n" +
	"a compose-era deployment is migrated in place, its data volumes untouched."

// stackVerb builds a verb-first stack command: `<verb>` is the parent (bare, it
// prints its targets), `<verb> stack` the leaf that runs the action.
func stackVerb(env *Env, leaf leafFn, verb, short string) *cobra.Command {
	cmd := nounGroup(verb, short, short+"\n\n"+stackLong+"\n\n"+
		"The noun is required: `dxdfir "+verb+" stack` (or `stacks`).")
	cmd.GroupID = groupStack
	child := leaf(env, "stack")
	child.Aliases = []string{"stacks"}
	cmd.AddCommand(child)
	return cmd
}

func newDeployCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackDeployLeaf, "deploy", "Bring the analysis stack up from inventory data, then verify it (deploy stack).")
}

func newDestroyCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackDestroyLeaf, "destroy", "Stop and remove the analysis stack's containers/networks (destroy stack).")
}

func newStartCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackStartLeaf, "start", "Start the analysis stack's existing stopped containers (start stack).")
}

func newStopCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackStopLeaf, "stop", "Stop the analysis stack's containers but keep them (stop stack).")
}

func newStatusCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackStatusLeaf, "status", "Show the analysis stack's container status (status stack).")
}

// newStackCmd builds the hidden `dxdfir stack <verb>` alias group: the noun-first
// spelling the stack verbs had before the grammar went verb first. Each child
// still runs its action, printing cobra's deprecation note (to stderr) with the
// verb-first spelling to use instead.
func newStackCmd(env *Env) *cobra.Command {
	parent := nounGroup("stack",
		"Deprecated noun-first spelling of the stack verbs.",
		"Deprecated noun-first spelling of the stack verbs. Each still runs and prints\n"+
			"the verb-first form to use instead:\n\n"+
			"  stack deploy   ->  deploy stack\n"+
			"  stack destroy  ->  destroy stack\n"+
			"  stack start    ->  start stack\n"+
			"  stack stop     ->  stop stack\n"+
			"  stack status   ->  status stack")
	parent.Hidden = true
	parent.Aliases = []string{"stacks"}
	for _, alias := range []struct {
		leaf leafFn
		verb string
	}{
		{stackDeployLeaf, "deploy"},
		{stackDestroyLeaf, "destroy"},
		{stackStartLeaf, "start"},
		{stackStopLeaf, "stop"},
		{stackStatusLeaf, "status"},
	} {
		cmd := alias.leaf(env, alias.verb)
		cmd.Deprecated = "use: dxdfir " + alias.verb + " stack"
		parent.AddCommand(cmd)
	}
	return parent
}

// ---- the actions, one leaf builder each ----

func stackDeployLeaf(env *Env, use string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: "Bring the stack up from inventory data, then verify it is running.",
		Long:  "Bring the stack up from inventory data, then verify it is running.\n\n" + stackLong,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runStackAction("deploy", nil); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " elastic stack deployed."))
			return nil
		},
	}
	return cmd
}

func stackDestroyLeaf(env *Env, use string) *cobra.Command {
	var volumes, yes bool
	cmd := &cobra.Command{
		Use:   use,
		Short: "Stop and remove the stack's containers/networks (optionally its volumes).",
		Long:  "Stop and remove the stack's containers/networks (optionally its volumes).\n\n" + stackLong,
		Args:  cobra.NoArgs,
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
			fmt.Println(style.Green(style.GlyphOK + " elastic stack destroyed."))
			return nil
		},
	}
	cmd.Flags().BoolVar(&volumes, "volumes", false, "Also remove named volumes (WIPES stack data).")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Do not prompt.")
	return cmd
}

func stackStartLeaf(env *Env, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: "Start EXISTING stopped containers.",
		Long:  "Start EXISTING stopped containers.\n\n" + stackLong,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runStackAction("start", nil); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " elastic stack started."))
			return nil
		},
	}
}

func stackStopLeaf(env *Env, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: "Stop containers but keep them.",
		Long:  "Stop containers but keep them.\n\n" + stackLong,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runStackAction("stop", nil); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " elastic stack stopped."))
			return nil
		},
	}
}

func stackStatusLeaf(env *Env, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: "Show container status.",
		Long:  "Show container status.\n\n" + stackLong,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return env.runStackAction("status", nil)
		},
	}
}

func boolVar(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
