package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Get-Sybers/DX_DFIR/go/internal/run"
	"github.com/Get-Sybers/DX_DFIR/go/internal/style"
)

// The analysis-stack lifecycle is Ansible-orchestrated (dxdfir_stack role): each
// verb fronts a thin dxdfir-stack-<action>.yml play around the dxdfir_stack role.
//
// The verbs read verb first — `deploy stack`, `start stack`, `stop stack`,
// `restart stack`, `status stack`, `update stack` — with `stack` the noun child
// of each verb. The noun is required (a bare verb prints its targets), so a
// later target such as another service cannot collide. `purge stack` (the
// destructive teardown) lives with the other purge targets in purge.go.

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
	"reads the host first: status reports a host with no stack, start/stop/purge\n" +
	"flag it, and deploy installs docker when missing, then converges the stack —\n" +
	"a compose-era deployment is migrated in place, its data volumes untouched."

// leafFn builds one spelling of a leaf command under the given Use line.
type leafFn func(env *Env, use string) *cobra.Command

// stackVerb builds a verb-first stack command: `<verb>` is the parent (bare, it
// prints its targets), `<verb> stack` the leaf that runs the action.
func stackVerb(env *Env, leaf leafFn, verb, short string) *cobra.Command {
	cmd := nounGroup(verb, short, short+"\n\n"+stackLong+"\n\n"+
		"The noun is required: `dx "+verb+" stack` (or `stacks`).")
	cmd.GroupID = groupStack
	child := leaf(env, "stack")
	child.Aliases = []string{"stacks"}
	cmd.AddCommand(child)
	return cmd
}

func newDeployCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackDeployLeaf, "deploy", "Bring the analysis stack up from inventory data, then verify it (deploy stack).")
}

func newStartCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackStartLeaf, "start", "Start the analysis stack's existing stopped containers (start stack).")
}

func newStopCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackStopLeaf, "stop", "Stop the analysis stack's containers but keep them (stop stack).")
}

func newRestartCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackRestartLeaf, "restart", "Restart the analysis stack: stop its containers, then start them again (restart stack).")
}

func newStatusCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackStatusLeaf, "status", "Show the analysis stack's container status (status stack).")
}

func newUpdateCmd(env *Env) *cobra.Command {
	return stackVerb(env, stackUpdateLeaf, "update", "Re-converge the analysis stack onto the current inventory/images (update stack).")
}

// ---- the actions, one leaf builder each ----

func stackDeployLeaf(env *Env, use string) *cobra.Command {
	return &cobra.Command{
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

// stackRestartLeaf composes the existing stop and start plays — no new playbook:
// stop the running containers, then start them again. A stop failure aborts
// before the start so a half-restarted stack is never left silently.
func stackRestartLeaf(env *Env, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: "Stop the stack's containers, then start them again.",
		Long: "Restart the stack: stop its containers, then start them again.\n\n" +
			"Composed from the stop and start plays (no data is removed).\n\n" + stackLong,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runStackAction("stop", nil); err != nil {
				return err
			}
			if err := env.runStackAction("start", nil); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " elastic stack restarted."))
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

// stackUpdateLeaf re-runs the deploy play, which converges the stack onto the
// current inventory and pulled images — i.e. an in-place update. It reuses the
// deploy play rather than inventing an update-specific one.
func stackUpdateLeaf(env *Env, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: "Re-converge the stack onto the current inventory/images (in-place update).",
		Long: "Re-converge the stack onto the current inventory and pulled images — an\n" +
			"in-place update. Runs the deploy play, which is idempotent: unchanged\n" +
			"services are left as they are, changed ones are rolled forward.\n\n" + stackLong,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runStackAction("deploy", nil); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " elastic stack updated."))
			return nil
		},
	}
}

func boolVar(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
