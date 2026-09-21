package cli

import (
	"context"
	"errors"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// The CAR stage is Ansible-orchestrated (dxdfir_byakugan role): build / verify /
// timeline each front a thin playbook so the CLI drives Ansible, which runs the
// get-sybers/byakugan image from its contract (env vars + mounts).

// newBuildCarCmd — `dxdfir build-car` → dxdfir-build-car.yml.
func newBuildCarCmd(env *Env) *cobra.Command {
	var (
		out     string
		rebuild bool
		derive  bool
		stix    bool
	)
	cmd := &cobra.Command{
		Use:   "build-car [PROCESSED_DIR]",
		Short: "Build the per-source CAR stores (car_<object>.jsonl + car_relationships.jsonl) from processed evidence.",
		Long: "Build the per-source CAR stores from processed evidence, via the dxdfir_byakugan\n" +
			"Ansible role (`byakugan build` over the processed tree).\n\n" +
			"Discovers every source under the processed tree (PROCESSED_DIR, or\n" +
			"<repo>/data_store/processed) and builds each one's car_<object>.jsonl (per\n" +
			"populated object) plus car_relationships.jsonl (always written, even empty)\n" +
			"under the CAR tree (--out, or <repo>/data_store/processed/byakugan). A source whose\n" +
			"car_relationships.jsonl already exists is left as-is; pass --rebuild to re-derive it\n" +
			"from the current maps. --derive adds the derived relationship pass\n" +
			"(car_inferred.jsonl); --stix also derives the STIX 2.1 bundle.",
		GroupID: groupCAR,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"dxdfir_byakugan_action=build"}
			if len(args) > 0 && args[0] != "" {
				vars = append(vars, "dxdfir_byakugan_processed_dir="+args[0])
			}
			vars = appendVar(vars, "dxdfir_byakugan_dir", out)
			if rebuild {
				vars = append(vars, "dxdfir_byakugan_rebuild=true")
			}
			if derive {
				vars = append(vars, "dxdfir_byakugan_derive=true")
			}
			if stix {
				vars = append(vars, "dxdfir_byakugan_stix=true")
			}
			plan, err := ansiblePlan(r, ap, "dxdfir-build-car.yml", vars, false)
			if err != nil {
				return err
			}
			code := run.Passthrough(context.Background(), plan, true)
			return exitCode(code)
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "The CAR tree to write (default: <repo>/data_store/processed/byakugan).")
	cmd.Flags().BoolVar(&rebuild, "rebuild", false, "Rebuild CAR stores that already exist (e.g. after a map/coverage change).")
	cmd.Flags().BoolVar(&derive, "derive", false, "Also run the derived relationship pass into car_inferred.jsonl.")
	cmd.Flags().BoolVar(&stix, "stix", false, "Also derive the STIX 2.1 bundle from the finished stores.")
	return cmd
}

// newVerifyCarCmd — `dxdfir verify-car` → dxdfir-verify-car.yml (the CAR gate).
func newVerifyCarCmd(env *Env) *cobra.Command {
	var carDir string
	cmd := &cobra.Command{
		Use:   "verify-car",
		Short: "Run the CAR correctness gate over the materialised CAR tree.",
		Long: "Run the CAR correctness gate (dxdfir_byakugan role, verify action) over the\n" +
			"materialised CAR (default <repo>/data_store/processed/byakugan). Run the pipeline\n" +
			"first (process -> build-car).",
		GroupID: groupCAR,
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"dxdfir_byakugan_action=verify"}
			vars = appendVar(vars, "dxdfir_byakugan_dir", carDir)
			plan, err := ansiblePlan(r, ap, "dxdfir-verify-car.yml", vars, false)
			if err != nil {
				return err
			}
			code := run.Passthrough(context.Background(), plan, true)
			return exitCode(code)
		},
	}
	cmd.Flags().StringVar(&carDir, "car-dir", "", "The materialised CAR tree (default: <repo>/data_store/processed/byakugan).")
	return cmd
}

// newCarTimelineCmd — `dxdfir build-timeline CAR_DIR` → dxdfir-car-timeline.yml.
// Verb-first spelling; `car-timeline` stays as an alias.
func newCarTimelineCmd(env *Env) *cobra.Command {
	var (
		outDir string
		force  bool
		host   string
		after  string
		before string
	)
	cmd := &cobra.Command{
		Use:     "build-timeline CAR_DIR",
		Aliases: []string{"car-timeline"},
		Short:   "Build one property-rich, time-ordered CAR timeline from car_<object>.jsonl + car_relationships.jsonl.",
		Long: "Build one property-rich, time-ordered CAR timeline (dxdfir_byakugan role, timeline\n" +
			"action — `byakugan timeline`). Unions the object events and relationship edges\n" +
			"from a source's CAR stores into timeline.jsonl beside them (or under --out-dir).\n" +
			"Point it at one source's car directory, or a tree to aggregate every source under\n" +
			"it. An existing timeline.jsonl is kept unless --force.",
		GroupID: groupCAR,
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"dxdfir_byakugan_action=timeline", "dxdfir_byakugan_timeline_dir=" + args[0]}
			vars = appendVar(vars, "dxdfir_byakugan_timeline_out_dir", outDir)
			if force {
				vars = append(vars, "dxdfir_byakugan_timeline_force=true")
			}
			vars = appendVar(vars, "dxdfir_byakugan_timeline_host", host)
			vars = appendVar(vars, "dxdfir_byakugan_timeline_after", after)
			vars = appendVar(vars, "dxdfir_byakugan_timeline_before", before)
			plan, err := ansiblePlan(r, ap, "dxdfir-car-timeline.yml", vars, false)
			if err != nil {
				return err
			}
			code := run.Passthrough(context.Background(), plan, true)
			return exitCode(code)
		},
	}
	cmd.Flags().StringVar(&outDir, "out-dir", "", "Directory timeline.jsonl is written to (default: CAR_DIR itself).")
	cmd.Flags().BoolVar(&force, "force", false, "Rewrite an existing timeline.jsonl.")
	cmd.Flags().StringVar(&host, "host", "", "Only events whose source_host matches.")
	cmd.Flags().StringVar(&after, "after", "", "Only events at/after this ISO timestamp.")
	cmd.Flags().StringVar(&before, "before", "", "Only events at/before this ISO timestamp.")
	return cmd
}

// newLoadCarCmd — `dxdfir load-car` → dxdfir-load-car.yml.
func newLoadCarCmd(env *Env) *cobra.Command {
	var (
		namespace string
		setup     bool
		noSetup   bool
		force     bool
		kibana    bool
	)
	cmd := &cobra.Command{
		Use:   "load-car",
		Short: "Bulk-load the materialised CAR tree into the Elastic stack's logs-car.* data streams.",
		Long: "Bulk-load the materialised CAR tree into the analysis stack, via the dxdfir_car_load\n" +
			"Ansible role (`byakugan load` pushed into logs-car.<object>-<namespace> x13,\n" +
			"logs-car.rel-<namespace> and logs-car.inferred-<namespace>).\n\n" +
			"Requires the analysis stack (`deploy stack`) and a built CAR (`build-car`); brings\n" +
			"the stack up first if it is not already running. --setup (default) applies the\n" +
			"logs-car.* index/component templates before loading and authenticates as the\n" +
			"elastic superuser; pass --no-setup for routine repeat loads once the templates\n" +
			"exist, which authenticates as the least-privilege byakugan_loader identity\n" +
			"instead. --kibana also imports the rendered Kibana saved objects (only sent when\n" +
			"--setup is also on).",
		GroupID: groupCAR,
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// The saved-objects import only runs in the setup pass (the role
			// ignores it otherwise) — refuse the silently-ignored combination
			// instead of leaving "why did no dashboards import" to forensics.
			if kibana && (!setup || noSetup) {
				return errors.New("--kibana requires --setup: the Kibana saved-objects import runs in the setup pass")
			}
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"dxdfir_car_load_action=load"}
			vars = appendVar(vars, "dxdfir_car_load_namespace", namespace)
			vars = append(vars, "dxdfir_car_load_setup="+boolVar(setup && !noSetup))
			if force {
				vars = append(vars, "dxdfir_car_load_force=true")
			}
			if kibana {
				vars = append(vars, "dxdfir_car_load_kibana_import=true")
			}
			plan, err := ansiblePlan(r, ap, "dxdfir-load-car.yml", vars, false)
			if err != nil {
				return err
			}
			code := run.Passthrough(context.Background(), plan, true)
			return exitCode(code)
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Elastic data-stream namespace (default: default).")
	cmd.Flags().BoolVar(&setup, "setup", true, "Apply the logs-car.* templates before loading (first run).")
	cmd.Flags().BoolVar(&noSetup, "no-setup", false, "Skip template setup — routine repeat loads once they exist.")
	cmd.Flags().BoolVar(&force, "force", false, "Re-render and re-push even when already loaded.")
	cmd.Flags().BoolVar(&kibana, "kibana", false, "Also import the rendered Kibana saved objects (requires --setup).")
	return cmd
}

// appendVar appends an -e KEY=VALUE only when value is non-empty.
func appendVar(vars []string, key, value string) []string {
	if value == "" {
		return vars
	}
	return append(vars, key+"="+value)
}

// exitCode maps a passthrough exit code to the RunE error contract.
func exitCode(code int) error {
	if code != 0 {
		return ExitError{Code: code}
	}
	return nil
}
