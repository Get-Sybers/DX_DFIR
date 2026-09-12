package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// The CAR stage is Ansible-orchestrated (dxdfir_car role): build / verify /
// timeline each front a thin playbook so the CLI drives Ansible, not Python
// directly. The processors still do the work — the role invokes them.

// newBuildCarCmd — `dxdfir build-car` → dxdfir-build-car.yml.
func newBuildCarCmd(env *Env) *cobra.Command {
	var (
		inPath    string
		out       string
		host      string
		artefacts string
		rebuild   bool
	)
	cmd := &cobra.Command{
		Use:   "build-car [PROCESSED_DIR]",
		Short: "Build the per-source CAR stores (car.db + superset.db) from processed evidence.",
		Long: "Build the per-source CAR stores from processed evidence, via the dxdfir_car\n" +
			"Ansible role.\n\n" +
			"Default (batch): discover every source under the processed tree (PROCESSED_DIR,\n" +
			"or <repo>/data_store/processed) and build each one's car.db + superset.db.\n" +
			"Single-source (--in): one processed file/dir -> one car.db. A source whose car.db\n" +
			"already exists is left as-is; pass --rebuild to re-derive it from the current maps.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"dxdfir_car_action=build"}
			if inPath != "" {
				vars = append(vars, "dxdfir_car_in="+inPath)
				vars = appendVar(vars, "dxdfir_car_out", out)
				vars = appendVar(vars, "dxdfir_car_host", host)
				vars = appendVar(vars, "dxdfir_car_artefacts", artefacts)
			} else {
				if len(args) > 0 && args[0] != "" {
					vars = append(vars, "dxdfir_car_processed_dir="+args[0])
				}
				vars = appendVar(vars, "dxdfir_car_out", out)
				if rebuild {
					vars = append(vars, "dxdfir_car_rebuild=true")
				}
			}
			plan, err := ansiblePlan(r, ap, "dxdfir-build-car.yml", vars, false)
			if err != nil {
				return err
			}
			code := run.Passthrough(context.Background(), plan, true)
			return exitCode(code)
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "", "Single-source: one processed file/dir -> one car.db.")
	cmd.Flags().StringVar(&out, "out", "", "Output dir (single-source: this source's car dir; batch: the car/ root).")
	cmd.Flags().StringVar(&host, "host", "", "Single-source: fallback source_host where the map derives none.")
	cmd.Flags().StringVar(&artefacts, "artefacts", "", "Single-source: comma-separated artefact map keys (default: route by filename).")
	cmd.Flags().BoolVar(&rebuild, "rebuild", false, "Rebuild CAR stores that already exist (e.g. after a map/coverage change).")
	return cmd
}

// newVerifyCarCmd — `dxdfir verify-car` → dxdfir-verify-car.yml (the CAR gate).
func newVerifyCarCmd(env *Env) *cobra.Command {
	var carDir string
	cmd := &cobra.Command{
		Use:   "verify-car",
		Short: "Run the CAR correctness gate over the materialised CAR tree.",
		Long: "Run the CAR correctness gate (dxdfir_car role, verify action) over the\n" +
			"materialised CAR (default <repo>/data_store/processed/car). Run the pipeline\n" +
			"first (process -> build-car).",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"dxdfir_car_action=verify"}
			vars = appendVar(vars, "dxdfir_car_dir", carDir)
			plan, err := ansiblePlan(r, ap, "dxdfir-verify-car.yml", vars, false)
			if err != nil {
				return err
			}
			code := run.Passthrough(context.Background(), plan, true)
			return exitCode(code)
		},
	}
	cmd.Flags().StringVar(&carDir, "car-dir", "", "The materialised CAR tree (default: <repo>/data_store/processed/car).")
	return cmd
}

// newCarTimelineCmd — `dxdfir car-timeline CAR_DIR` → dxdfir-car-timeline.yml.
func newCarTimelineCmd(env *Env) *cobra.Command {
	var (
		out    string
		host   string
		after  string
		before string
	)
	cmd := &cobra.Command{
		Use:   "car-timeline CAR_DIR",
		Short: "Build one property-rich, time-ordered CAR timeline from car.db + superset.db.",
		Long: "Build one property-rich, time-ordered CAR timeline (dxdfir_car role, timeline\n" +
			"action). Unions the object events and relationship edges from a source's CAR\n" +
			"stores into <car_dir>/timeline.jsonl. Point it at one source's car directory, or\n" +
			"a tree to aggregate every source under it.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"dxdfir_car_action=timeline", "dxdfir_car_timeline_dir=" + args[0]}
			vars = appendVar(vars, "dxdfir_car_timeline_out", out)
			vars = appendVar(vars, "dxdfir_car_timeline_host", host)
			vars = appendVar(vars, "dxdfir_car_timeline_after", after)
			vars = appendVar(vars, "dxdfir_car_timeline_before", before)
			plan, err := ansiblePlan(r, ap, "dxdfir-car-timeline.yml", vars, false)
			if err != nil {
				return err
			}
			code := run.Passthrough(context.Background(), plan, true)
			return exitCode(code)
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "Output path (default: <car_dir>/timeline.jsonl).")
	cmd.Flags().StringVar(&host, "host", "", "Only events whose source_host matches.")
	cmd.Flags().StringVar(&after, "after", "", "Only events at/after this ISO timestamp.")
	cmd.Flags().StringVar(&before, "before", "", "Only events at/before this ISO timestamp.")
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
