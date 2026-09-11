package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// newBuildCarCmd builds `dxdfir build-car`, which derives the per-source CAR
// stores (car.db + superset.db) from processed evidence via
// `python -m get_sybers_dxdfir.mitrecar`.
//
// Default (batch): discover every source under the processed tree and build
// each one. Single-source (--in): one processed file/dir -> one car.db.
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
		Long: "Build the per-source CAR stores from processed evidence.\n\n" +
			"Default (batch): discover every source under the processed tree (PROCESSED_DIR,\n" +
			"or <repo>/data_store/processed) and build each one's car.db + superset.db.\n" +
			"Single-source (--in): one processed file/dir -> one car.db. A source whose car.db\n" +
			"already exists is left as-is; pass --rebuild to re-derive it from the current maps.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			py, err := repo.Python()
			if err != nil {
				return Fail(127, "%v", err)
			}
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			var argv []string
			if inPath != "" {
				argv = []string{"-m", "get_sybers_dxdfir.mitrecar", "--in", inPath}
				for _, kv := range [][2]string{{"--out", out}, {"--host", host}, {"--artefacts", artefacts}} {
					if kv[1] != "" {
						argv = append(argv, kv[0], kv[1])
					}
				}
			} else {
				batch := r.Path("data_store", "processed")
				if len(args) > 0 && args[0] != "" {
					batch = args[0]
				}
				argv = []string{"-m", "get_sybers_dxdfir.mitrecar", "--batch", batch}
				if out != "" {
					argv = append(argv, "--out", out)
				}
				if rebuild { // the engine's own flag for "rebuild existing"
					argv = append(argv, "--force")
				}
			}
			code := run.Passthrough(context.Background(),
				run.Plan{Bin: py, Args: argv, Dir: r.Root}, true)
			if code != 0 {
				return ExitError{Code: code}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "", "Single-source: one processed file/dir -> one car.db.")
	cmd.Flags().StringVar(&out, "out", "", "Output dir (single-source: this source's car dir; batch: the car/ root).")
	cmd.Flags().StringVar(&host, "host", "", "Single-source: fallback source_host where the map derives none.")
	cmd.Flags().StringVar(&artefacts, "artefacts", "", "Single-source: comma-separated artefact map keys (default: route by filename).")
	cmd.Flags().BoolVar(&rebuild, "rebuild", false, "Rebuild CAR stores that already exist (e.g. after a map/coverage change).")
	return cmd
}

// newVerifyCarCmd builds `dxdfir verify-car`, the CAR correctness gate over the
// materialised CAR tree (`python -m get_sybers_dxdfir.carcheck`).
func newVerifyCarCmd(env *Env) *cobra.Command {
	var carDir string
	cmd := &cobra.Command{
		Use:   "verify-car",
		Short: "Run the CAR correctness gate over the materialised CAR tree.",
		Long: "Run the CAR correctness gate over the materialised CAR tree.\n\n" +
			"Checks the built CAR (default <repo>/data_store/processed/car) for a valid,\n" +
			"traceable model. Run the pipeline first (process -> build-car).",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			py, err := repo.Python()
			if err != nil {
				return Fail(127, "%v", err)
			}
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			dir := carDir
			if dir == "" {
				dir = r.Path("data_store", "processed", "car")
			}
			code := run.Passthrough(context.Background(),
				run.Plan{Bin: py, Args: []string{"-m", "get_sybers_dxdfir.carcheck", "--car-dir", dir}, Dir: r.Root}, true)
			if code != 0 {
				return ExitError{Code: code}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&carDir, "car-dir", "", "The materialised CAR tree (default: <repo>/data_store/processed/car).")
	return cmd
}

// newCarTimelineCmd builds `dxdfir car-timeline`, which unions a source's CAR
// object events and relationship edges into one time-ordered timeline.jsonl via
// `python -m get_sybers_dxdfir.mitrecar timeline <CAR_DIR>`.
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
		Long: "Build one property-rich, time-ordered CAR timeline.\n\n" +
			"Unions the object events and the relationship edges from a source's CAR stores\n" +
			"into <car_dir>/timeline.jsonl. Point it at one source's car directory, or a tree\n" +
			"to aggregate every source under it.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			py, err := repo.Python()
			if err != nil {
				return Fail(127, "%v", err)
			}
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			argv := []string{"-m", "get_sybers_dxdfir.mitrecar", "timeline", args[0]}
			for _, kv := range [][2]string{{"--out", out}, {"--host", host}, {"--after", after}, {"--before", before}} {
				if kv[1] != "" {
					argv = append(argv, kv[0], kv[1])
				}
			}
			code := run.Passthrough(context.Background(),
				run.Plan{Bin: py, Args: argv, Dir: r.Root}, true)
			if code != 0 {
				return ExitError{Code: code}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "Output path (default: <car_dir>/timeline.jsonl).")
	cmd.Flags().StringVar(&host, "host", "", "Only events whose source_host matches.")
	cmd.Flags().StringVar(&after, "after", "", "Only events at/after this ISO timestamp.")
	cmd.Flags().StringVar(&before, "before", "", "Only events at/before this ISO timestamp.")
	return cmd
}
