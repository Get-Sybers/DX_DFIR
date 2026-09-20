package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// newStampDetectionsCmd builds `dxdfir stamp-detections`, a transparent
// passthrough to `python -m get_sybers_dxdfir.detect.car_detections` — the
// car-detections lookup-index writer (Byakugan#99 phase 6). Flag parsing is
// disabled so every token reaches the Python entrypoint verbatim, exactly
// like newStixCmd: this verb is a second Python-backed CAR command, not an
// Ansible-orchestrated one (car.go's newLoadCarCmd et al.).
func newStampDetectionsCmd(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "stamp-detections [TREE]",
		Short: "Stamp Byakugan's behaviour hits (STIX sightings) into the car-detections lookup index.",
		Long: "Project the behaviour hits Byakugan's `--stix` export already materialises\n" +
			"(STIX Sightings in each source's stix_bundle.json under the CAR tree) into the\n" +
			"car-detections lookup index, per the join-keys.yml contract\n" +
			"(python/get_sybers_dxdfir/detect/rules/car-detections/). Writes\n" +
			"car-detections.bulk.ndjson next to the tree (or --out) by default; --post also\n" +
			"PUTs the index template (skipped when already equal) and bulk-loads the stack.\n\n" +
			"All arguments pass through to `python -m get_sybers_dxdfir.detect.car_detections`\n" +
			"(-h for its flags: --out, --post, --url, --ca, ...). Does not implement the\n" +
			"logs-car.behaviour-* stream or the Detection-Engine-alert sweep join-keys.yml\n" +
			"itself describes (both still future work).",
		GroupID:            groupCAR,
		DisableFlagParsing: true,
		RunE: func(_ *cobra.Command, args []string) error {
			py, err := repo.Python()
			if err != nil {
				return Fail(127, "%v", err)
			}
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			plan := run.Plan{
				Bin:  py,
				Args: append([]string{"-m", "get_sybers_dxdfir.detect.car_detections"}, args...),
				Dir:  r.Root,
			}
			code := run.Passthrough(context.Background(), plan, false)
			if code != 0 {
				return ExitError{Code: code}
			}
			return nil
		},
	}
}
