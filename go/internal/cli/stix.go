package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// newStixCmd builds `dxdfir stix`, a transparent passthrough to
// `python -m get_sybers_dxdfir.stix`. Flag parsing is disabled so every token
// (including subcommand names and their flags) reaches the Python entrypoint
// verbatim. The echo is suppressed because stix writes machine-readable data to
// stdout and its own summary to stderr — the child's stdio is inherited, so the
// payload stays pipe-clean.
func newStixCmd(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:                "stix",
		Short:              "STIX 2.1 / OpenCTI exchange (export | behaviour-sightings | pull | sightings). Data → stdout, summary → stderr.",
		Long:               "STIX 2.1 / OpenCTI exchange (export | behaviour-sightings | pull | sightings).\n\nAll arguments pass through to `python -m get_sybers_dxdfir.stix`. Data → stdout, summary → stderr.",
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
				Args: append([]string{"-m", "get_sybers_dxdfir.stix"}, args...),
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
