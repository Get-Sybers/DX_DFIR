package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// newValidateCmd builds `dxdfir validate`, a thin front for the repository check
// harness (tests/run-checks.sh). It requires bash on PATH and runs the script
// with the repo root as cwd, propagating its exit code.
func newValidateCmd(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Run the repository check harness (fronts tests/run-checks.sh).",
		Long: "Run the repository check harness.\n\n" +
			"Fronts tests/run-checks.sh from the repo root, streaming its output live and\n" +
			"propagating its exit status. Requires bash on PATH.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := repo.Require("bash"); err != nil {
				return Fail(127, "%v", err)
			}
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			checks := r.Path("tests", "run-checks.sh")
			if !fileExists(checks) {
				return Fail(2, "check harness not found: %s", checks)
			}
			code := run.Passthrough(context.Background(),
				run.Plan{Bin: "bash", Args: []string{checks}, Dir: r.Root}, true)
			if code != 0 {
				return ExitError{Code: code}
			}
			return nil
		},
	}
}
