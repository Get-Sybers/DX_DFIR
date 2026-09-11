package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
	"github.com/get-sybers/dx_dfir/go/internal/style"
)

// stackComposeSubdir maps the --stack value to its directory under docker/.
var stackComposeSubdir = map[string]string{"elastic": "elastic", "sofelk": "sof-elk"}

// stackCompose validates the stack name, resolves the repo, and returns the
// docker-compose file plus its directory (the compose cwd, so relative volume
// mounts and .env resolve). Errors already carry the exit contract: 2 for a bad
// stack name or a missing compose file.
func (env *Env) stackCompose(stack string) (composeFile, composeDir string, err error) {
	sub, ok := stackComposeSubdir[stack]
	if !ok {
		return "", "", Fail(2, "unknown stack %q — use one of: elastic, sofelk", stack)
	}
	r, err := env.resolveRepo()
	if err != nil {
		return "", "", err
	}
	composeDir = r.Path("docker", sub)
	composeFile = filepath.Join(composeDir, "docker-compose.yml")
	if !fileExists(composeFile) {
		return "", "", Fail(2, "no docker-compose.yml under %s", composeDir)
	}
	return composeFile, composeDir, nil
}

// runCompose runs `docker compose -f <file> <verbArgs...>` from the compose dir.
func (env *Env) runCompose(stack string, verbArgs ...string) error {
	if err := repo.Require("docker"); err != nil {
		return Fail(127, "%v", err)
	}
	composeFile, composeDir, err := env.stackCompose(stack)
	if err != nil {
		return err
	}
	args := append([]string{"compose", "-f", composeFile}, verbArgs...)
	code := run.Passthrough(context.Background(),
		run.Plan{Bin: "docker", Args: args, Dir: composeDir}, true)
	if code != 0 {
		return ExitError{Code: code}
	}
	return nil
}

// newStackCmd builds the `dxdfir stack` group: docker compose around the
// analysis stacks under docker/elastic and docker/sof-elk. The bare group prints
// help; the --stack/-s persistent flag selects which stack each subcommand
// drives.
func newStackCmd(env *Env) *cobra.Command {
	var stack string

	parent := &cobra.Command{
		Use:   "stack",
		Short: "Bring the analysis stack up/down (docker compose around docker/elastic or docker/sof-elk).",
		Long: "Bring the analysis stack up/down.\n\n" +
			"Thin wrapper over `docker compose` for the stacks under docker/elastic and\n" +
			"docker/sof-elk. Select one with --stack/-s (elastic|sofelk).",
	}
	parent.PersistentFlags().StringVarP(&stack, "stack", "s", "elastic", "Which stack to drive (elastic|sofelk).")

	var build, noBuild bool
	deploy := &cobra.Command{
		Use:   "deploy",
		Short: "Build (if needed) and start the stack in the background (`docker compose up -d`).",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			args := []string{"up", "-d", "--remove-orphans"}
			if build && !noBuild {
				args = []string{"up", "--build", "-d", "--remove-orphans"}
			}
			if err := env.runCompose(stack, args...); err != nil {
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
			args := []string{"down", "--remove-orphans"}
			if volumes {
				args = append(args, "--volumes")
			}
			if err := env.runCompose(stack, args...); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " " + stack + " stack destroyed."))
			return nil
		},
	}
	destroy.Flags().BoolVar(&volumes, "volumes", false, "Also remove named volumes (WIPES stack data).")
	destroy.Flags().BoolVarP(&destroyYes, "yes", "y", false, "Do not prompt.")

	start := &cobra.Command{
		Use:   "start",
		Short: "Start EXISTING stopped containers (`docker compose start`).",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runCompose(stack, "start"); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " " + stack + " stack started."))
			return nil
		},
	}

	stop := &cobra.Command{
		Use:   "stop",
		Short: "Stop containers but keep them (`docker compose stop`).",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := env.runCompose(stack, "stop"); err != nil {
				return err
			}
			fmt.Println(style.Green(style.GlyphOK + " " + stack + " stack stopped."))
			return nil
		},
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Show container status (`docker compose ps`).",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return env.runCompose(stack, "ps")
		},
	}

	parent.AddCommand(deploy, destroy, start, stop, status)
	return parent
}
