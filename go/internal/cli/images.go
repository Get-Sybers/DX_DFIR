package cli

import (
	"context"
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// newBuildDockerCmd builds `dxdfir build-docker`, which fronts the
// dxdfir-build-images.yml play (the dxdfir_images role): it builds each dxdfir/*
// tool image from its ansible-hardened Dockerfile and asserts the hardening
// contract on the result. Run it once per host before first processing, and
// again after changing anything under docker/.
func newBuildDockerCmd(env *Env) *cobra.Command {
	var (
		images    []string
		force     bool
		extraVars []string
	)
	cmd := &cobra.Command{
		Use:   "build-docker",
		Short: "Build (and hardening-verify) the dxdfir/* tool images from the in-repo Dockerfiles.",
		Long: "Build (and hardening-verify) the dxdfir/* tool images.\n\n" +
			"Fronts playbooks/dxdfir-build-images.yml: builds each image from its\n" +
			"ansible-hardened Dockerfile under docker/, then asserts the hardening contract\n" +
			"on the result (fixed non-root USER, com.get-sybers.hardened label, no package\n" +
			"managers or interpreters in the tool-only images).",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ap, err := repo.AnsiblePlaybook()
			if err != nil {
				return Fail(127, "%v", err)
			}
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			playbook := r.Playbook("dxdfir-build-images.yml")
			if !fileExists(playbook) {
				return Fail(2, "build-images playbook not found: %s", playbook)
			}
			args := []string{"-i", "localhost,", "-c", "local", playbook}
			if force {
				args = append(args, "-e", "dxdfir_images_force=true")
			}
			if len(images) > 0 {
				// JSON so ansible parses it as a list, matching the play's own docs.
				set, _ := json.Marshal(images)
				args = append(args, "-e", "dxdfir_images_set="+string(set))
			}
			for _, kv := range extraVars {
				args = append(args, "-e", kv)
			}
			plan := run.Plan{
				Bin:  ap,
				Args: args,
				Dir:  r.Root,
				Env:  []string{"ANSIBLE_ROLES_PATH=" + r.RolesPath()},
			}
			code := run.Passthrough(context.Background(), plan, true)
			if code != 0 {
				return ExitError{Code: code}
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVarP(&images, "image", "i", nil,
		"Restrict the build set to this image (repeatable). Default: build every dxdfir/* tool image.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Rebuild even when the image already exists (docker layer cache still applies).")
	cmd.Flags().StringArrayVarP(&extraVars, "extra-var", "e", nil,
		"Extra Ansible var KEY=VALUE (repeatable).")
	return cmd
}

// newVerifyImagesCmd builds `dxdfir verify-images`, which audits the hardened
// dxdfir/* tool-image inventory via `python -m get_sybers_dxdfir.images
// --audit`. The audit prints its JSON report to stdout and any violations to
// stderr; this verb just propagates its exit status (1 if not clean).
func newVerifyImagesCmd(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "verify-images",
		Short: "Audit the hardened dxdfir/* tool-image inventory.",
		Long: "Audit the hardened dxdfir/* tool-image inventory.\n\n" +
			"Fails if any expected tool image is missing or un-hardened, or if an\n" +
			"UNEXPECTED dxdfir/* image is present. The report goes to stdout, violations to\n" +
			"stderr, and a non-clean inventory exits 1.",
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
			plan := run.Plan{Bin: py, Args: []string{"-m", "get_sybers_dxdfir.images", "--audit"}, Dir: r.Root}
			code := run.Passthrough(context.Background(), plan, true)
			if code != 0 {
				return ExitError{Code: code}
			}
			return nil
		},
	}
}
