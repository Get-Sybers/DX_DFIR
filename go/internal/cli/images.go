package cli

import (
	"context"
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// newBuildDockerCmd — `dxdfir build-docker` → dxdfir-build-images.yml
// (dxdfir_images role): pull each get-sybers/* image from the registry and
// verify the hardening contract on the result. (Building lives upstream in the
// get_sybers.godfir_build collection; here the images are pulled, not built.)
func newBuildDockerCmd(env *Env) *cobra.Command {
	var (
		images    []string
		force     bool
		extraVars []string
	)
	cmd := &cobra.Command{
		Use:   "build-docker",
		Short: "Pull (and hardening-verify) the get-sybers/* tool images from the registry.",
		Long: "Provision the get-sybers/* tool images by REGISTRY PULL.\n\n" +
			"Fronts playbooks/dxdfir-build-images.yml: the images role delegates to the\n" +
			"get_sybers.godfir_run.godfir_images role (imported by URL), which pulls\n" +
			"ghcr.io/get-sybers/<tool>:<tag> and tags it to the local get-sybers/<tool>:latest\n" +
			"name. Building images lives upstream in get_sybers.godfir_build; the hardening\n" +
			"contract (non-root USER, com.get-sybers.hardened) is verified by godfir_images.",
		GroupID: groupSetup,
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			if !fileExists(r.Playbook("dxdfir-build-images.yml")) {
				return Fail(2, "build-images playbook not found: %s", r.Playbook("dxdfir-build-images.yml"))
			}
			var vars []string
			if force {
				vars = append(vars, "dxdfir_images_force=true")
			}
			if len(images) > 0 {
				// A JSON OBJECT extra-var so ansible types the value as a list. A
				// `key=value` -e is always a STRING (the role's `loop` rejects it),
				// and -e has higher precedence than any set_fact coercion — so the
				// list must arrive typed from here.
				blob, _ := json.Marshal(map[string][]string{"dxdfir_images_set": images})
				vars = append(vars, string(blob))
			}
			vars = append(vars, extraVars...)
			plan, err := ansiblePlan(r, ap, "dxdfir-build-images.yml", vars, false)
			if err != nil {
				return err
			}
			code := run.Passthrough(context.Background(), plan, true)
			return exitCode(code)
		},
	}
	cmd.Flags().StringArrayVarP(&images, "image", "i", nil,
		"Restrict the build set to this image (repeatable). Default: build every get-sybers/* tool image.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Rebuild even when the image already exists (docker layer cache still applies).")
	cmd.Flags().StringArrayVarP(&extraVars, "extra-var", "e", nil,
		"Extra Ansible var KEY=VALUE (repeatable).")
	return cmd
}

// newVerifyImagesCmd — `dxdfir verify-images` → dxdfir-verify-images.yml: audit
// the hardened get-sybers/* tool-image inventory (non-clean inventory exits non-zero).
func newVerifyImagesCmd(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "verify-images",
		Short: "Audit the hardened get-sybers/* tool-image inventory.",
		Long: "Audit the hardened get-sybers/* tool-image inventory (dxdfir-verify-images.yml).\n\n" +
			"Fails if any expected tool image is missing or un-hardened, or if an\n" +
			"UNEXPECTED get-sybers/* image is present.",
		GroupID: groupSetup,
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			plan, err := ansiblePlan(r, ap, "dxdfir-verify-images.yml", nil, false)
			if err != nil {
				return err
			}
			code := run.Passthrough(context.Background(), plan, true)
			return exitCode(code)
		},
	}
}
