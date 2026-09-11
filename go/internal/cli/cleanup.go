package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
	"github.com/get-sybers/dx_dfir/go/internal/style"
)

// removeChildrenPreservingGitkeep removes every child of root (files, symlinks,
// and subdirs recursively) except a top-level ".gitkeep". It returns the number
// of top-level files/symlinks and top-level directories removed (dirs are
// removed whole with os.RemoveAll but count once). When dryRun is set nothing is
// removed but the same counts are reported.
func removeChildrenPreservingGitkeep(root string, dryRun bool) (files, dirs int, err error) {
	entries, err := os.ReadDir(root) // sorted by name
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		if e.Name() == ".gitkeep" {
			continue
		}
		full := filepath.Join(root, e.Name())
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
			files++
			if !dryRun {
				if rmErr := os.Remove(full); rmErr != nil {
					return files, dirs, rmErr
				}
			}
		} else {
			dirs++
			if !dryRun {
				if rmErr := os.RemoveAll(full); rmErr != nil {
					return files, dirs, rmErr
				}
			}
		}
	}
	return files, dirs, nil
}

// newCleanupCmd builds the `dxdfir cleanup` group: wipe processed evidence, CAR
// stores, or the dxdfir/* docker images.
func newCleanupCmd(env *Env) *cobra.Command {
	parent := &cobra.Command{
		Use:   "cleanup",
		Short: "Wipe processed evidence, CAR stores, or dxdfir/* docker images.",
	}
	parent.AddCommand(
		newCleanupTreeCmd(env,
			"processed",
			"Wipe everything under data_store/processed/ (all lanes + CAR).",
			[]string{"data_store", "processed"},
			"data_store/processed",
			"Wipe everything under data_store/processed/? [y/N]: "),
		newCleanupTreeCmd(env,
			"car",
			"Wipe the materialised CAR (data_store/processed/car/).",
			[]string{"data_store", "processed", "car"},
			"data_store/processed/car",
			"Wipe the CAR tree under data_store/processed/car/? [y/N]: "),
		newCleanupDockerCmd(env),
	)
	return parent
}

// newCleanupTreeCmd builds a cleanup subcommand that empties one data_store
// subtree, preserving its top-level .gitkeep. Shared by `cleanup processed` and
// `cleanup car`.
func newCleanupTreeCmd(env *Env, use, short string, parts []string, label, promptMsg string) *cobra.Command {
	var dryRun, yes bool
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			target := r.Path(parts...)
			if !dirExists(target) {
				fmt.Printf("Nothing to clean — %s/ does not exist.\n", label)
				return nil
			}
			if !dryRun && !yes {
				if !confirmYes(promptMsg) {
					return Fail(1, "Aborted.")
				}
			}
			files, dirs, err := removeChildrenPreservingGitkeep(target, dryRun)
			if err != nil {
				return Fail(1, "cleanup failed: %v", err)
			}
			verb := "removed"
			if dryRun {
				verb = "would remove"
			}
			fmt.Println(style.Green(fmt.Sprintf("%s %s %d file(s) + %d dir(s) under %s/",
				style.GlyphOK, verb, files, dirs, label)))
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be removed.")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Do not prompt.")
	return cmd
}

// newCleanupDockerCmd builds `dxdfir cleanup docker`, which removes built
// dxdfir/* tool images so the next build is clean.
func newCleanupDockerCmd(env *Env) *cobra.Command {
	var dryRun, yes, dangling, allDxdfir bool
	cmd := &cobra.Command{
		Use:   "docker",
		Short: "Remove built dxdfir/* tool images so the next build is clean.",
		Long: "Remove built dxdfir/* tool images.\n\n" +
			"By default only the hardened tool set is removed (the source of truth is the\n" +
			"Python get_sybers_dxdfir.images.HARDENED_IMAGES). --all-dxdfir removes EVERY\n" +
			"dxdfir/* image present; --dangling also prunes dangling layers.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := repo.Require("docker"); err != nil {
				return Fail(127, "%v", err)
			}
			present, err := dockerImageList()
			if err != nil {
				return Fail(1, "docker image ls failed: %v", err)
			}
			var targets []string
			if allDxdfir {
				for _, img := range present {
					if strings.HasPrefix(img, "dxdfir/") && !strings.HasSuffix(img, ":<none>") {
						targets = append(targets, img)
					}
				}
			} else {
				hardened, herr := hardenedImageSet()
				if herr != nil {
					return herr
				}
				presentSet := make(map[string]bool, len(present))
				for _, img := range present {
					presentSet[img] = true
				}
				for _, img := range hardened {
					if presentSet[img] {
						targets = append(targets, img)
					}
				}
			}
			if len(targets) == 0 && !dangling {
				fmt.Println("Nothing to clean — no matching dxdfir/* images on this host.")
				return nil
			}
			if len(targets) > 0 {
				head := "removing"
				if dryRun {
					head = "would remove"
				}
				fmt.Println(style.Yellow(fmt.Sprintf("%s %d image(s):", head, len(targets))))
				for _, img := range targets {
					fmt.Println(style.Yellow("   " + img))
				}
				if !dryRun && !yes {
					if !confirmYes("Proceed? [y/N]: ") {
						return Fail(1, "Aborted.")
					}
				}
				if !dryRun {
					code := run.Passthrough(context.Background(),
						run.Plan{Bin: "docker", Args: append([]string{"rmi", "-f"}, targets...)}, true)
					if code != 0 {
						return ExitError{Code: code}
					}
				}
			}
			if dangling && !dryRun {
				code := run.Passthrough(context.Background(),
					run.Plan{Bin: "docker", Args: []string{"image", "prune", "-f"}}, true)
				if code != 0 {
					return ExitError{Code: code}
				}
			}
			fmt.Println(style.Green(style.GlyphOK + " docker cleanup complete."))
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be removed.")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Do not prompt.")
	cmd.Flags().BoolVar(&dangling, "dangling", false, "Also `docker image prune -f` dangling layers.")
	cmd.Flags().BoolVar(&allDxdfir, "all-dxdfir", false, "Remove EVERY dxdfir/* image (default: only the hardened tool set).")
	return cmd
}

// dockerImageList returns the "<repo>:<tag>" of every image on the host.
func dockerImageList() ([]string, error) {
	out, err := exec.Command("docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}").Output()
	if err != nil {
		return nil, err
	}
	var imgs []string
	for _, ln := range strings.Split(string(out), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			imgs = append(imgs, ln)
		}
	}
	return imgs, nil
}

// hardenedImageSet reads the hardened tool-image list from the Python source of
// truth (get_sybers_dxdfir.images.HARDENED_IMAGES) so the two stay in lockstep.
func hardenedImageSet() ([]string, error) {
	py, err := repo.Python()
	if err != nil {
		return nil, Fail(127, "%v", err)
	}
	out, err := exec.Command(py, "-c",
		"import json;from get_sybers_dxdfir import images;print(json.dumps(list(images.HARDENED_IMAGES)))").Output()
	if err != nil {
		return nil, Fail(1, "could not read the hardened image set: %v", err)
	}
	var hardened []string
	if err := json.Unmarshal(bytes.TrimSpace(out), &hardened); err != nil {
		return nil, Fail(1, "could not parse the hardened image set: %v", err)
	}
	return hardened, nil
}
