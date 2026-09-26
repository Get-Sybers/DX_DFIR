package cli

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/lanes"
	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/style"
)

// evidenceLane maps an evidence source to where it reads from (subdirs under
// data_store/raw) and the file extensions that count as evidence there — the
// same defaults the processing roles use.
type evidenceLane struct {
	name string
	subs []string
	exts map[string]bool
}

func extSet(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// evidenceLanes is the ordered lane view over data_store/raw/ — the lane
// specs' raw inputs, skipping the detection lane (it scans the others' evidence).
var evidenceLanes = func() []evidenceLane {
	var out []evidenceLane
	for _, s := range lanes.Specs {
		if s.Name == "signatures" {
			continue
		}
		out = append(out, evidenceLane{s.Name, s.InputSubdirs, extSet(s.Exts...)})
	}
	return out
}()

// rawSubdirs are the top-level data_store/raw/ subdirs shown by `list raw`.
var rawSubdirs = []string{
	"pcaps", "memory", "disk_images", "VM_files", "logs", "filesystem",
	"mobile", "other_raw_data", "collections", "sort",
}

// processedSubdirs are the top-level data_store/processed/ subdirs shown by
// `list processed`: one leaf per tool (the lane specs' OutLeaf), then the
// detection tree and the engine's own leaves.
var processedSubdirs = func() []string {
	var out []string
	for _, s := range lanes.Specs {
		out = append(out, s.OutLeaf)
	}
	return append(out, "byakugan", "exchange")
}()

// countFiles returns the number of regular files anywhere beneath dir
// (recursive). A missing/unreadable dir counts as zero.
func countFiles(dir string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// countFilesByExt counts files beneath dir whose lower-cased extension is in exts.
func countFilesByExt(dir string, exts map[string]bool) int {
	n := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && exts[strings.ToLower(filepath.Ext(path))] {
			n++
		}
		return nil
	})
	return n
}

// newListCmd builds `dxdfir list [VIEW]`: native (no-subprocess) views of the
// staged evidence — lane counts over raw/ (the default, bare `list`), a
// directory view of raw/ or processed/ — and of the tracked collections.
func newListCmd(env *Env) *cobra.Command {
	// view builds one evidence view as a subcommand.
	view := func(use, short string, render func(r *repo.Repo)) *cobra.Command {
		return &cobra.Command{
			Use:   use,
			Short: short,
			Args:  cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				r, err := env.resolveRepo()
				if err != nil {
					return err
				}
				render(r)
				return nil
			},
		}
	}
	lanes := view("lanes", "Per-lane counts over data_store/raw/ (what `process` reads) — the default.", printLanesView)
	lanes.Aliases = []string{"lane"} // singular is accepted too
	cmd := &cobra.Command{
		Use:     "list [VIEW]",
		Short:   "List staged evidence (lanes | raw | processed) or collections.",
		GroupID: groupEvidence,
		Long: "List staged evidence, or the tracked collections.\n\n" +
			"Views:\n" +
			"  lanes (default) — per-lane counts over data_store/raw/ (what `process` reads).\n" +
			"  raw             — a directory view of data_store/raw/ top-level subdirs.\n" +
			"  processed       — a directory view of data_store/processed/ top-level subdirs.\n" +
			"  collections     — registered, detected and dropzone-candidate collections;\n" +
			"                    the active one is starred.",
		Args: cobra.MaximumNArgs(1),
		// A bare `list` shows the lanes view; a KNOWN view routes to its
		// subcommand before reaching here, so any arg that lands here is an
		// unknown view — name the valid ones rather than cobra's generic
		// "accepts 0 arg(s)".
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				return Fail(2, "unknown list view %q — the views are: %s", args[0], viewNames(c))
			}
			return lanes.RunE(c, args)
		},
	}
	collections := collectionsLeaf(env, "collections")
	collections.Aliases = []string{"collection"} // singular is accepted too
	cmd.AddCommand(
		lanes,
		view("raw", "A directory view of data_store/raw/ top-level subdirs.", func(r *repo.Repo) {
			printDirView(r.Path("data_store", "raw"), rawSubdirs, "data_store/raw")
		}),
		view("processed", "A directory view of data_store/processed/ top-level subdirs.", func(r *repo.Repo) {
			printDirView(r.Path("data_store", "processed"), processedSubdirs, "data_store/processed")
		}),
		collections,
	)
	return cmd
}

// viewNames lists the accepted `list` view spellings — each view subcommand's
// name and its aliases — so the unknown-view error stays exhaustive and never
// drifts as views (or their singular/plural aliases) change.
func viewNames(list *cobra.Command) string {
	var parts []string
	for _, sub := range list.Commands() {
		if sub.Name() == "help" { // the auto-generated help command is not a view
			continue
		}
		name := sub.Name()
		if len(sub.Aliases) > 0 {
			name += " (or " + strings.Join(sub.Aliases, ", ") + ")"
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, ", ")
}

// printLanesView prints the per-lane evidence counts over data_store/raw/.
func printLanesView(r *repo.Repo) {
	raw := r.Path("data_store", "raw")
	fmt.Println(style.Bold("Evidence under data_store/raw/"))
	for _, lane := range evidenceLanes {
		count := 0
		for _, sub := range lane.subs {
			d := filepath.Join(raw, sub)
			if dirExists(d) {
				count += countFilesByExt(d, lane.exts)
			}
		}
		cnt := fmt.Sprintf("%5d", count)
		note := ""
		if count > 0 {
			cnt = style.Green(cnt)
		} else {
			cnt = style.Grey(cnt)
			note = style.Grey("  (not staged)")
		}
		loc := strings.Join(lane.subs, ", ") + "/"
		fmt.Printf("  %-15s %s file(s)  %s%s\n", lane.name, cnt, loc, note)
	}
	fmt.Printf("  %-15s %5s          scans pcaps / files / memory / disk images / evtx (the lanes above)\n", "signatures", "-")
	fmt.Println("")
	fmt.Println("Process one with:  dxdfir process <source>   (see  dxdfir process -h)")
	fmt.Println("Other views:       dxdfir list raw   |   dxdfir list processed   |   dxdfir list collections")
}

// printDirView prints a directory-oriented file count over each of subs beneath
// root, noting subdirs that are absent.
func printDirView(root string, subs []string, label string) {
	fmt.Println(style.Bold("Evidence under " + label + "/"))
	for _, sub := range subs {
		d := filepath.Join(root, sub)
		exists := dirExists(d)
		count := 0
		if exists {
			count = countFiles(d)
		}
		cnt := fmt.Sprintf("%5d", count)
		if count > 0 {
			cnt = style.Green(cnt)
		} else {
			cnt = style.Grey(cnt)
		}
		note := ""
		if !exists {
			note = style.Grey("  (missing)")
		}
		fmt.Printf("  %-16s %s file(s)%s\n", sub, cnt, note)
	}
}
