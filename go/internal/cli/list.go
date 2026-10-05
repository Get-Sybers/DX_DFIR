package cli

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Get-Sybers/DX_DFIR/go/internal/lanes"
	"github.com/Get-Sybers/DX_DFIR/go/internal/repo"
	"github.com/Get-Sybers/DX_DFIR/go/internal/style"
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

// rawSubdirs are the top-level data_store/raw/ subdirs shown by `list evidence --raw`.
var rawSubdirs = []string{
	"pcaps", "memory", "disk_images", "VM_files", "logs", "filesystem",
	"mobile", "other_raw_data", "collections", "sort",
}

// processedSubdirs are the top-level data_store/processed/ subdirs shown by
// `list evidence --processed`: one leaf per tool (the lane specs' OutLeaf), then
// the detection tree and the engine's own leaves.
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
//
// An empty extension set is a wildcard — a lane whose evidence is "a folder
// of anything" (godaemonhunter's staged Linux hosts) counts every regular
// file — while dotfiles (a collection's control files, an editor's
// droppings) never count as evidence.
func countFilesByExt(dir string, exts map[string]bool) int {
	n := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		if len(exts) == 0 || exts[strings.ToLower(filepath.Ext(path))] {
			n++
		}
		return nil
	})
	return n
}

// newListCmd builds `dx list [evidence|collections]`: native (no-subprocess)
// views of the staged evidence and of the tracked collections. A bare `list`
// shows the per-lane evidence counts (the most useful default).
func newListCmd(env *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list [evidence|collections]",
		Short:   "List staged evidence or the tracked collections.",
		GroupID: groupEvidence,
		Long: "List staged evidence, or the tracked collections.\n\n" +
			"Nouns:\n" +
			"  evidence (default) — per-lane counts over data_store/raw/ (what `process` reads).\n" +
			"                       --raw / --processed switch to a directory view of those trees.\n" +
			"  collections        — registered, detected and dropzone-candidate collections;\n" +
			"                       the active one is starred.",
		Args: cobra.ArbitraryArgs,
		// A bare `list` shows the evidence lanes view; a known noun routes to its
		// subcommand before reaching here, so any arg that lands here is an unknown
		// noun — name the valid ones rather than cobra's generic error.
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return Fail(2, "unknown list noun %q — the nouns are: evidence, collections", args[0])
			}
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			printLanesView(r)
			return nil
		},
	}
	collections := collectionsLeaf(env, "collections")
	collections.Aliases = []string{"collection"} // singular is accepted too
	cmd.AddCommand(newListEvidenceCmd(env), collections)
	return cmd
}

// newListEvidenceCmd builds `dx list evidence`: the per-lane counts by default,
// or a directory view of raw/ or processed/ with --raw / --processed.
func newListEvidenceCmd(env *Env) *cobra.Command {
	var raw, processed bool
	cmd := &cobra.Command{
		Use:     "evidence",
		Aliases: []string{"lanes", "lane"},
		Short:   "Per-lane counts over data_store/raw/ (default); --raw / --processed for directory views.",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if raw && processed {
				return Fail(2, "pass at most one of --raw / --processed")
			}
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			switch {
			case raw:
				printDirView(r.Path("data_store", "raw"), rawSubdirs, "data_store/raw")
			case processed:
				printDirView(r.Path("data_store", "processed"), processedSubdirs, "data_store/processed")
			default:
				printLanesView(r)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&raw, "raw", false, "A directory view of data_store/raw/ top-level subdirs.")
	cmd.Flags().BoolVar(&processed, "processed", false, "A directory view of data_store/processed/ top-level subdirs.")
	return cmd
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
	fmt.Println("Process one with:  dx process <scope>   (see  dx process -h)")
	fmt.Println("Other views:       dx list evidence --raw   |   dx list evidence --processed   |   dx list collections")
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
