package cli

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

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

// diskImageExts is shared by the plaso and zimmerman lanes.
var diskImageExts = extSet(".e01", ".ex01", ".dd", ".raw", ".img", ".vmdk",
	".vhd", ".vhdx", ".001", ".aff4", ".vmx", ".ova")

// evidenceLanes is the ordered lane view over data_store/raw/ (matches the
// Python CLI's Source order, skipping the non-lane "signatures" and "all").
var evidenceLanes = []evidenceLane{
	{"zeek", []string{"pcaps"}, extSet(".pcap", ".pcapng", ".cap")},
	{"evtx", []string{"logs/winevt"}, extSet(".evtx")},
	{"volatility", []string{"memory"}, extSet(".dmp", ".mem", ".lime", ".vmem", ".raw", ".dump", ".bin")},
	{"plaso", []string{"disk_images", "VM_files"}, diskImageExts},
	{"zimmerman", []string{"disk_images", "VM_files"}, diskImageExts},
}

// rawSubdirs are the top-level data_store/raw/ subdirs shown by `list raw`.
var rawSubdirs = []string{
	"pcaps", "memory", "disk_images", "VM_files", "logs", "filesystem",
	"mobile", "other_raw_data", "collections", "sort",
}

// processedSubdirs are the top-level data_store/processed/ subdirs shown by
// `list processed`.
var processedSubdirs = []string{
	"zeek", "windows_logs", "volatility", "plaso", "zimmerman",
	"linux_logs", "software_logs", "log2timeline", "csv", "json",
}

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

// newListCmd builds `dxdfir list [KIND]`, a native (no-subprocess) view of the
// staged evidence: lane counts over raw/ (default), or a directory view of
// raw/ or processed/.
func newListCmd(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "list [KIND]",
		Short: "List staged evidence (lanes | raw | processed).",
		Long: "List staged evidence.\n\n" +
			"Views:\n" +
			"  lanes (default) — per-lane counts over data_store/raw/ (what `process` reads).\n" +
			"  raw             — a directory view of data_store/raw/ top-level subdirs.\n" +
			"  processed       — a directory view of data_store/processed/ top-level subdirs.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			kind := "lanes"
			if len(args) > 0 {
				kind = args[0]
			}
			switch kind {
			case "lanes":
				printLanesView(r)
			case "raw":
				printDirView(r.Path("data_store", "raw"), rawSubdirs, "data_store/raw")
			case "processed":
				printDirView(r.Path("data_store", "processed"), processedSubdirs, "data_store/processed")
			default:
				return Fail(2, "unknown list view %q — use one of: lanes, raw, processed", kind)
			}
			return nil
		},
	}
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
		fmt.Printf("  %-13s %s file(s)  %s%s\n", lane.name, cnt, loc, note)
	}
	fmt.Printf("  %-13s %5s          scans pcaps / files / disk images / evtx (the lanes above)\n", "signatures", "-")
	fmt.Println("")
	fmt.Println("Process one with:  dxdfir process <source>   (see  dxdfir process -h)")
	fmt.Println("Other views:       dxdfir list raw   |   dxdfir list processed")
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
