package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/collect"
	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/run"
	"github.com/get-sybers/dx_dfir/go/internal/style"
	"github.com/get-sybers/dx_dfir/go/internal/tui"
)

// ---- shared query types (the JSON contract of `python -m ...collection`) ----

type collSummary struct {
	Name  string         `json:"name"`
	Lanes map[string]int `json:"lanes"`
	Total int            `json:"total"`
	Sha1  *string        `json:"sha1"`
}

type collStatus struct {
	Active       string        `json:"active"`
	Registered   []collSummary `json:"registered"`
	Unregistered []collSummary `json:"unregistered"`
	Candidates   []string      `json:"candidates"`
}

type collState struct {
	Name       string `json:"name"`
	Registered bool   `json:"registered"`
	Detected   bool   `json:"detected"`
	Exists     bool   `json:"exists"`
}

type laneInput struct {
	Lane  string `json:"lane"`
	Var   string `json:"var"`
	Dir   string `json:"dir"`
	Count int    `json:"count"`
}

type collLanes struct {
	Name   string      `json:"name"`
	Inputs []laneInput `json:"inputs"`
}

// collQuery runs a collection subcommand and decodes its stdout JSON into out.
func collQuery(r *repo.Repo, py string, out any, args ...string) error {
	full := append([]string{"-m", "get_sybers_dxdfir.collection", "--repo-root", r.Root}, args...)
	stdout, stderr, err := run.Capture(context.Background(), run.Plan{Bin: py, Args: full, Dir: r.Root})
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = err.Error()
		}
		return Fail(2, "collection %s: %s", strings.Join(args, " "), msg)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal([]byte(stdout), out)
}

// ---- signal context shared by the progress-driving verbs ----

func signalCtx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}

func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func confirm(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt+" [y/N]: ")
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(sc.Text()))
	return a == "y" || a == "yes"
}

// ---- register (top-level sugar) ----

func newRegisterCmd(env *Env) *cobra.Command {
	var noHash bool
	cmd := &cobra.Command{
		Use:   "register NAME",
		Short: "Register a collection (promote the dropzone folder if present, else create), then hash",
		Long: "Sugar for `collection register`. If data_store/raw/sort/<NAME>/ exists it is\n" +
			"promoted (loose files auto-classified into lane subdirs); otherwise an empty\n" +
			"collection is created. A SQLite registry row is added and (unless --no-hash)\n" +
			"the evidence is SHA-1'd into .collection.hashes.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runRegister(env, args[0], "", !noHash)
		},
	}
	cmd.Flags().BoolVar(&noHash, "no-hash", false, "Skip SHA-1 hashing the evidence into .collection.hashes.")
	return cmd
}

func runRegister(env *Env, name, fromExplicit string, doHash bool) error {
	r, err := env.resolveRepo()
	if err != nil {
		return err
	}
	py, err := repo.Python()
	if err != nil {
		return Fail(127, "%v", err)
	}
	fromPath := fromExplicit
	if fromPath == "" {
		dz := r.Path("data_store", "raw", "sort", name)
		if fi, e := os.Stat(dz); e == nil && fi.IsDir() {
			fromPath = dz
		}
	}
	title := "register " + name
	if fromPath != "" {
		title = "register " + filepath.Base(fromPath) + " -> " + name
	}
	ctx, cancel := signalCtx()
	defer cancel()
	runner := &collect.Runner{Repo: r, Python: py, Title: title}
	updates := runner.Register(ctx, name, fromPath, doHash)
	return exitFromErr(present(env, tui.NewCollection(), updates, cancel))
}

// ---- collection sub-app ----

func newCollectionCmd(env *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collection",
		Short: "Group raw evidence into collections and auto-sort the dropzone.",
	}
	cmd.AddCommand(
		newCollectionListCmd(env),
		newCollectionRegisterCmd(env),
		newCollectionUnregisterCmd(env),
		newCollectionSelectCmd(env),
		newCollectionUnselectCmd(env),
		newCollectionSortCmd(env),
	)
	return cmd
}

func newCollectionListCmd(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List collections (registered + dropzone candidates); the active one is starred.",
		RunE: func(*cobra.Command, []string) error {
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			py, err := repo.Python()
			if err != nil {
				return Fail(127, "%v", err)
			}
			var st collStatus
			if err := collQuery(r, py, &st, "status"); err != nil {
				return err
			}
			printCollectionList(st)
			return nil
		},
	}
}

func printCollectionList(st collStatus) {
	if len(st.Registered) == 0 && len(st.Unregistered) == 0 && len(st.Candidates) == 0 {
		fmt.Println("No collections yet. Register one:  dxdfir register <name>")
		return
	}
	row := func(c collSummary, tag string) {
		mark := " "
		if c.Name == st.Active {
			mark = style.Yellow(style.GlyphStar)
		}
		detail := laneDetail(c.Lanes)
		sha := ""
		if c.Sha1 != nil && *c.Sha1 != "" {
			sha = "  sha1:" + trunc(*c.Sha1, 12)
		}
		count := fmt.Sprintf("%4d", c.Total)
		if c.Total > 0 {
			count = style.Green(count)
		} else {
			count = style.Grey(count)
		}
		line := fmt.Sprintf(" %s %-22s %s file(s)  [%s]%s", mark, c.Name, count, detail, sha)
		if tag != "" {
			line += "  " + style.Yellow(tag)
		}
		fmt.Println(line)
	}
	for _, c := range st.Registered {
		row(c, "")
	}
	for _, c := range st.Unregistered {
		row(c, "unregistered")
	}
	for _, c := range st.Candidates {
		fmt.Printf("   %-22s %s\n", c, style.Cyan("dropzone candidate — dxdfir register "+c))
	}
}

func laneDetail(lanes map[string]int) string {
	if len(lanes) == 0 {
		return "empty"
	}
	keys := make([]string, 0, len(lanes))
	for k := range lanes {
		if lanes[k] > 0 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return "empty"
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s:%d", k, lanes[k])
	}
	return strings.Join(parts, ", ")
}

func newCollectionRegisterCmd(env *Env) *cobra.Command {
	var fromPath string
	var noHash bool
	cmd := &cobra.Command{
		Use:   "register [NAME]",
		Short: "Register a collection (long form). NAME optional with --from (uses its basename).",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			if name == "" {
				if fromPath == "" {
					return Fail(2, "register: NAME is required (or pass --from PATH to infer it).")
				}
				name = filepath.Base(fromPath)
				fmt.Fprintln(os.Stderr, style.Grey(style.GlyphInfo+" no NAME given — using '"+name+"' (basename of --from)."))
			}
			return runRegister(env, name, fromPath, !noHash)
		},
	}
	cmd.Flags().StringVarP(&fromPath, "from", "f", "", "Source: a dropzone subfolder or an external directory to symlink.")
	cmd.Flags().BoolVar(&noHash, "no-hash", false, "Skip SHA-1 hashing the evidence into .collection.hashes.")
	return cmd
}

func newCollectionUnregisterCmd(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "unregister NAME",
		Short: "Drop the registry row + marker (evidence and log are preserved).",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			py, err := repo.Python()
			if err != nil {
				return Fail(127, "%v", err)
			}
			var res struct {
				Removed bool `json:"removed"`
			}
			if err := collQuery(r, py, &res, "unregister", args[0]); err != nil {
				return err
			}
			if res.Removed {
				fmt.Println(style.Green(style.GlyphOK + " unregistered '" + args[0] + "' — evidence + log untouched."))
			} else {
				fmt.Println(style.Yellow(style.GlyphInfo + " '" + args[0] + "' was not registered — nothing to do."))
			}
			return nil
		},
	}
}

func newCollectionSelectCmd(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "select NAME",
		Short: "Mark a collection as the active target for subsequent commands.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			py, err := repo.Python()
			if err != nil {
				return Fail(127, "%v", err)
			}
			if err := collQuery(r, py, nil, "select", args[0]); err != nil {
				return err
			}
			fmt.Println(style.Yellow(style.GlyphStar + " active collection is now '" + args[0] + "'"))
			return nil
		},
	}
}

func newCollectionUnselectCmd(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "unselect",
		Short: "Clear the active collection.",
		RunE: func(*cobra.Command, []string) error {
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			py, err := repo.Python()
			if err != nil {
				return Fail(127, "%v", err)
			}
			var res struct {
				Previous *string `json:"previous"`
			}
			if err := collQuery(r, py, &res, "unselect"); err != nil {
				return err
			}
			if res.Previous == nil {
				fmt.Println("no active collection was set.")
			} else {
				fmt.Println(style.Green(style.GlyphOK + " cleared active collection (was '" + *res.Previous + "')"))
			}
			return nil
		},
	}
}

func newCollectionSortCmd(env *Env) *cobra.Command {
	var dryRun, noRegister, noHash bool
	cmd := &cobra.Command{
		Use:   "sort [NAME]",
		Short: "Sort the dropzone into a collection's lanes by magic-byte type (content beats extension).",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := env.resolveRepo()
			if err != nil {
				return err
			}
			py, err := repo.Python()
			if err != nil {
				return Fail(127, "%v", err)
			}
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			if name == "" {
				if name, err = defaultCollection(r, py); err != nil {
					return err
				}
			}
			if !dryRun {
				if err := resolveCollection(r, py, name, noRegister); err != nil {
					return err
				}
			}
			title := "sort -> " + name
			ctx, cancel := signalCtx()
			defer cancel()
			runner := &collect.Runner{Repo: r, Python: py, Title: title}
			updates := runner.Sort(ctx, name, dryRun, !noHash)
			return exitFromErr(present(env, tui.NewCollection(), updates, cancel))
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would move; move nothing.")
	cmd.Flags().BoolVar(&noRegister, "no-register", false, "Sort an unregistered collection without registering it.")
	cmd.Flags().BoolVar(&noHash, "no-hash", false, "Skip the hash manifest refresh after sorting.")
	return cmd
}

// defaultCollection returns the active collection, or the only one if unambiguous.
func defaultCollection(r *repo.Repo, py string) (string, error) {
	var st collStatus
	if err := collQuery(r, py, &st, "status"); err != nil {
		return "", err
	}
	if st.Active != "" {
		return st.Active, nil
	}
	known := make([]string, 0)
	for _, c := range st.Registered {
		known = append(known, c.Name)
	}
	for _, c := range st.Unregistered {
		known = append(known, c.Name)
	}
	switch len(known) {
	case 0:
		return "", Fail(2, "No collections. Register one first:  dxdfir register <name>")
	case 1:
		return known[0], nil
	default:
		return "", Fail(2, "Several collections (%s) — pick one with `dxdfir collection select <name>` or pass it.",
			strings.Join(known, ", "))
	}
}

// resolveCollection makes a collection usable before sort/process: registered → ok;
// detected (unregistered but has evidence) → register (prompt when interactive);
// absent → error.
func resolveCollection(r *repo.Repo, py, name string, noRegister bool) error {
	var st collState
	if err := collQuery(r, py, &st, "state", name); err != nil {
		return err
	}
	if st.Registered {
		return nil
	}
	if st.Detected {
		if noRegister {
			fmt.Fprintln(os.Stderr, style.Yellow(style.GlyphWarn+" '"+name+"' is unregistered — proceeding untracked (no log)."))
			return nil
		}
		reg := true
		if isInteractive() {
			reg = confirm("Detected unregistered collection '" + name + "'. Register it to keep a processing record?")
		}
		if reg {
			if err := collQuery(r, py, nil, "register", name, "--source", "detected"); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, style.Green(style.GlyphOK+" registered '"+name+"'."))
		}
		return nil
	}
	return Fail(2, "no such collection '%s'. Register it: dxdfir register %s", name, name)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
