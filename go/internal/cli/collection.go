package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/collect"
	"github.com/get-sybers/dx_dfir/go/internal/collection"
	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/style"
	"github.com/get-sybers/dx_dfir/go/internal/tui"
)

// ---- shared query types ----
//
// The whole collection layer — status/lanes/state reads, select/unselect/
// unregister/register/sort/promote/link writes, and the SHA-1 hash — is native
// Go (internal/collection); nothing shells the retired
// retired python collection module. These aliases keep the cli's
// rendering + process-scoping code unchanged.

type (
	collSummary = collection.Summary
	collStatus  = collection.Status
	collState   = collection.State
	laneInput   = collection.LaneInput
	collLanes   = collection.Lanes
)

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

// ---- the collection verbs ----
//
// Each verb is one run function wrapped by up to three cobra commands built
// from the same leaf builder: the verb-first parent that takes a bare NAME as
// sugar (`register [NAME]`), its `collection` child (`register collection
// [NAME]`), and the hidden noun-first alias (`collection register [NAME]`).
// A leaf builder always returns a fresh *cobra.Command — cobra allows a
// command exactly one parent.

// leafFn builds one spelling of a collection verb under the given Use line.
type leafFn func(env *Env, use string) *cobra.Command

// collectionVerb builds a verb-first collection command: the parent itself runs
// the bare-NAME sugar, and its `collection` child is the spelled-out form.
// nameUse is the NAME part of the Use line ("" / " NAME" / " [NAME]").
func collectionVerb(env *Env, leaf leafFn, verb, nameUse string) *cobra.Command {
	cmd := leaf(env, verb+nameUse)
	cmd.GroupID = groupEvidence
	cmd.Long = strings.TrimRight(cmd.Long, "\n") + "\n\n" +
		"The noun is optional and takes either spelling — `dxdfir " + verb + nameUse + "` is\n" +
		"`dxdfir " + verb + " collection" + nameUse + "` (or `collections`).\n" +
		"A collection named exactly `collection`/`collections` needs the spelled-out form."
	child := leaf(env, "collection"+nameUse)
	child.Aliases = []string{"collections"}
	cmd.AddCommand(child)
	return cmd
}

func newRegisterCmd(env *Env) *cobra.Command {
	return collectionVerb(env, registerLeaf, "register", " [NAME]")
}

func newUnregisterCmd(env *Env) *cobra.Command {
	return collectionVerb(env, unregisterLeaf, "unregister", " NAME")
}

func newSelectCmd(env *Env) *cobra.Command {
	return collectionVerb(env, selectLeaf, "select", " NAME")
}

func newUnselectCmd(env *Env) *cobra.Command {
	return collectionVerb(env, unselectLeaf, "unselect", "")
}

func newSortCmd(env *Env) *cobra.Command {
	return collectionVerb(env, sortLeaf, "sort", " [NAME]")
}

// newCollectionCmd builds the hidden `dxdfir collection <verb>` alias group: the
// noun-first spelling every verb had before the grammar went verb first. Each
// child still runs its verb, printing cobra's deprecation note (to stderr) with
// the verb-first spelling to use instead.
func newCollectionCmd(env *Env) *cobra.Command {
	parent := nounGroup("collection",
		"Deprecated noun-first spelling of the collection verbs.",
		"Deprecated noun-first spelling of the collection verbs. Each still runs and\n"+
			"prints the verb-first form to use instead:\n\n"+
			"  collection list              ->  list collections\n"+
			"  collection register [NAME]   ->  register collection [NAME]    (or: register NAME)\n"+
			"  collection unregister NAME   ->  unregister collection NAME    (or: unregister NAME)\n"+
			"  collection select NAME       ->  select collection NAME        (or: select NAME)\n"+
			"  collection unselect          ->  unselect collection           (or: unselect)\n"+
			"  collection sort [NAME]       ->  sort collection [NAME]        (or: sort [NAME])")
	parent.Hidden = true
	parent.Aliases = []string{"collections"}
	for _, alias := range []struct {
		cmd *cobra.Command
		now string
	}{
		{collectionsLeaf(env, "list"), "list collections"},
		{registerLeaf(env, "register [NAME]"), "register collection [NAME]"},
		{unregisterLeaf(env, "unregister NAME"), "unregister collection NAME"},
		{selectLeaf(env, "select NAME"), "select collection NAME"},
		{unselectLeaf(env, "unselect"), "unselect collection"},
		{sortLeaf(env, "sort [NAME]"), "sort collection [NAME]"},
	} {
		alias.cmd.Deprecated = "use: dxdfir " + alias.now
		parent.AddCommand(alias.cmd)
	}
	return parent
}

// ---- list collections ----

// collectionsLeaf builds the collection listing (`list collections`, and the
// hidden alias `collection list`).
func collectionsLeaf(env *Env, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: "List collections (registered + dropzone candidates); the active one is starred.",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runListCollections(env)
		},
	}
}

func runListCollections(env *Env) error {
	r, err := env.resolveRepo()
	if err != nil {
		return err
	}
	st, err := collection.CheckStatus(r.Root)
	if err != nil {
		return Fail(2, "list collections: %v", err)
	}
	printCollectionList(st)
	return nil
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
		detail := typeDetail(c.Types)
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

// typeDetail renders a collection's Types as "pcaps:3, memory:2" — the identified
// evidence lanes and their counts, in taxonomy order (nonzero only).
func typeDetail(types []collection.TypeCount) string {
	if len(types) == 0 {
		return "empty"
	}
	parts := make([]string, len(types))
	for i, t := range types {
		parts[i] = fmt.Sprintf("%s:%d", t.Label, t.Count)
	}
	return strings.Join(parts, ", ")
}

// ---- register ----

func registerLeaf(env *Env, use string) *cobra.Command {
	var fromPath string
	var noHash bool
	cmd := &cobra.Command{
		Use:   use,
		Short: "Register a collection: promote its dropzone folder if present, else create it; then hash.",
		Long: "Register a collection. If data_store/raw/sort/<NAME>/ exists it is promoted\n" +
			"(loose files auto-classified into lane subdirs); otherwise an empty collection\n" +
			"is created — or, with --from PATH, an external directory is symlinked in and\n" +
			"NAME defaults to its basename. A SQLite registry row is added and (unless\n" +
			"--no-hash) the evidence is SHA-1'd into .collection.hashes.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			if name == "" {
				if fromPath == "" {
					return Fail(2, "register: NAME is required (or pass --from PATH to infer it) — see: dxdfir register --help")
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

func runRegister(env *Env, name, fromExplicit string, doHash bool) error {
	r, err := env.resolveRepo()
	if err != nil {
		return err
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
	runner := &collect.Runner{Repo: r, Title: title}
	updates := runner.Register(ctx, name, fromPath, doHash)
	return exitFromErr(present(env, tui.NewCollection(), updates, cancel))
}

// ---- unregister ----

func unregisterLeaf(env *Env, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: "Drop the registry row + marker (evidence and log are preserved).",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runUnregister(env, args[0])
		},
	}
}

func runUnregister(env *Env, name string) error {
	r, err := env.resolveRepo()
	if err != nil {
		return err
	}
	removed, err := collection.Unregister(r.Root, name)
	if err != nil {
		return Fail(2, "%v", err)
	}
	if removed {
		fmt.Println(style.Green(style.GlyphOK + " unregistered '" + name + "' — evidence + log untouched."))
	} else {
		fmt.Println(style.Yellow(style.GlyphInfo + " '" + name + "' was not registered — nothing to do."))
	}
	return nil
}

// ---- select / unselect ----

func selectLeaf(env *Env, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: "Mark a collection as the active target for subsequent commands.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runSelect(env, args[0])
		},
	}
}

func runSelect(env *Env, name string) error {
	r, err := env.resolveRepo()
	if err != nil {
		return err
	}
	if err := collection.Select(r.Root, name); err != nil {
		return Fail(2, "%v", err)
	}
	fmt.Println(style.Yellow(style.GlyphStar + " active collection is now '" + name + "'"))
	return nil
}

func unselectLeaf(env *Env, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: "Clear the active collection.",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runUnselect(env)
		},
	}
}

func runUnselect(env *Env) error {
	r, err := env.resolveRepo()
	if err != nil {
		return err
	}
	prev, err := collection.Unselect(r.Root)
	if err != nil {
		return Fail(2, "%v", err)
	}
	if prev == "" {
		fmt.Println("no active collection was set.")
	} else {
		fmt.Println(style.Green(style.GlyphOK + " cleared active collection (was '" + prev + "')"))
	}
	return nil
}

// ---- sort ----

// sortOpts are the sort verb's flags, bound per command instance.
type sortOpts struct {
	dryRun, noRegister, noHash bool
}

func sortLeaf(env *Env, use string) *cobra.Command {
	var o sortOpts
	cmd := &cobra.Command{
		Use:   use,
		Short: "Sort the dropzone into a collection's lanes by magic-byte type (content beats extension).",
		Long: "Sort the dropzone into a collection's lanes by magic-byte type (content beats\n" +
			"extension). With no NAME the active collection is used, or the only one if\n" +
			"there is exactly one.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			return runSort(env, name, o)
		},
	}
	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "Show what would move; move nothing.")
	cmd.Flags().BoolVar(&o.noRegister, "no-register", false, "Sort an unregistered collection without registering it.")
	cmd.Flags().BoolVar(&o.noHash, "no-hash", false, "Skip the hash manifest refresh after sorting.")
	return cmd
}

func runSort(env *Env, name string, o sortOpts) error {
	r, err := env.resolveRepo()
	if err != nil {
		return err
	}
	if name == "" {
		if name, err = defaultCollection(r); err != nil {
			return err
		}
	}
	if !o.dryRun {
		if err := resolveCollection(r, name, o.noRegister); err != nil {
			return err
		}
	}
	title := "sort -> " + name
	ctx, cancel := signalCtx()
	defer cancel()
	runner := &collect.Runner{Repo: r, Title: title}
	updates := runner.Sort(ctx, name, o.dryRun, !o.noHash)
	return exitFromErr(present(env, tui.NewCollection(), updates, cancel))
}

// ---- shared resolution ----

// defaultCollection returns the active collection, or the only one if unambiguous.
func defaultCollection(r *repo.Repo) (string, error) {
	st, err := collection.CheckStatus(r.Root)
	if err != nil {
		return "", Fail(2, "collection status: %v", err)
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
		return "", Fail(2, "Several collections (%s) — pick one with `dxdfir select <name>` or pass it.",
			strings.Join(known, ", "))
	}
}

// resolveCollection makes a collection usable before sort/process: registered → ok;
// detected (unregistered but has evidence) → register (prompt when interactive);
// absent → error.
func resolveCollection(r *repo.Repo, name string, noRegister bool) error {
	st, err := collection.CheckState(r.Root, name)
	if err != nil {
		return Fail(2, "collection state %s: %v", name, err)
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
			if _, err := collection.Register(r.Root, name, "", "detected", nil); err != nil {
				return Fail(2, "register %s: %v", name, err)
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
