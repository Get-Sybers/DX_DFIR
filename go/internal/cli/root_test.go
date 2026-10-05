package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestRootFind pins the command grammar by routing every spelling through
// cobra's own resolver: verb first with the noun child (`register evidence
// LS24`), the bare-NAME sugar on the evidence verbs (`register LS24`), the
// noun-required stack verbs (`deploy stack`), the `list` nouns, the `purge`
// targets, and the `byakugan` tool namespace. Nothing runs — Find only resolves.
func TestRootFind(t *testing.T) {
	root := NewRootCmd("test")
	cases := []struct {
		args []string
		path string   // CommandPath of the resolved command
		rest []string // positionals (and flags) handed to it
	}{
		// evidence verbs: verb + noun
		{[]string{"register", "evidence", "LS24"}, "dx register evidence", []string{"LS24"}},
		{[]string{"register", "evidence"}, "dx register evidence", nil},
		{[]string{"register", "evidence", "LS24", "--no-hash"}, "dx register evidence", []string{"LS24", "--no-hash"}},
		{[]string{"unregister", "evidence", "LS24"}, "dx unregister evidence", []string{"LS24"}},
		{[]string{"select", "evidence", "LS24"}, "dx select evidence", []string{"LS24"}},
		{[]string{"unselect", "evidence"}, "dx unselect evidence", nil},
		{[]string{"sort", "evidence", "LS24"}, "dx sort evidence", []string{"LS24"}},
		{[]string{"sort", "evidence", "LS24", "--dry-run"}, "dx sort evidence", []string{"LS24", "--dry-run"}},
		// evidence verbs: the bare NAME stands in for the noun
		{[]string{"register", "LS24"}, "dx register", []string{"LS24"}},
		{[]string{"register", "LS24", "--no-hash"}, "dx register", []string{"LS24", "--no-hash"}},
		{[]string{"unregister", "LS24"}, "dx unregister", []string{"LS24"}},
		{[]string{"select", "LS24"}, "dx select", []string{"LS24"}},
		{[]string{"unselect"}, "dx unselect", nil},
		{[]string{"sort", "LS24"}, "dx sort", []string{"LS24"}},
		{[]string{"sort"}, "dx sort", nil},
		// list: bare is the evidence lanes view; the nouns are children
		{[]string{"list"}, "dx list", nil},
		{[]string{"list", "evidence"}, "dx list evidence", nil},
		{[]string{"list", "evidence", "--raw"}, "dx list evidence", []string{"--raw"}},
		{[]string{"list", "lanes"}, "dx list evidence", nil}, // alias
		{[]string{"list", "collections"}, "dx list collections", nil},
		{[]string{"list", "collection"}, "dx list collections", nil}, // singular alias
		// stack verbs: the noun is required; a bare verb prints its targets
		{[]string{"deploy", "stack"}, "dx deploy stack", nil},
		{[]string{"start", "stack"}, "dx start stack", nil},
		{[]string{"stop", "stack"}, "dx stop stack", nil},
		{[]string{"restart", "stack"}, "dx restart stack", nil},
		{[]string{"status", "stack"}, "dx status stack", nil},
		{[]string{"update", "stack"}, "dx update stack", nil},
		{[]string{"deploy", "stacks"}, "dx deploy stack", nil}, // plural alias
		{[]string{"deploy"}, "dx deploy", nil},
		// setup: build/verify images
		{[]string{"build", "images"}, "dx build images", nil},
		{[]string{"build", "images", "--force"}, "dx build images", []string{"--force"}},
		{[]string{"verify", "images"}, "dx verify images", nil},
		// process: noun optional, scope/tool positional
		{[]string{"process", "evidence", "LS24", "zeek"}, "dx process", []string{"evidence", "LS24", "zeek"}},
		{[]string{"process", "LS24", "zeek"}, "dx process", []string{"LS24", "zeek"}},
		{[]string{"process", "pcaps"}, "dx process", []string{"pcaps"}},
		// purge: one verb, noun targets
		{[]string{"purge", "stack"}, "dx purge stack", nil},
		{[]string{"purge", "stack", "--volumes", "-y"}, "dx purge stack", []string{"--volumes", "-y"}},
		{[]string{"purge", "evidence"}, "dx purge evidence", nil},
		{[]string{"purge", "car"}, "dx purge car", nil},
		{[]string{"purge", "images", "--dangling"}, "dx purge images", []string{"--dangling"}},
		{[]string{"purge", "docker"}, "dx purge images", nil}, // alias
		// byakugan tool namespace (noun first)
		{[]string{"byakugan", "build"}, "dx byakugan build", nil},
		{[]string{"byakugan", "verify"}, "dx byakugan verify", nil},
		{[]string{"byakugan", "load"}, "dx byakugan load", nil},
		{[]string{"byakugan", "load", "--no-setup"}, "dx byakugan load", []string{"--no-setup"}},
		{[]string{"byakugan", "export-timeline", "CAR"}, "dx byakugan export-timeline", []string{"CAR"}},
		{[]string{"byakugan", "timeline", "CAR"}, "dx byakugan export-timeline", []string{"CAR"}}, // alias
		{[]string{"byakugan", "export-stix"}, "dx byakugan export-stix", nil},
		{[]string{"byakugan", "export", "HITS"}, "dx byakugan export-stix", []string{"HITS"}}, // alias
		{[]string{"byakugan", "pull", "--from-bundle", "x.json"}, "dx byakugan pull", []string{"--from-bundle", "x.json"}},
		// validate
		{[]string{"validate"}, "dx validate", nil},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			cmd, rest, err := root.Find(tc.args)
			if err != nil {
				t.Fatalf("Find(%q): %v", tc.args, err)
			}
			if got := cmd.CommandPath(); got != tc.path {
				t.Fatalf("Find(%q) resolved %q, want %q", tc.args, got, tc.path)
			}
			if len(rest) == 0 {
				rest = nil
			}
			if !reflect.DeepEqual(rest, tc.rest) {
				t.Errorf("Find(%q) left args %q, want %q", tc.args, rest, tc.rest)
			}
			if !cmd.Runnable() {
				t.Errorf("%q is not runnable", tc.path)
			}
			if cmd.Deprecated != "" || cmd.Hidden {
				t.Errorf("%q is the current spelling and must be neither deprecated nor hidden", tc.path)
			}
		})
	}
}

// TestRootFindRejectsTypos keeps a typo from silently opening the readout or a
// group's help: the root and every noun group resolve the unknown token to
// themselves, and their own RunE then errors (root.go, nounGroup).
func TestRootFindRejectsTypos(t *testing.T) {
	root := NewRootCmd("test")
	for _, args := range [][]string{
		{"regster", "LS24"},
		{"register", "evidnce", "LS24"}, // falls to the sugar with NAME "evidnce"
		{"deploy", "stak"},
		{"byakugan", "buidl"},
		{"purge", "stak"},
	} {
		cmd, rest, err := root.Find(args)
		if err != nil {
			t.Fatalf("Find(%q): %v", args, err)
		}
		if len(rest) == 0 {
			t.Errorf("Find(%q) resolved %q and consumed every token — the typo vanished", args, cmd.CommandPath())
		}
	}
}

// TestRootCommandsGrouped keeps `dx --help` sectioned: every visible root
// command sits in one of the declared help groups (mirroring
// docs/getting-started/commands.md), so a new verb cannot land in cobra's
// "Additional Commands" bucket unnoticed.
func TestRootCommandsGrouped(t *testing.T) {
	root := NewRootCmd("test")
	for _, c := range root.Commands() {
		if !c.IsAvailableCommand() {
			continue
		}
		if c.GroupID == "" {
			t.Errorf("%q: visible root command without a help group", c.Name())
			continue
		}
		if !root.ContainsGroup(c.GroupID) {
			t.Errorf("%q: help group %q is not declared on the root", c.Name(), c.GroupID)
		}
	}
}

// TestSpellingsShareFlags asserts that both spellings of an evidence verb — the
// sugar parent and its noun child — expose the same flags, since both wrap one
// run function.
func TestSpellingsShareFlags(t *testing.T) {
	root := NewRootCmd("test")
	find := func(args ...string) *cobra.Command {
		cmd, _, err := root.Find(args)
		if err != nil {
			t.Fatalf("Find(%q): %v", args, err)
		}
		return cmd
	}
	for _, verb := range []string{"register", "unregister", "select", "unselect", "sort"} {
		want := find(verb).LocalFlags().FlagUsages()
		if got := find(verb, "evidence").LocalFlags().FlagUsages(); got != want {
			t.Errorf("%s evidence: flags differ from the %s sugar:\n%s\nvs\n%s", verb, verb, got, want)
		}
	}
}

// TestStackNoBecomeFlag pins the decision that escalation is automatic, not
// flag-gated: NO stack verb exposes a --become or --allow-world-readable-keys
// flag. The converge verbs escalate on their own via stackEscalate.
func TestStackNoBecomeFlag(t *testing.T) {
	root := NewRootCmd("test")
	for _, path := range [][]string{
		{"deploy", "stack"}, {"update", "stack"}, {"start", "stack"},
		{"stop", "stack"}, {"status", "stack"}, {"restart", "stack"}, {"purge", "stack"},
	} {
		cmd, _, err := root.Find(path)
		if err != nil {
			t.Fatalf("Find(%q): %v", path, err)
		}
		for _, fl := range []string{"become", "allow-world-readable-keys"} {
			if cmd.Flags().Lookup(fl) != nil {
				t.Errorf("%q unexpectedly exposes --%s (escalation must be automatic, not a flag)",
					strings.Join(path, " "), fl)
			}
		}
	}
}

// TestStackEscalate pins the automatic-escalation decision: a converge action
// always opts the role into become, and the sudo prompt is requested only when
// we are not already root (root no-ops the become, so prompting is pointless).
func TestStackEscalate(t *testing.T) {
	asUser, askUser := stackEscalate(1000)
	if len(asUser) != 1 || asUser[0] != "dxdfir_stack_become=true" {
		t.Errorf("stackEscalate(1000) vars = %v, want [dxdfir_stack_become=true]", asUser)
	}
	if !askUser {
		t.Error("stackEscalate(1000): want askBecomePass=true for a non-root euid")
	}
	asRoot, askRoot := stackEscalate(0)
	if len(asRoot) != 1 || asRoot[0] != "dxdfir_stack_become=true" {
		t.Errorf("stackEscalate(0) vars = %v, want [dxdfir_stack_become=true]", asRoot)
	}
	if askRoot {
		t.Error("stackEscalate(0): want askBecomePass=false when already root")
	}
}
