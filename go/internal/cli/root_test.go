package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestRootFind pins the command grammar by routing every spelling through
// cobra's own resolver: verb first with the noun child (`register collection
// LS24`), the bare-NAME sugar on the collection verbs (`register LS24`), the
// `list` views, the noun-required stack verbs (`deploy stack`), and the hidden,
// deprecated noun-first aliases (`collection register`, `stack deploy`).
// Nothing runs — Find only resolves.
func TestRootFind(t *testing.T) {
	root := NewRootCmd("test")
	cases := []struct {
		args  []string
		path  string   // CommandPath of the resolved command
		rest  []string // positionals (and flags) handed to it
		alias bool     // resolved via a hidden, deprecated noun-first alias
	}{
		// collection verbs: verb + noun
		{[]string{"register", "collection", "LS24"}, "dxdfir register collection", []string{"LS24"}, false},
		{[]string{"register", "collection"}, "dxdfir register collection", nil, false},
		{[]string{"register", "collection", "LS24", "--no-hash"}, "dxdfir register collection", []string{"LS24", "--no-hash"}, false},
		{[]string{"unregister", "collection", "LS24"}, "dxdfir unregister collection", []string{"LS24"}, false},
		{[]string{"select", "collection", "LS24"}, "dxdfir select collection", []string{"LS24"}, false},
		{[]string{"unselect", "collection"}, "dxdfir unselect collection", nil, false},
		{[]string{"sort", "collection", "LS24"}, "dxdfir sort collection", []string{"LS24"}, false},
		{[]string{"sort", "collection", "LS24", "--dry-run"}, "dxdfir sort collection", []string{"LS24", "--dry-run"}, false},
		// the noun takes either spelling — singular or plural (collection/collections)
		{[]string{"register", "collections", "LS24"}, "dxdfir register collection", []string{"LS24"}, false},
		{[]string{"sort", "collections", "LS24"}, "dxdfir sort collection", []string{"LS24"}, false},
		{[]string{"select", "collections", "LS24"}, "dxdfir select collection", []string{"LS24"}, false},
		{[]string{"unregister", "collections", "LS24"}, "dxdfir unregister collection", []string{"LS24"}, false},
		{[]string{"list", "collection"}, "dxdfir list collections", nil, false},
		{[]string{"list", "lane"}, "dxdfir list lanes", nil, false},
		{[]string{"unselect", "collections"}, "dxdfir unselect collection", nil, false},
		{[]string{"deploy", "stacks"}, "dxdfir deploy stack", nil, false},
		{[]string{"status", "stacks"}, "dxdfir status stack", nil, false},
		// collection verbs: the bare NAME stands in for the noun
		{[]string{"register", "LS24"}, "dxdfir register", []string{"LS24"}, false},
		{[]string{"register", "LS24", "--no-hash"}, "dxdfir register", []string{"LS24", "--no-hash"}, false},
		{[]string{"unregister", "LS24"}, "dxdfir unregister", []string{"LS24"}, false},
		{[]string{"select", "LS24"}, "dxdfir select", []string{"LS24"}, false},
		{[]string{"unselect"}, "dxdfir unselect", nil, false},
		{[]string{"sort", "LS24"}, "dxdfir sort", []string{"LS24"}, false},
		{[]string{"sort"}, "dxdfir sort", nil, false},
		// list: bare is the lanes view; the views are children
		{[]string{"list"}, "dxdfir list", nil, false},
		{[]string{"list", "lanes"}, "dxdfir list lanes", nil, false},
		{[]string{"list", "raw"}, "dxdfir list raw", nil, false},
		{[]string{"list", "processed"}, "dxdfir list processed", nil, false},
		{[]string{"list", "collections"}, "dxdfir list collections", nil, false},
		// stack verbs: the noun is required; a bare verb prints its targets
		{[]string{"deploy", "stack"}, "dxdfir deploy stack", nil, false},
		{[]string{"deploy", "stack", "--no-build"}, "dxdfir deploy stack", []string{"--no-build"}, false},
		{[]string{"destroy", "stack", "--volumes", "-y"}, "dxdfir destroy stack", []string{"--volumes", "-y"}, false},
		{[]string{"start", "stack"}, "dxdfir start stack", nil, false},
		{[]string{"stop", "stack"}, "dxdfir stop stack", nil, false},
		{[]string{"status", "stack"}, "dxdfir status stack", nil, false},
		{[]string{"deploy"}, "dxdfir deploy", nil, false},
		// already verb first — unchanged
		{[]string{"cleanup", "processed"}, "dxdfir cleanup processed", nil, false},
		{[]string{"cleanup", "docker", "--dangling"}, "dxdfir cleanup docker", []string{"--dangling"}, false},
		{[]string{"stix", "export"}, "dxdfir stix", []string{"export"}, false},
		{[]string{"process", "LS24", "zeek"}, "dxdfir process", []string{"LS24", "zeek"}, false},
		{[]string{"build-car"}, "dxdfir build-car", nil, false},
		{[]string{"build-timeline", "CAR"}, "dxdfir build-timeline", []string{"CAR"}, false},
		{[]string{"car-timeline", "CAR"}, "dxdfir build-timeline", []string{"CAR"}, false}, // alias
		// hidden noun-first aliases still route
		{[]string{"collection", "list"}, "dxdfir collection list", nil, true},
		{[]string{"collection", "register", "LS24"}, "dxdfir collection register", []string{"LS24"}, true},
		{[]string{"collection", "unregister", "LS24"}, "dxdfir collection unregister", []string{"LS24"}, true},
		{[]string{"collection", "select", "LS24"}, "dxdfir collection select", []string{"LS24"}, true},
		{[]string{"collection", "unselect"}, "dxdfir collection unselect", nil, true},
		{[]string{"collection", "sort", "LS24", "--dry-run"}, "dxdfir collection sort", []string{"LS24", "--dry-run"}, true},
		{[]string{"stack", "deploy"}, "dxdfir stack deploy", nil, true},
		{[]string{"stack", "destroy"}, "dxdfir stack destroy", nil, true},
		// the hidden alias groups accept the plural spelling too
		{[]string{"collections", "register", "LS24"}, "dxdfir collection register", []string{"LS24"}, true},
		{[]string{"stacks", "deploy"}, "dxdfir stack deploy", nil, true},
		{[]string{"stack", "start"}, "dxdfir stack start", nil, true},
		{[]string{"stack", "stop"}, "dxdfir stack stop", nil, true},
		{[]string{"stack", "status"}, "dxdfir stack status", nil, true},
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
			switch {
			case tc.alias && cmd.Deprecated == "":
				t.Errorf("%q is a noun-first alias and must carry a deprecation note", tc.path)
			case tc.alias && !cmd.Parent().Hidden:
				t.Errorf("%q: the alias group %q must be hidden", tc.path, cmd.Parent().Name())
			case !tc.alias && (cmd.Deprecated != "" || cmd.Hidden):
				t.Errorf("%q is the current spelling and must be neither deprecated nor hidden", tc.path)
			}
		})
	}
}

// TestRootFindRejectsTypos keeps a typo from silently opening the dashboard or
// a group's help: the root and every noun group resolve the unknown token to
// themselves, and their own RunE then errors (root.go, nounGroup).
func TestRootFindRejectsTypos(t *testing.T) {
	root := NewRootCmd("test")
	for _, args := range [][]string{
		{"regster", "LS24"},
		{"register", "colection", "LS24"}, // falls to the sugar with NAME "colection"
		{"deploy", "stak"},
		{"collection", "sellect", "LS24"},
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

// TestRootCommandsGrouped keeps `dxdfir --help` sectioned: every visible root
// command sits in one of the declared help groups (mirroring
// docs/getting-started/commands.md), so a new verb cannot land in cobra's
// "Additional Commands" bucket unnoticed.
func TestRootCommandsGrouped(t *testing.T) {
	root := NewRootCmd("test")
	for _, c := range root.Commands() {
		if !c.IsAvailableCommand() {
			continue // the hidden alias groups
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

// TestSpellingsShareFlags asserts that every spelling of a verb — the sugar
// parent, its noun child, and the hidden noun-first alias — exposes the same
// flags, since all three wrap one run function.
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
		if got := find(verb, "collection").LocalFlags().FlagUsages(); got != want {
			t.Errorf("%s collection: flags differ from the %s sugar:\n%s\nvs\n%s", verb, verb, got, want)
		}
		if got := find("collection", verb).LocalFlags().FlagUsages(); got != want {
			t.Errorf("collection %s: flags differ from the %s sugar:\n%s\nvs\n%s", verb, verb, got, want)
		}
	}
	for _, verb := range []string{"deploy", "destroy", "start", "stop", "status"} {
		want := find(verb, "stack").LocalFlags().FlagUsages()
		if got := find("stack", verb).LocalFlags().FlagUsages(); got != want {
			t.Errorf("stack %s: flags differ from %s stack:\n%s\nvs\n%s", verb, verb, got, want)
		}
	}
	if got, want := find("collection", "list").LocalFlags().FlagUsages(), find("list", "collections").LocalFlags().FlagUsages(); got != want {
		t.Errorf("collection list: flags differ from list collections:\n%s\nvs\n%s", got, want)
	}
}
