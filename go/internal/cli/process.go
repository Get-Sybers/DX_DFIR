package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	coll "github.com/Get-Sybers/DX_DFIR/go/internal/collection" // aliased: `collection` is a param name here
	"github.com/Get-Sybers/DX_DFIR/go/internal/lanes"
	"github.com/Get-Sybers/DX_DFIR/go/internal/style"
)

// evidenceTypes are the raw-evidence lanes a scope word can name — the
// data_store/raw/ top-level areas, matched against each tool's InputSubdirs.
// Naming one scopes a run to the tools that read that kind of evidence.
var evidenceTypes = []string{
	"disk_images", "filesystem", "logs", "memory",
	"mobile", "other_raw_data", "pcaps", "VM_files",
}

// isEvidenceType reports whether w names a raw-evidence area.
func isEvidenceType(w string) bool {
	for _, t := range evidenceTypes {
		if t == w {
			return true
		}
	}
	return false
}

// toolReadsType reports whether a tool's lane reads the given evidence type —
// the type is the first path component of one of the lane's InputSubdirs
// (so "logs" matches "logs/winevt" and "logs/linux").
func toolReadsType(spec lanes.Spec, evType string) bool {
	for _, sub := range spec.InputSubdirs {
		if sub == evType || strings.HasPrefix(sub, evType+"/") {
			return true
		}
	}
	return false
}

func newProcessCmd(env *Env) *cobra.Command {
	var force, noRegister bool
	var extraVars []string
	cmd := &cobra.Command{
		Use:   "process evidence [SCOPE] [TOOL]",
		Short: "Process evidence with a tool — what is processed, and what it is processed with.",
		Long: "Process evidence with a tool. The SCOPE is what is processed (a collection, or a\n" +
			"raw-evidence type); the TOOL is what it is processed with. Each tool is driven by\n" +
			"its ansible-playbook; progress is reconstructed live by watching the deterministic\n" +
			"output files land on disk.\n\n" +
			"Tools (the lane is named after the tool that drives it):\n" +
			laneHelp() +
			"  all             every tool above\n\n" +
			"SCOPE is a collection name, or a raw-evidence type:\n" +
			"  " + strings.Join(evidenceTypes, ", ") + "\n\n" +
			"The noun `evidence` is optional, and the two scope/tool positionals may be given in\n" +
			"either order — a known tool is the tool, a known evidence type scopes to the lanes\n" +
			"that read it, anything else is treated as a collection:\n" +
			"  dx process evidence zeek          # zeek over all staged raw evidence\n" +
			"  dx process my-case zeek           # zeek scoped to collection 'my-case'\n" +
			"  dx process my-case                # every tool with evidence in 'my-case'\n" +
			"  dx process pcaps                  # every tool that reads pcaps, over all raw pcaps\n" +
			"With a collection each tool reads data_store/raw/collections/<name>/ and writes\n" +
			"processed/<tool>/<name>/; only tools with staged evidence run. With no collection,\n" +
			"the active one is used if set.\n\n" +
			"A collection named exactly like a tool (e.g. 'zeek') is read as the tool when given\n" +
			"positionally — select it first (dx select zeek) and it is used as the active\n" +
			"collection instead.",
		GroupID: groupEvidence,
		Args:    cobra.RangeArgs(1, 3),
		RunE: func(_ *cobra.Command, args []string) error {
			// The positionals are order-independent: a leading literal `evidence`
			// is the noun word; a known tool is the tool; a known evidence type is
			// the scope type; anything else is the collection (validated later).
			tool, collection, evType := "", "", ""
			for _, a := range args {
				switch {
				case a == "evidence":
					// the (optional) noun word — ignore it
				case lanes.IsLaneWord(a):
					if tool != "" {
						return Fail(2, "two tools given (%q and %q) — pass at most one tool. "+
							"If one names a collection, select it first (dx select <name>) and pass only the tool",
							tool, a)
					}
					tool = a
				case isEvidenceType(a):
					if evType != "" || collection != "" {
						return Fail(2, "two scopes given — pass at most one collection or evidence type")
					}
					evType = a
				default:
					if collection != "" || evType != "" {
						return Fail(2, "two scopes given (%q and another) — pass at most one collection or evidence type", a)
					}
					collection = a
				}
			}
			if tool == "" {
				tool = "all" // `process <scope>` runs every tool with evidence
			}
			return runProcess(env, tool, collection, evType, force, noRegister, extraVars)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Reprocess inputs that already have output.")
	cmd.Flags().StringArrayVarP(&extraVars, "extra-var", "e", nil, "Extra Ansible var KEY=VALUE (repeatable).")
	cmd.Flags().BoolVar(&noRegister, "no-register", false, "With a collection: process an unregistered one without registering.")
	return cmd
}

func runProcess(env *Env, tool, collection, evType string, force, noRegister bool, extraVars []string) error {
	r, err := env.resolveRepo()
	if err != nil {
		return err
	}
	ap, err := r.AnsiblePlaybook()
	if err != nil {
		return Fail(127, "%v", err)
	}

	// Resolve the collection (explicit arg, else the active one) — unless the
	// run is scoped to a raw-evidence type, which reads all raw, never a case.
	if collection == "" && evType == "" {
		if st, err := coll.CheckStatus(r.Root); err == nil {
			collection = st.Active
		}
	}
	if collection == "" && evType == "" {
		fmt.Fprintln(os.Stderr, style.Yellow(
			"no collection selected — processing all staged raw evidence under data_store/raw/. "+
				"Scope to a case with: dx process <collection> "+tool+"  (or select one: dx select <name>)"))
	}

	scopeVars := map[string][]string{}
	scopeDirs := map[string][]string{}
	counts := map[string]int{}
	if collection != "" {
		if err := resolveCollection(r, collection, noRegister); err != nil {
			return err
		}
		// Sort the collection's evidence into canonical lane subdirs before
		// counting — idempotent, so already-filed files are skipped.
		if sr, err := coll.SortInto(r.Root, collection, false, nil); err != nil {
			fmt.Fprintf(os.Stderr, "%s auto-sort failed for '%s': %v\n",
				style.Yellow(style.GlyphWarn), collection, err)
		} else if sr.MovedCount() > 0 {
			fmt.Fprintf(os.Stderr, "%s sorted %d file(s) into lane subdirs for '%s'\n",
				style.Green(style.GlyphOK), sr.MovedCount(), collection)
		}
		cl, ok := coll.ListLanes(r.Root, collection)
		if !ok {
			return Fail(2, "invalid collection name %q", collection)
		}
		for _, in := range cl.Inputs {
			scopeVars[in.Lane] = append(scopeVars[in.Lane], in.Var+"="+in.Dir)
			scopeDirs[in.Lane] = append(scopeDirs[in.Lane], in.Dir)
			counts[in.Lane] += in.Count
		}
	}

	// Decide which tools to run: the name, alias or group resolves to lane names.
	laneNames, _ := lanes.Resolve(tool)

	// An evidence-type scope keeps only the tools that read that type.
	if evType != "" {
		filtered := laneNames[:0:0]
		for _, ln := range laneNames {
			if spec, ok := lanes.SpecByName(ln); ok && toolReadsType(spec, evType) {
				filtered = append(filtered, ln)
			}
		}
		laneNames = filtered
		if len(laneNames) == 0 {
			fmt.Fprintln(os.Stderr, style.Yellow(fmt.Sprintf(
				"no tool reads evidence type '%s' — nothing to do", evType)))
			return nil
		}
	}

	if len(laneNames) > 1 && collection != "" {
		filtered := laneNames[:0:0]
		for _, ln := range laneNames {
			if counts[ln] > 0 {
				filtered = append(filtered, ln)
			}
		}
		laneNames = filtered
		if len(laneNames) == 0 {
			fmt.Fprintln(os.Stderr, style.Yellow(fmt.Sprintf(
				"collection '%s' has no evidence — stage files then: dx sort %s", collection, collection)))
			return nil
		}
	}

	// Build the lane runs.
	var runs []lanes.LaneRun
	for _, ln := range laneNames {
		spec, ok := lanes.SpecByName(ln)
		if !ok {
			continue
		}
		lr := lanes.LaneRun{Spec: spec, InputCount: -1}
		if collection != "" {
			lr.InputDirs = scopeDirs[ln]
			lr.InputCount = counts[ln]
			lr.ScopeVars = scopeVars[ln]
			lr.Collection = collection
		} else {
			lr.InputDirs = lanes.DefaultInputDirs(r, spec)
		}
		runs = append(runs, lr)
	}

	title := "process " + tool
	switch {
	case collection != "":
		title += " (collection " + collection + ")"
	case evType != "":
		title += " (" + evType + ")"
	}
	if len(laneNames) > 1 || laneNames[0] != tool {
		fmt.Fprintln(os.Stderr, style.Bold("process "+tool+" -> "+strings.Join(laneNames, ", ")))
	}

	ctx, cancel := signalCtx()
	defer cancel()
	job := &lanes.Job{
		Repo: r, Ansible: ap, Force: force,
		ExtraVars: extraVars, Runs: runs, Title: title,
	}
	updates := job.Execute(ctx)
	return exitFromErr(present(updates, cancel))
}

// laneHelp renders the tool table for `process -h`: every tool with its aliases
// and summary, then the retired group name.
func laneHelp() string {
	var b strings.Builder
	for _, sp := range lanes.Specs {
		fmt.Fprintf(&b, "  %-15s %s\n", sp.Name, sp.Summary)
		if len(sp.Aliases) > 0 {
			fmt.Fprintf(&b, "  %-15s   also: %s\n", "", strings.Join(sp.Aliases, ", "))
		}
	}
	for g, members := range lanes.Groups {
		if g == "all" {
			continue
		}
		fmt.Fprintf(&b, "  %-15s %s\n", g, strings.Join(members, " + "))
	}
	return b.String()
}
