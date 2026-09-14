package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	coll "github.com/get-sybers/dx_dfir/go/internal/collection" // aliased: `collection` is a param name here
	"github.com/get-sybers/dx_dfir/go/internal/lanes"
	"github.com/get-sybers/dx_dfir/go/internal/repo"
	"github.com/get-sybers/dx_dfir/go/internal/style"
	"github.com/get-sybers/dx_dfir/go/internal/tui"
)

var validSources = map[string]bool{
	"zeek": true, "evtx": true, "volatility": true, "plaso": true,
	"zimmerman": true, "signatures": true, "all": true,
}

func newProcessCmd(env *Env) *cobra.Command {
	var pipeline string
	var force, noRegister bool
	var extraVars []string
	cmd := &cobra.Command{
		Use:   "process [COLLECTION] [LANE]",
		Short: "Process evidence with a lane — what is processed, and what it is processed with.",
		Long: "Process evidence with a lane (a collection is what is processed; the lane is what\n" +
			"it is processed with). Each lane is driven by its ansible-playbook; progress is\n" +
			"reconstructed live by watching the deterministic output files land on disk.\n\n" +
			"Lanes:\n" +
			"  zeek        PCAPs -> Zeek JSON logs\n" +
			"  evtx        Windows event logs -> EvtxECmd JSON\n" +
			"  volatility  memory images -> plugin JSONL\n" +
			"  plaso       disk images/VMs -> super timeline\n" +
			"  zimmerman   disk images/VMs -> registry/MFT/… artefacts\n" +
			"  signatures  yara/suricata/hayabusa over the staged evidence\n" +
			"  all         every lane above\n\n" +
			"The two positionals may be given in either order — the lane is recognised by name,\n" +
			"anything else is treated as a collection:\n" +
			"  dxdfir process zeek                 # zeek over all staged raw evidence\n" +
			"  dxdfir process my-case zeek         # zeek scoped to collection 'my-case'\n" +
			"  dxdfir process my-case              # every lane with evidence in 'my-case'\n" +
			"With a collection each lane is scoped to data_store/raw/collections/<name>/ and only\n" +
			"lanes with staged evidence run. With no collection, the active one is used if set.\n\n" +
			"A collection named exactly like a lane (e.g. 'zeek') is read as the lane when given\n" +
			"positionally — select it first (dxdfir collection select zeek) and it is used as the\n" +
			"active collection instead.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			// The positionals are order-independent: a known lane name is the lane,
			// anything else is the collection (its existence is validated later).
			source, collection := "", ""
			for _, a := range args {
				switch {
				case validSources[a]:
					if source != "" {
						return Fail(2, "two lanes given (%q and %q) — pass at most one lane", source, a)
					}
					source = a
				default:
					if collection != "" {
						return Fail(2, "unrecognised argument %q — %q is not a lane (zeek|evtx|volatility|plaso|zimmerman|signatures|all) and a collection is already given (%q)", a, a, collection)
					}
					collection = a
				}
			}
			if source == "" {
				source = "all" // `process <collection>` runs every lane with evidence
			}
			if pipeline != "elastic" && pipeline != "sofelk" {
				return Fail(2, "invalid --pipeline %q — use elastic or sofelk", pipeline)
			}
			return runProcess(env, source, collection, pipeline, force, noRegister, extraVars)
		},
	}
	cmd.Flags().StringVarP(&pipeline, "pipeline", "p", "elastic", "Backend to target: elastic or sofelk.")
	cmd.Flags().BoolVar(&force, "force", false, "Reprocess inputs that already have output.")
	cmd.Flags().StringArrayVarP(&extraVars, "extra-var", "e", nil, "Extra Ansible var KEY=VALUE (repeatable).")
	cmd.Flags().BoolVar(&noRegister, "no-register", false, "With a collection: process an unregistered one without registering.")
	return cmd
}

func runProcess(env *Env, source, collection, pipeline string, force, noRegister bool, extraVars []string) error {
	r, err := env.resolveRepo()
	if err != nil {
		return err
	}
	ap, err := repo.AnsiblePlaybook()
	if err != nil {
		return Fail(127, "%v", err)
	}

	// Resolve the collection (explicit arg, else the active one).
	if collection == "" {
		if st, err := coll.CheckStatus(r.Root); err == nil {
			collection = st.Active
		}
	}
	if collection == "" {
		fmt.Fprintln(os.Stderr, style.Yellow(
			"no collection selected — processing all staged raw evidence under data_store/raw/. "+
				"Scope to a case with: dxdfir process <collection> "+source+"  (or select one: dxdfir collection select <name>)"))
	}

	scopeVars := map[string][]string{}
	scopeDirs := map[string][]string{}
	counts := map[string]int{}
	if collection != "" {
		if err := resolveCollection(r, collection, noRegister); err != nil {
			return err
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

	// Decide which lanes to run.
	var laneNames []string
	if source == "all" {
		laneNames = lanes.AllNames()
		if collection != "" {
			filtered := laneNames[:0:0]
			for _, ln := range laneNames {
				if counts[ln] > 0 {
					filtered = append(filtered, ln)
				}
			}
			laneNames = filtered
			if len(laneNames) == 0 {
				fmt.Fprintln(os.Stderr, style.Yellow(fmt.Sprintf(
					"collection '%s' has no evidence — stage files then: dxdfir collection sort %s", collection, collection)))
				return nil
			}
		}
	} else {
		laneNames = []string{source}
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
		} else {
			lr.InputDirs = lanes.DefaultInputDirs(r, spec)
		}
		runs = append(runs, lr)
	}

	title := "process " + source + " -> " + pipeline
	if collection != "" {
		title += " (collection " + collection + ")"
	}
	if source == "all" {
		title = "process all -> " + pipeline
		if collection != "" {
			title += " (collection " + collection + ")"
		}
		fmt.Fprintln(os.Stderr, style.Bold("process all -> "+strings.Join(laneNames, ", ")))
	}

	ctx, cancel := signalCtx()
	defer cancel()
	job := &lanes.Job{
		Repo: r, Ansible: ap, Pipeline: pipeline, Force: force,
		ExtraVars: extraVars, Runs: runs, Title: title,
	}
	updates := job.Execute(ctx)
	return exitFromErr(present(env, tui.NewProcess(), updates, cancel))
}
