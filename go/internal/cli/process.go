package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

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
		Use:   "process SOURCE [COLLECTION]",
		Short: "Process one evidence source — or 'all' lanes — driving each Ansible role (preflight → process → verify).",
		Long: "Process an evidence source (zeek|evtx|volatility|plaso|zimmerman|signatures) or\n" +
			"'all' lanes. Each lane is driven by its ansible-playbook; progress is reconstructed\n" +
			"live by watching the deterministic output files land on disk. With a COLLECTION,\n" +
			"each lane is scoped to data_store/raw/collections/<name>/ and only lanes with staged\n" +
			"evidence run.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			source := args[0]
			if !validSources[source] {
				return Fail(2, "invalid source %q — use one of: zeek evtx volatility plaso zimmerman signatures all", source)
			}
			if pipeline != "elastic" && pipeline != "sofelk" {
				return Fail(2, "invalid --pipeline %q — use elastic or sofelk", pipeline)
			}
			collection := ""
			if len(args) == 2 {
				collection = args[1]
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
	py, err := repo.Python()
	if err != nil {
		return Fail(127, "%v", err)
	}

	// Resolve the collection (explicit arg, else the active one).
	if collection == "" {
		var st collStatus
		if err := collQuery(r, py, &st, "status"); err == nil {
			collection = st.Active
		}
	}

	scopeVars := map[string][]string{}
	scopeDirs := map[string][]string{}
	counts := map[string]int{}
	if collection != "" {
		if err := resolveCollection(r, py, collection, noRegister); err != nil {
			return err
		}
		var cl collLanes
		if err := collQuery(r, py, &cl, "lanes", collection); err != nil {
			return err
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
