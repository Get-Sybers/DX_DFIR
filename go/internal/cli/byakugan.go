package cli

import (
	"context"
	"errors"

	"github.com/spf13/cobra"

	"github.com/Get-Sybers/DX_DFIR/go/internal/run"
)

// byakugan is a tool namespace (noun first, like `dotnet tool`): the CAR
// normalisation lifecycle and the STIX / OpenCTI exchange, both run engine-side
// by the get-sybers/byakugan image from its contract. Each subcommand fronts a
// thin Ansible playbook so the CLI drives Ansible, which runs the container.
//
//	build / verify / load        — materialise, gate, and bulk-load the CAR
//	export-timeline              — build one time-ordered CAR timeline
//	export-stix / behaviour /    — the STIX 2.1 / OpenCTI exchange (dxdfir_exchange
//	  pull / sightings             role; byakugan.exchange sub-tool)
func newByakuganCmd(env *Env) *cobra.Command {
	cmd := nounGroup("byakugan",
		"CAR normalisation (build/verify/load/export-timeline) and STIX/OpenCTI exchange.",
		"The byakugan engine: CAR normalisation and the STIX 2.1 / OpenCTI exchange.\n\n"+
			"CAR lifecycle:\n"+
			"  build            build the per-source CAR stores from processed evidence.\n"+
			"  verify           run the CAR correctness gate over the materialised CAR.\n"+
			"  load             bulk-load the CAR into the Elastic stack's logs-car.* streams.\n"+
			"  export-timeline  build one property-rich, time-ordered CAR timeline.\n\n"+
			"STIX 2.1 / OpenCTI exchange (dxdfir_exchange role; `byakugan.exchange`):\n"+
			"  export-stix      turn detection hits into a validated STIX 2.1 bundle.\n"+
			"  behaviour        join the detection lanes to the CAR entities they touch.\n"+
			"  pull             copy OpenCTI's indicators into the cti-* Elastic shape.\n"+
			"  sightings        turn indicator-match alerts into STIX sightings.\n\n"+
			"The OpenCTI wire comes from the environment: DXDFIR_OPENCTI_URL,\n"+
			"DXDFIR_OPENCTI_TOKEN (never a flag; it travels via the lane's secret_env\n"+
			"env-file) and DXDFIR_OPENCTI_CONNECTOR_ID. Wire-bound runs (--push, a live\n"+
			"pull) also need --network with the docker network to attach.")
	cmd.GroupID = groupByakugan
	cmd.AddCommand(
		newByakuganBuildCmd(env),
		newByakuganVerifyCmd(env),
		newByakuganLoadCmd(env),
		newByakuganTimelineCmd(env),
		newByakuganExportStixCmd(env),
		newByakuganBehaviourCmd(env),
		newByakuganPullCmd(env),
		newByakuganSightingsCmd(env),
	)
	return cmd
}

// ---- CAR lifecycle (godfir_byakugan role) ----

// newByakuganBuildCmd — `dx byakugan build` → dxdfir-build-car.yml.
func newByakuganBuildCmd(env *Env) *cobra.Command {
	var (
		out     string
		rebuild bool
		derive  bool
		stix    bool
	)
	cmd := &cobra.Command{
		Use:   "build [PROCESSED_DIR]",
		Short: "Build the per-source CAR stores (car_<object>.jsonl + car_relationships.jsonl) from processed evidence.",
		Long: "Build the per-source CAR stores from processed evidence, via the godfir_byakugan\n" +
			"Ansible role (`byakugan build` over the processed tree).\n\n" +
			"Discovers every source under the processed tree (PROCESSED_DIR, or\n" +
			"<repo>/data_store/processed) and builds each one's car_<object>.jsonl (per\n" +
			"populated object) plus car_relationships.jsonl (always written, even empty)\n" +
			"under the CAR tree (--out, or <repo>/data_store/processed/byakugan). A source whose\n" +
			"car_relationships.jsonl already exists is left as-is; pass --rebuild to re-derive it\n" +
			"from the current maps. --derive adds the derived relationship pass\n" +
			"(car_inferred.jsonl); --stix also derives the STIX 2.1 bundle.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"godfir_byakugan_action=build"}
			if len(args) > 0 && args[0] != "" {
				vars = append(vars, "godfir_byakugan_processed_dir="+args[0])
			}
			vars = appendVar(vars, "godfir_byakugan_dir", out)
			if rebuild {
				vars = append(vars, "godfir_byakugan_rebuild=true")
			}
			if derive {
				vars = append(vars, "godfir_byakugan_derive=true")
			}
			if stix {
				vars = append(vars, "godfir_byakugan_stix=true")
			}
			plan, err := ansiblePlan(r, ap, "dxdfir-build-car.yml", vars, false)
			if err != nil {
				return err
			}
			return exitCode(run.Passthrough(context.Background(), plan, true))
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "The CAR tree to write (default: <repo>/data_store/processed/byakugan).")
	cmd.Flags().BoolVar(&rebuild, "rebuild", false, "Rebuild CAR stores that already exist (e.g. after a map/coverage change).")
	cmd.Flags().BoolVar(&derive, "derive", false, "Also run the derived relationship pass into car_inferred.jsonl.")
	cmd.Flags().BoolVar(&stix, "stix", false, "Also derive the STIX 2.1 bundle from the finished stores.")
	return cmd
}

// newByakuganVerifyCmd — `dx byakugan verify` → dxdfir-verify-car.yml (the CAR gate).
func newByakuganVerifyCmd(env *Env) *cobra.Command {
	var carDir string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Run the CAR correctness gate over the materialised CAR tree.",
		Long: "Run the CAR correctness gate (godfir_byakugan role, verify action) over the\n" +
			"materialised CAR (default <repo>/data_store/processed/byakugan). Run the pipeline\n" +
			"first (process -> byakugan build).",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"godfir_byakugan_action=verify"}
			vars = appendVar(vars, "godfir_byakugan_dir", carDir)
			plan, err := ansiblePlan(r, ap, "dxdfir-verify-car.yml", vars, false)
			if err != nil {
				return err
			}
			return exitCode(run.Passthrough(context.Background(), plan, true))
		},
	}
	cmd.Flags().StringVar(&carDir, "car-dir", "", "The materialised CAR tree (default: <repo>/data_store/processed/byakugan).")
	return cmd
}

// newByakuganLoadCmd — `dx byakugan load` → dxdfir-load-car.yml.
func newByakuganLoadCmd(env *Env) *cobra.Command {
	var (
		namespace string
		setup     bool
		noSetup   bool
		force     bool
		kibana    bool
	)
	cmd := &cobra.Command{
		Use:   "load",
		Short: "Bulk-load the materialised CAR tree into the Elastic stack's logs-car.* data streams.",
		Long: "Bulk-load the materialised CAR tree into the analysis stack, via the dxdfir_car_load\n" +
			"Ansible role (`byakugan load` pushed into logs-car.<object>-<namespace> x13,\n" +
			"logs-car.rel-<namespace>, logs-car.inferred-<namespace> and logs-car.content-<namespace>).\n\n" +
			"Requires the analysis stack (`deploy stack`) and a built CAR (`byakugan build`); brings\n" +
			"the stack up first if it is not already running. --setup (default) applies the\n" +
			"logs-car.* index/component templates before loading and authenticates as the\n" +
			"elastic superuser; pass --no-setup for routine repeat loads once the templates\n" +
			"exist, which authenticates as the least-privilege byakugan_loader identity\n" +
			"instead. --kibana also creates the engine's Byakugan Kibana space (/s/byakugan: the\n" +
			"logs-car.* data view and the CAR timeline dashboard, from the image's own elastic/\n" +
			"tree; only sent when --setup is also on).",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// The saved-objects import only runs in the setup pass (the role
			// ignores it otherwise) — refuse the silently-ignored combination
			// instead of leaving "why did no dashboards import" to forensics.
			if kibana && (!setup || noSetup) {
				return errors.New("--kibana requires --setup: the Kibana saved-objects import runs in the setup pass")
			}
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"dxdfir_car_load_action=load"}
			vars = appendVar(vars, "dxdfir_car_load_namespace", namespace)
			vars = append(vars, "dxdfir_car_load_setup="+boolVar(setup && !noSetup))
			if force {
				vars = append(vars, "dxdfir_car_load_force=true")
			}
			if kibana {
				vars = append(vars, "dxdfir_car_load_kibana_import=true")
			}
			plan, err := ansiblePlan(r, ap, "dxdfir-load-car.yml", vars, false)
			if err != nil {
				return err
			}
			return exitCode(run.Passthrough(context.Background(), plan, true))
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Elastic data-stream namespace (default: default).")
	cmd.Flags().BoolVar(&setup, "setup", true, "Apply the logs-car.* templates before loading (first run).")
	cmd.Flags().BoolVar(&noSetup, "no-setup", false, "Skip template setup — routine repeat loads once they exist.")
	cmd.Flags().BoolVar(&force, "force", false, "Re-render and re-push even when already loaded.")
	cmd.Flags().BoolVar(&kibana, "kibana", false, "Also create the Byakugan Kibana space and import its saved objects (requires --setup).")
	return cmd
}

// newByakuganTimelineCmd — `dx byakugan export-timeline CAR_DIR` → dxdfir-car-timeline.yml.
func newByakuganTimelineCmd(env *Env) *cobra.Command {
	var (
		outDir string
		force  bool
		host   string
		after  string
		before string
	)
	cmd := &cobra.Command{
		Use:     "export-timeline CAR_DIR",
		Aliases: []string{"timeline"},
		Short:   "Build one property-rich, time-ordered CAR timeline from car_<object>.jsonl + car_relationships.jsonl.",
		Long: "Build one property-rich, time-ordered CAR timeline (godfir_byakugan role, timeline\n" +
			"action — `byakugan timeline`). Unions the object events and relationship edges\n" +
			"from a source's CAR stores into timeline.jsonl beside them (or under --out-dir).\n" +
			"Point it at one source's car directory, or a tree to aggregate every source under\n" +
			"it. An existing timeline.jsonl is kept unless --force.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"godfir_byakugan_action=timeline", "godfir_byakugan_timeline_dir=" + args[0]}
			vars = appendVar(vars, "godfir_byakugan_timeline_out_dir", outDir)
			if force {
				vars = append(vars, "godfir_byakugan_timeline_force=true")
			}
			vars = appendVar(vars, "godfir_byakugan_timeline_host", host)
			vars = appendVar(vars, "godfir_byakugan_timeline_after", after)
			vars = appendVar(vars, "godfir_byakugan_timeline_before", before)
			plan, err := ansiblePlan(r, ap, "dxdfir-car-timeline.yml", vars, false)
			if err != nil {
				return err
			}
			return exitCode(run.Passthrough(context.Background(), plan, true))
		},
	}
	cmd.Flags().StringVar(&outDir, "out-dir", "", "Directory timeline.jsonl is written to (default: CAR_DIR itself).")
	cmd.Flags().BoolVar(&force, "force", false, "Rewrite an existing timeline.jsonl.")
	cmd.Flags().StringVar(&host, "host", "", "Only events whose source_host matches.")
	cmd.Flags().StringVar(&after, "after", "", "Only events at/after this ISO timestamp.")
	cmd.Flags().StringVar(&before, "before", "", "Only events at/before this ISO timestamp.")
	return cmd
}

// ---- STIX / OpenCTI exchange (dxdfir_exchange role) ----

// newByakuganExportStixCmd — `dx byakugan export-stix` → dxdfir-exchange-export.yml.
func newByakuganExportStixCmd(env *Env) *cobra.Command {
	var (
		outDir     string
		bundlesDir string
		rulesDir   string
		caseID     string
		tlp        string
		push       bool
		network    string
	)
	cmd := &cobra.Command{
		Use:     "export-stix [HITS_DIR]",
		Aliases: []string{"export"},
		Short:   "Turn detection hits into a validated STIX 2.1 bundle (sightings + indicators).",
		Long: "Turn detection hits into a validated STIX 2.1 bundle (dxdfir_exchange role,\n" +
			"export action — `byakugan stix-export`). Every regular file under the hits\n" +
			"tree (HITS_DIR, or <repo>/data_store/processed/detections) is a hits input;\n" +
			"indicator patterns resolve from the image's baked /rules (or --rules-dir);\n" +
			"--bundles-dir merges a materialised CAR tree's stix_bundle.json projections\n" +
			"through. Writes <out>/bundle.json; --push also delivers it to OpenCTI.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			var vars []string
			if len(args) > 0 && args[0] != "" {
				vars = append(vars, "dxdfir_exchange_hits_dir="+args[0])
			}
			vars = appendVar(vars, "dxdfir_exchange_out_dir", outDir)
			vars = appendVar(vars, "dxdfir_exchange_bundles_dir", bundlesDir)
			vars = appendVar(vars, "dxdfir_exchange_rules_dir", rulesDir)
			vars = appendVar(vars, "dxdfir_exchange_case", caseID)
			vars = appendVar(vars, "dxdfir_exchange_tlp", tlp)
			if push {
				vars = append(vars, "dxdfir_exchange_push=true")
			}
			vars = appendVar(vars, "dxdfir_exchange_network", network)
			plan, err := ansiblePlan(r, ap, "dxdfir-exchange-export.yml", vars, false)
			if err != nil {
				return err
			}
			return exitCode(run.Passthrough(context.Background(), plan, true))
		},
	}
	cmd.Flags().StringVar(&outDir, "out-dir", "", "Where the bundle lands (default: <repo>/data_store/processed/exchange).")
	cmd.Flags().StringVar(&bundlesDir, "bundles-dir", "", "A materialised CAR tree whose stix_bundle.json projections pass through merged.")
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "Operator rules-as-code mounted over the image's baked /rules set.")
	cmd.Flags().StringVar(&caseID, "case", "", "Case id scoping the STIX ids (default: the hits' run id).")
	cmd.Flags().StringVar(&tlp, "tlp", "", "TLP marking on exported objects (white|green|amber|red|none).")
	cmd.Flags().BoolVar(&push, "push", false, "Also push the bundle to OpenCTI (needs the env wire + --network).")
	cmd.Flags().StringVar(&network, "network", "", "Docker network NAME for the push (the confined default is none).")
	return cmd
}

// newByakuganBehaviourCmd — `dx byakugan behaviour` → dxdfir-exchange-behaviour.yml.
func newByakuganBehaviourCmd(env *Env) *cobra.Command {
	var (
		detectionsDir string
		outDir        string
		caseID        string
		tlp           string
		producer      string
	)
	cmd := &cobra.Command{
		Use:   "behaviour [CAR_DIR]",
		Short: "Join the detection lanes to the CAR entities they touch, as STIX behaviour sightings.",
		Long: "Join the detection lanes to the CAR entities they touch, as STIX sightings\n" +
			"over spindle-keyed observed-data (dxdfir_exchange role, behaviour action —\n" +
			"`byakugan stix-behaviour`). Reads the materialised CAR (CAR_DIR, or\n" +
			"<repo>/data_store/processed/byakugan) and the detection-lane output\n" +
			"(--detections-dir); writes <out>/behaviour-sightings.json. Fully offline.\n" +
			"--case is required: it scopes every sighting id.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"dxdfir_exchange_case=" + caseID}
			if len(args) > 0 && args[0] != "" {
				vars = append(vars, "dxdfir_exchange_car_dir="+args[0])
			}
			vars = appendVar(vars, "dxdfir_exchange_detections_dir", detectionsDir)
			vars = appendVar(vars, "dxdfir_exchange_out_dir", outDir)
			vars = appendVar(vars, "dxdfir_exchange_tlp", tlp)
			vars = appendVar(vars, "dxdfir_exchange_producer", producer)
			plan, err := ansiblePlan(r, ap, "dxdfir-exchange-behaviour.yml", vars, false)
			if err != nil {
				return err
			}
			return exitCode(run.Passthrough(context.Background(), plan, true))
		},
	}
	cmd.Flags().StringVar(&caseID, "case", "", "Case id scoping the sighting/observation ids (required).")
	cmd.Flags().StringVar(&detectionsDir, "detections-dir", "", "The detection-lane output dir (default: <repo>/data_store/processed/detections).")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "Where the sightings land (default: <repo>/data_store/processed/exchange).")
	cmd.Flags().StringVar(&tlp, "tlp", "", "TLP marking (white|green|amber|red|none).")
	cmd.Flags().StringVar(&producer, "producer", "", "Producer identity name (default: the engine's DX_DFIR).")
	_ = cmd.MarkFlagRequired("case")
	return cmd
}

// newByakuganPullCmd — `dx byakugan pull` → dxdfir-exchange-pull.yml.
func newByakuganPullCmd(env *Env) *cobra.Command {
	var (
		outDir     string
		since      string
		index      string
		fromBundle string
		keepBundle bool
		network    string
	)
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Copy OpenCTI's indicators into the cti-* Elastic bulk shape.",
		Long: "Copy OpenCTI's indicators into the cti-* Elasticsearch _bulk shape\n" +
			"(dxdfir_exchange role, pull action — `byakugan cti-pull`, the one input-less\n" +
			"sub-tool). Live against the env wire by default (needs --network);\n" +
			"--from-bundle re-normalises an already-pulled indicator bundle fully\n" +
			"offline. Writes <out>/cti-bulk.ndjson; --keep-bundle also keeps the pulled\n" +
			"bundle beside it for later offline re-normalising.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			var vars []string
			vars = appendVar(vars, "dxdfir_exchange_out_dir", outDir)
			vars = appendVar(vars, "dxdfir_exchange_since", since)
			vars = appendVar(vars, "dxdfir_exchange_index", index)
			vars = appendVar(vars, "dxdfir_exchange_from_bundle", fromBundle)
			if keepBundle {
				vars = append(vars, "dxdfir_exchange_keep_bundle=true")
			}
			vars = appendVar(vars, "dxdfir_exchange_network", network)
			plan, err := ansiblePlan(r, ap, "dxdfir-exchange-pull.yml", vars, false)
			if err != nil {
				return err
			}
			return exitCode(run.Passthrough(context.Background(), plan, true))
		},
	}
	cmd.Flags().StringVar(&outDir, "out-dir", "", "Where the copy lands (default: <repo>/data_store/processed/exchange).")
	cmd.Flags().StringVar(&since, "since", "", "Only indicators modified after this ISO-8601 timestamp.")
	cmd.Flags().StringVar(&index, "index", "", "The cti-* index the bulk lines target (default: cti-opencti).")
	cmd.Flags().StringVar(&fromBundle, "from-bundle", "", "Re-normalise this already-pulled indicator bundle file (offline; no wire).")
	cmd.Flags().BoolVar(&keepBundle, "keep-bundle", false, "Also keep the pulled indicator bundle (opencti-indicators.json).")
	cmd.Flags().StringVar(&network, "network", "", "Docker network NAME for the live pull (the confined default is none).")
	return cmd
}

// newByakuganSightingsCmd — `dx byakugan sightings` → dxdfir-exchange-sightings.yml.
func newByakuganSightingsCmd(env *Env) *cobra.Command {
	var (
		outDir  string
		caseID  string
		tlp     string
		push    bool
		network string
	)
	cmd := &cobra.Command{
		Use:   "sightings ALERTS_DIR",
		Short: "Turn indicator-match alerts into STIX sightings of the platform's own indicators.",
		Long: "Turn exported indicator-match alerts into STIX sightings of the platform's\n" +
			"own indicators (dxdfir_exchange role, sightings action — `byakugan\n" +
			"cti-sightings`). Every regular file under ALERTS_DIR is an alerts input (an\n" +
			"ES _search response over .alerts-security.alerts-*, a JSON array, or JSON\n" +
			"Lines). Writes <out>/sightings.json; --push delivers them back to OpenCTI.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, ap, err := env.ansibleRepo()
			if err != nil {
				return err
			}
			vars := []string{"dxdfir_exchange_alerts_dir=" + args[0]}
			vars = appendVar(vars, "dxdfir_exchange_out_dir", outDir)
			vars = appendVar(vars, "dxdfir_exchange_case", caseID)
			vars = appendVar(vars, "dxdfir_exchange_tlp", tlp)
			if push {
				vars = append(vars, "dxdfir_exchange_push=true")
			}
			vars = appendVar(vars, "dxdfir_exchange_network", network)
			plan, err := ansiblePlan(r, ap, "dxdfir-exchange-sightings.yml", vars, false)
			if err != nil {
				return err
			}
			return exitCode(run.Passthrough(context.Background(), plan, true))
		},
	}
	cmd.Flags().StringVar(&outDir, "out-dir", "", "Where the sightings land (default: <repo>/data_store/processed/exchange).")
	cmd.Flags().StringVar(&caseID, "case", "", "Case id scoping the sighting ids (default: the alerts' rule execution id).")
	cmd.Flags().StringVar(&tlp, "tlp", "", "TLP marking (white|green|amber|red|none).")
	cmd.Flags().BoolVar(&push, "push", false, "Also push the sightings back to OpenCTI (needs the env wire + --network).")
	cmd.Flags().StringVar(&network, "network", "", "Docker network NAME for the push (the confined default is none).")
	return cmd
}

// appendVar appends an -e KEY=VALUE only when value is non-empty.
func appendVar(vars []string, key, value string) []string {
	if value == "" {
		return vars
	}
	return append(vars, key+"="+value)
}

// exitCode maps a passthrough exit code to the RunE error contract.
func exitCode(code int) error {
	if code != 0 {
		return ExitError{Code: code}
	}
	return nil
}
