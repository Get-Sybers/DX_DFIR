package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/get-sybers/dx_dfir/go/internal/run"
)

// The STIX/CTI exchange is Ansible-orchestrated (dxdfir_exchange role): four
// verbs, each fronting a thin playbook that runs the get-sybers/byakugan
// image's own exchange sub-tool (byakugan.exchange) from its contract. The
// OpenCTI endpoint/token/connector-id come from the environment
// (DXDFIR_OPENCTI_URL / _TOKEN / _CONNECTOR_ID) — the token rides the lane's
// secret_env env-file, never argv — and a push or live pull must name a
// docker network (--network), since the lane's confined default is
// --network none.
func newStixCmd(env *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stix",
		Short: "STIX 2.1 / OpenCTI exchange (export | behaviour | pull | sightings), via the byakugan exchange lane.",
		Long: "The STIX 2.1 / OpenCTI exchange, run engine-side (`byakugan.exchange`) as\n" +
			"confined containers via the dxdfir_exchange Ansible role: detection hits to a\n" +
			"STIX bundle (export), the detection lanes joined to CAR entities (behaviour),\n" +
			"OpenCTI indicators into the cti-* Elastic copy (pull), and indicator-match\n" +
			"alerts back as sightings (sightings). Products land under\n" +
			"data_store/processed/exchange by default.\n\n" +
			"The OpenCTI wire comes from the environment: DXDFIR_OPENCTI_URL,\n" +
			"DXDFIR_OPENCTI_TOKEN (never a flag; it travels via the lane's secret_env\n" +
			"env-file) and DXDFIR_OPENCTI_CONNECTOR_ID. Wire-bound runs (--push, a live\n" +
			"pull) also need --network with the docker network to attach.",
		GroupID: groupCAR,
	}
	cmd.AddCommand(
		newStixExportCmd(env),
		newStixBehaviourCmd(env),
		newStixPullCmd(env),
		newStixSightingsCmd(env),
	)
	return cmd
}

// newStixExportCmd — `dxdfir stix export` → dxdfir-exchange-export.yml.
func newStixExportCmd(env *Env) *cobra.Command {
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
		Use:   "export [HITS_DIR]",
		Short: "Turn detection hits into a validated STIX 2.1 bundle (sightings + indicators).",
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

// newStixBehaviourCmd — `dxdfir stix behaviour` → dxdfir-exchange-behaviour.yml.
func newStixBehaviourCmd(env *Env) *cobra.Command {
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

// newStixPullCmd — `dxdfir stix pull` → dxdfir-exchange-pull.yml.
func newStixPullCmd(env *Env) *cobra.Command {
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

// newStixSightingsCmd — `dxdfir stix sightings` → dxdfir-exchange-sightings.yml.
func newStixSightingsCmd(env *Env) *cobra.Command {
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
