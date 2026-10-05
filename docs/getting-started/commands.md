# Command reference

Every command, grouped by task. `dx --help` (and `--help` on any subcommand) is the
live source of truth — when this page and the CLI disagree, trust the CLI and open an
issue.

Commands read **verb first** — `<verb> <noun>`: `deploy stack`, `register evidence
case-a`, `list evidence`. The evidence verbs also take a bare NAME in place of the noun
(`register case-a` is `register evidence case-a`). The one exception is `byakugan`, a
tool namespace whose subcommands are its own verbs (`byakugan build`, `byakugan
export-stix`).

One command sits outside `dx`: the [setup script](install.md)
for the [stack](../architecture/the-stack.md) (which the `dx … stack` verbs also drive).

## Setup

| Command | What it does |
|---|---|
| `./scripts/setup-environment.sh [--yes] [--no-color]` | One-time host prep: Docker, tools, the Byakugan engine, the venv, the `dx` binary. See [install](install.md). |
| `dx build images [-i NAME] [--force]` | Pull + hardening-verify the `get-sybers/*` tool images from the registry. Run once per host. |
| `dx verify images` | Audit the hardened tool-image inventory (fails on any missing or un-hardened image). |

## Evidence

The noun `evidence` names a collection (a tracked case) or, for `list`/`process`, the
staged raw evidence as a whole.

| Command | What it does |
|---|---|
| `dx list evidence [--raw\|--processed]` | Show staged evidence — per-lane counts (default), or a directory view of raw/processed. |
| `dx list collections` | List collections — registered, detected, and dropzone candidates; the active one is starred. |
| `dx register [evidence] [NAME] [--no-hash]` | Promote a `data_store/raw/sort/<NAME>/` dropzone folder into a tracked collection (or create an empty one) and SHA-1 hash it. |
| `dx register … --from PATH` | Symlink an external directory in as the collection; NAME defaults to its basename. |
| `dx sort [evidence] [NAME] [--dry-run]` | Magic-byte-sort the dropzone into a collection's lane subdirs (content beats extension); no NAME means the active one. |
| `dx select [evidence] NAME` / `dx unselect [evidence]` | Set / clear the active collection (later commands scope to it). |
| `dx unregister [evidence] NAME` | Drop the registry row + marker (evidence and log preserved). |
| `dx process [evidence] [SCOPE] [TOOL]` | Process evidence with a [tool](../architecture/processing-lanes.md). `TOOL` ∈ `zeek·gowindowlicker·godaemonhunter·anamnesis·plaso·signatures·all` (aliases: `evtx`/`windowlicker`/`lick` → gowindowlicker, `daemonhunter`/`hunt` → godaemonhunter, `memory` → anamnesis, `log2timeline` → plaso, `godfir-toolz` → both host lanes). `SCOPE` is a collection name, or a raw-evidence type (`disk_images·filesystem·logs·memory·mobile·other_raw_data·pcaps·VM_files`) which scopes to the tools that read it; positionals are order-independent. Output lands in `processed/<tool>/[<collection>/]<host>/…`. |
| `dx process … --force` | Reprocess inputs that already have output (default is idempotent). |
| `dx process … -e KEY=VALUE` | Pass an Ansible extra-var (repeatable). |

See the [collection concept](../architecture/processing-lanes.md#collections).

## Byakugan (CAR normalisation + CTI exchange)

`byakugan` is the engine namespace: the CAR lifecycle and the STIX 2.1 / OpenCTI
exchange, both run inside the hardened `get-sybers/byakugan` image.

| Command | What it does |
|---|---|
| `dx byakugan build [DIR] [--out DIR] [--rebuild] [--derive] [--stix]` | Build per-source CAR stores from the processed tree (`byakugan build`). `--rebuild` re-derives existing stores; `--derive` adds the derived relationship pass (`car_inferred.jsonl`); `--stix` the STIX 2.1 bundle. |
| `dx byakugan verify [--car-dir DIR]` | The [CAR correctness gate](../architecture/car-pipeline.md#verify). Run before trusting the CAR. |
| `dx byakugan load [--namespace NS] [--no-setup] [--force] [--kibana]` | Bulk-load the materialised CAR into the [analysis stack](../architecture/the-stack.md)'s `logs-car.*` data streams (`byakugan load`). `--setup` (default) applies the index/component templates first; `--no-setup` for routine repeat loads; `--kibana` also imports the rendered Kibana saved objects. |
| `dx byakugan export-timeline CAR_DIR [--out-dir DIR] [--force] [--after ISO] [--before ISO]` | Build one time-ordered `timeline.jsonl` across a source or a whole tree, beside the stores unless `--out-dir` (alias: `timeline`). |
| `dx byakugan export-stix [HITS_DIR] [--bundles-dir DIR] [--case ID] [--push --network NET]` | Turn detection hits into a validated STIX 2.1 bundle (`dxdfir_exchange` role → `byakugan stix-export`; alias `export`). Writes `<out>/bundle.json` under `data_store/processed/exchange`. |
| `dx byakugan behaviour [CAR_DIR] --case ID [--detections-dir DIR]` | Join the detection lanes to the CAR entities they touch as STIX behaviour sightings (`byakugan stix-behaviour`, fully offline). Writes `<out>/behaviour-sightings.json`. |
| `dx byakugan pull [--since TS] [--index NAME] [--from-bundle FILE] [--network NET]` | Copy OpenCTI's indicators into the `cti-*` Elastic `_bulk` shape (`byakugan cti-pull`); `--from-bundle` re-normalises a kept bundle fully offline. Writes `<out>/cti-bulk.ndjson`. |
| `dx byakugan sightings ALERTS_DIR [--case ID] [--push --network NET]` | Turn indicator-match alerts into STIX sightings of the platform's own indicators (`byakugan cti-sightings`), pushed back with `--push`. The OpenCTI wire rides the environment: `DXDFIR_OPENCTI_URL` / `DXDFIR_OPENCTI_TOKEN` (never argv) / `DXDFIR_OPENCTI_CONNECTOR_ID`. |

## Analysis stack

| Command | What it does |
|---|---|
| `dx deploy stack` | Bring up and verify the analysis stack from inventory data (installs docker itself when missing). |
| `dx start stack` / `stop stack` / `status stack` | Start / stop / show the stack's containers. |
| `dx restart stack` | Stop the containers, then start them again (no data removed). |
| `dx update stack` | Re-converge the stack onto the current inventory/images (in-place update). |

The destructive teardown is `dx purge stack` (see [Housekeeping](#housekeeping)).
See [the stack](../architecture/the-stack.md).

## Housekeeping

`purge` is the one destructive verb, over several noun targets.

| Command | What it does |
|---|---|
| `dx purge stack [--volumes] [-y]` | Remove the stack's containers/networks; `--volumes` also wipes ingested data. |
| `dx purge evidence [--dry-run] [-y]` | Wipe `data_store/processed/` (all lanes + CAR). |
| `dx purge car [--dry-run] [-y]` | Wipe the materialised CAR tree only. |
| `dx purge images [--dangling] [--all-dxdfir] [-y]` | Remove the hardened `get-sybers/*` tool images. |
| `dx validate` | Run the repository [check harness](../reference/build-and-test.md) (`.github/tests/run-checks.sh`). |

## The command itself

| Command | What it does |
|---|---|
| `dx` | No subcommand: the [landing readout](the-interface.md) — environment readiness, tracked collections, staged evidence. |
| `dx --repo-root PATH` | Point at a DX_DFIR checkout explicitly (else auto-detected). |
| `dx --version` · `--help` | Version · help (at every level). |
