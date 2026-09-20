# Command reference

Every command, grouped by task. `dxdfir --help` (and `--help` on any subcommand) is the
live source of truth — when this page and the CLI disagree, trust the CLI and open an
issue.

Commands read verb first — `<verb> <noun> [NAME]`: `register collection case-a`,
`deploy stack`, `list collections`. The noun is singular or plural interchangeably
(`list collection` == `list collections`, `register collections` == `register
collection`). The collection verbs also take a bare NAME in place of the noun
(`register case-a` is `register collection case-a`). The former noun-first spellings
(`collection register`, `stack deploy`) still run, hidden, and print the verb-first
form to use.

Two commands sit outside `dxdfir`: the [setup script](install.md) and `docker compose`
for the [stack](../architecture/the-stack.md) (which the `dxdfir … stack` verbs also drive).

## Setup

| Command | What it does |
|---|---|
| `./scripts/setup-environment.sh [--yes] [--no-color]` | One-time host prep: Docker, tools, the Byakugan engine, the venv, the `dxdfir` binary. See [install](install.md). |
| `dxdfir build-docker [-i NAME] [--force]` | Build + hardening-verify the `get-sybers/*` tool images. Run once per host, and after any `docker/` change. |
| `dxdfir verify-images` | Audit the hardened tool-image inventory (fails on any missing or un-hardened image). |

## Evidence and collections

| Command | What it does |
|---|---|
| `dxdfir list [lanes\|raw\|processed]` | Show staged evidence — per-lane counts (default), or a directory view of raw/processed. |
| `dxdfir list collections` | List collections — registered, detected, and dropzone candidates; the active one is starred. |
| `dxdfir register [collection] [NAME] [--no-hash]` | Promote a `data_store/raw/sort/<NAME>/` dropzone folder into a tracked collection (or create an empty one) and SHA-1 hash it. |
| `dxdfir register … --from PATH` | Symlink an external directory in as the collection; NAME defaults to its basename. |
| `dxdfir sort [collection] [NAME] [--dry-run]` | Magic-byte-sort the dropzone into a collection's lane subdirs (content beats extension); no NAME means the active one. |
| `dxdfir select [collection] NAME` / `dxdfir unselect [collection]` | Set / clear the active collection (later commands scope to it). |
| `dxdfir unregister [collection] NAME` | Drop the registry row + marker (evidence and log preserved). |

See the [collection concept](../architecture/processing-lanes.md#collections).

## Processing

| Command | What it does |
|---|---|
| `dxdfir process [COLLECTION] [LANE]` | Process evidence with a [lane](../architecture/processing-lanes.md). `LANE` ∈ `zeek·evtx·memory·plaso·godfir-toolz·signatures·all`; positionals are order-independent. |
| `dxdfir process … --force` | Reprocess inputs that already have output (default is idempotent). |
| `dxdfir process … -e KEY=VALUE` | Pass an Ansible extra-var (repeatable). |

## CAR (normalisation)

| Command | What it does |
|---|---|
| `dxdfir build-car [DIR] [--out DIR] [--rebuild] [--derive] [--stix]` | Build per-source CAR stores from the processed tree via the [Byakugan engine](https://github.com/Get-Sybers/byakugan) (`byakugan build`). `--rebuild` re-derives existing stores; `--derive` adds the derived relationship pass (`superset.db`); `--stix` the STIX 2.1 bundle. |
| `dxdfir verify-car [--car-dir DIR]` | The [CAR correctness gate](../architecture/car-pipeline.md#verify). Run before trusting the CAR. |
| `dxdfir load-car [--namespace NS] [--setup\|--no-setup] [--force] [--kibana]` | Bulk-load the materialised CAR into the [analysis stack](../architecture/the-stack.md)'s `logs-car.*` data streams (`byakugan load`). `--setup` (default) applies the index/component templates first; `--no-setup` for routine repeat loads once they exist; `--kibana` also imports the rendered Kibana saved objects. |
| `dxdfir build-timeline CAR_DIR [--out-dir DIR] [--force] [--after ISO] [--before ISO]` | Build one time-ordered `timeline.jsonl` across a source or a whole tree, beside the stores unless `--out-dir` (alias: `car-timeline`). |
| `dxdfir stix export --hits FILE --out FILE [--push]` | Turn detection hits into a STIX 2.1 bundle (OpenCTI on the wire). See [stix/README](../../python/get_sybers_dxdfir/stix/README.md). |

## Analysis stack

| Command | What it does |
|---|---|
| `dxdfir deploy stack [--no-build]` | Build (if needed), start, and verify the analysis stack. |
| `dxdfir start stack` / `stop stack` / `status stack` | Start / stop / show the stack's containers. |
| `dxdfir destroy stack [--volumes] [-y]` | Remove the stack; `--volumes` also wipes ingested data. |

See [the stack](../architecture/the-stack.md) and
[docker/elastic/README.md](../../docker/elastic/README.md).

## Housekeeping

| Command | What it does |
|---|---|
| `dxdfir cleanup processed [--dry-run] [-y]` | Wipe `data_store/processed/` (all lanes + CAR). |
| `dxdfir cleanup car [-y]` | Wipe the materialised CAR tree only. |
| `dxdfir cleanup docker [-y]` | Remove the hardened `get-sybers/*` tool images. |
| `dxdfir validate` | Run the repository [check harness](../reference/build-and-test.md) (`.github/tests/run-checks.sh`). |

## The command itself

| Command | What it does |
|---|---|
| `dxdfir` | No subcommand: the [interactive UI](the-interface.md) on a terminal, else the readiness dashboard. |
| `dxdfir --no-tui` / `--tui` | Force plain output / force the dashboard. |
| `dxdfir --repo-root PATH` | Point at a DX_DFIR checkout explicitly (else auto-detected). |
| `dxdfir --version` · `--help` | Version · help (at every level). |
