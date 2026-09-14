# Command reference

Every command, grouped by task. `dxdfir --help` (and `--help` on any subcommand) is the
live source of truth — when this page and the CLI disagree, trust the CLI and open an
issue.

Two commands sit outside `dxdfir`: the [setup script](install.md) and `docker compose`
for the [stack](../architecture/the-stack.md) (which `dxdfir stack` also drives).

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
| `dxdfir register NAME [--no-hash]` | Promote a `data_store/raw/sort/<NAME>/` dropzone folder into a tracked collection (or create an empty one) and SHA-1 hash it. |
| `dxdfir collection list` | List collections — registered, detected, and dropzone candidates; the active one is starred. |
| `dxdfir collection register [NAME] [--from PATH] [--no-hash]` | Register a collection (long form of `register`); `--from` symlinks an external dir. |
| `dxdfir collection sort [NAME] [--dry-run]` | Magic-byte-sort the dropzone into a collection's lane subdirs (content beats extension). |
| `dxdfir collection select NAME` / `unselect` | Set / clear the active collection (later commands scope to it). |
| `dxdfir collection unregister NAME` | Drop the registry row + marker (evidence and log preserved). |

See the [collection concept](../architecture/processing-lanes.md#collections).

## Processing

| Command | What it does |
|---|---|
| `dxdfir process [COLLECTION] [LANE]` | Process evidence with a [lane](../architecture/processing-lanes.md). `LANE` ∈ `zeek·evtx·volatility·plaso·zimmerman·signatures·all`; positionals are order-independent. |
| `dxdfir process … --force` | Reprocess inputs that already have output (default is idempotent). |
| `dxdfir process … -p sofelk` | Use the retiring SOF-ELK delivery pipeline instead of the default `elastic`. |
| `dxdfir process … -e KEY=VALUE` | Pass an Ansible extra-var (repeatable). |

## CAR (normalisation)

| Command | What it does |
|---|---|
| `dxdfir build-car [DIR] [--rebuild]` | Build per-source CAR stores from the processed tree via the [Byakugan engine](https://github.com/Get-Sybers/byakugan). `--rebuild` re-derives existing stores. |
| `dxdfir verify-car [--car-dir DIR]` | The [CAR correctness gate](../architecture/car-pipeline.md#verify). Run before trusting the CAR. |
| `dxdfir car-timeline CAR_DIR [--out PATH] [--after ISO] [--before ISO]` | Build one time-ordered `timeline.jsonl` across a source or a whole tree. |
| `dxdfir stix export --hits FILE --out FILE [--push]` | Turn detection hits into a STIX 2.1 bundle (OpenCTI on the wire). See [stix/README](../../python/get_sybers_dxdfir/stix/README.md). |

## Analysis stack

| Command | What it does |
|---|---|
| `dxdfir stack deploy [-s elastic\|sofelk] [--no-build]` | Build (if needed), start, and verify the analysis stack. |
| `dxdfir stack start` / `stop` / `status` | Start / stop / show the selected stack's containers. |
| `dxdfir stack destroy [--volumes] [-y]` | Remove the stack; `--volumes` also wipes ingested data. |

See [the stack](../architecture/the-stack.md) and
[docker/elastic/README.md](../../docker/elastic/README.md).

## Housekeeping

| Command | What it does |
|---|---|
| `dxdfir cleanup processed [--dry-run] [-y]` | Wipe `data_store/processed/` (all lanes + CAR). |
| `dxdfir cleanup car [-y]` | Wipe the materialised CAR tree only. |
| `dxdfir cleanup docker [-y]` | Remove the hardened `get-sybers/*` tool images. |
| `dxdfir validate` | Run the repository [check harness](../reference/build-and-test.md) (`tests/run-checks.sh`). |

## The command itself

| Command | What it does |
|---|---|
| `dxdfir` | No subcommand: the [interactive UI](the-interface.md) on a terminal, else the readiness dashboard. |
| `dxdfir --no-tui` / `--tui` | Force plain output / force the dashboard. |
| `dxdfir --repo-root PATH` | Point at a DX_DFIR checkout explicitly (else auto-detected). |
| `dxdfir --version` · `--help` | Version · help (at every level). |
