# First run

The command journey from raw evidence to searchable analysis. Each step is one
`dxdfir` verb; run them in order — later steps read what earlier ones wrote.

> Assumes you've [installed](install.md) and run `dxdfir build-docker`.

## The path at a glance

```
stage evidence → process → build-car → verify-car → car-timeline → bring up stack → explore
```

## 1. Stage evidence

Drop files under the matching `data_store/raw/` subdirectory so the lanes can find them:

| Evidence | Put it under |
|---|---|
| Packet captures (`.pcap`/`.pcapng`) | `data_store/raw/pcaps/` |
| Memory images | `data_store/raw/memory/` |
| Disk images (`.E01`, raw/dd, VMDK, VHDX…) | `data_store/raw/disk_images/` |
| VMware VM exports | `data_store/raw/VM_files/` |
| Windows event logs (`.evtx`) | `data_store/raw/logs/winevt/` |

Not sure how to sort a mixed pile? Drop it all into `data_store/raw/sort/` and let
DX_DFIR classify it by magic bytes — see the [collection workflow](#optional-the-collection-workflow)
below. Check what's staged:

```bash
dxdfir list                    # per-lane evidence counts over data_store/raw/
```

> `data_store/` is git-ignored deny-by-default — never commit evidence. Verify hashes
> when you move forensic images. See [directory structure](../Dir-Structure.md).

**No evidence to hand? Kick the tyres with a sample.** Nothing evidence-like is committed
to the repo, but small, hash-pinned public samples are fetched on demand:

```bash
./dev-scripts/fetch-samples.sh --fetch drives-dftt-2004    # a few small disk images (~MBs)
```

See [`samples/README.md`](../../samples/README.md) for the starter set, then process it
like any evidence below.

## 2. Process

Run a [processing lane](../architecture/processing-lanes.md) over the evidence
(`process COLLECTION LANE` — the two are order-independent; a known lane name is the
lane, anything else the collection):

```bash
dxdfir process evtx            # one lane over all staged evidence of its type
dxdfir process all             # every lane that has evidence
```

Each lane runs its tool in a container and writes deterministic output under
`data_store/processed/`. On a terminal you get a [live progress dashboard](the-interface.md);
`process` is idempotent (already-processed inputs are skipped — pass `--force` to redo).

## 3. Normalise into CAR

```bash
dxdfir build-car               # processed evidence → per-source MITRE CAR stores
```

This drives the external [Byakugan engine](https://github.com/Get-Sybers/byakugan) to
turn every processed source into its own CAR store — `car.db` plus one
`car_<object>.jsonl` per object — under `data_store/processed/car/<source>/`. Changed a
map or coverage? Re-derive with `--rebuild`. See the
[CAR pipeline](../architecture/car-pipeline.md).

## 4. Verify

```bash
dxdfir verify-car              # the CAR correctness gate
```

Checks what the pipeline actually wrote — each exercised object populated, values sane,
every row traceable to one artefact. **Run this before you trust the CAR.**

## 5. Build a timeline

```bash
dxdfir car-timeline data_store/processed/car    # writes data_store/processed/car/timeline.jsonl
```

Unions every source's object events and relationship edges into one time-ordered
`timeline.jsonl` — the behaviour timeline. Written under `data_store/processed/car/` by
default, which is exactly what the [Timeline tab](the-interface.md#timeline) reads. (Pass
`--out PATH` to put it elsewhere — but the tab only reads the default location.)

## 6. Bring up the analysis backend

```bash
sudo sysctl -w vm.max_map_count=262144        # Elasticsearch requires this, or it crash-loops
cd docker/elastic && cp .env.example .env     # then fill in the placeholders (see below)
docker compose up -d                           # Elasticsearch + Kibana + Fleet + Filebeat
```

Or drive the same stack with `dxdfir stack deploy`. Everything binds `127.0.0.1`;
Filebeat ships the processed evidence into `logs-dxdfir.<type>-*` data streams. See
[the stack](../architecture/the-stack.md) and
[docker/elastic/README.md](../../docker/elastic/README.md).

> **Two things bite here on a first run:**
> - `vm.max_map_count=262144` must be set on the host or Elasticsearch won't start
>   (persist it in `/etc/sysctl.conf`).
> - The `.env` values aren't optional placeholders — passwords need ≥ 6 chars and each
>   encryption key must be `openssl rand -hex 32`. The comments in `.env.example` say
>   which is which. The file holds credentials and is git-ignored — never commit it.

## 7. Explore

- **Kibana** at <http://127.0.0.1:5601>.
- **`dxdfir`** (no args) — the interactive UI: keep driving the pipeline, watch the
  containers, and run ES|QL queries from the [Kibana tab](the-interface.md).

## Optional: the collection workflow

To group evidence into a named, tracked case and auto-sort a mixed pile:

```bash
# drop a mixed pile into data_store/raw/sort/case-a/, then:
dxdfir register case-a                  # promote it to a tracked collection + SHA-1 hash it
dxdfir collection sort case-a           # magic-byte sort loose files into lane subdirs (add --dry-run to preview)
dxdfir collection select case-a         # make it the active target for later commands
dxdfir process case-a all               # process the whole collection
```

More in the [command reference](commands.md) and the [collection concept](../architecture/processing-lanes.md#collections).

## When something's off

- `build-car` / `car-timeline` fail → the Byakugan engine checkout is missing; re-run
  the [setup script](install.md).
- A lane finds nothing → evidence is in the wrong `data_store/raw/` subdir (step 1).
- Empty or stale CAR → you ran the steps out of order; the sequence is
  `process → build-car → verify-car`.
