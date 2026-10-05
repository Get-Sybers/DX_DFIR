# First run

The command journey from raw evidence to searchable analysis. Each step is one
`dx` verb; run them in order — later steps read what earlier ones wrote.

> Assumes you've [installed](install.md) and run `dx build images`.

## The path at a glance

```
stage evidence → process → byakugan build → byakugan verify → byakugan export-timeline → bring up stack → explore
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
dx list evidence               # per-lane evidence counts over data_store/raw/
```

> `data_store/` is git-ignored deny-by-default — never commit evidence. Verify hashes
> when you move forensic images. See [directory structure](../Dir-Structure.md).

**No evidence to hand? Kick the tyres with a sample.** Nothing evidence-like is committed
to the repo, but small, hash-pinned public samples are fetched on demand:

```bash
./dev-scripts/fetch-samples.sh --fetch drives-dftt-2004    # a few small disk images (~MBs)
```

Run `./dev-scripts/fetch-samples.sh --list` for the full sample catalogue, then process it
like any evidence below.

## 2. Process

Run a [processing lane](../architecture/processing-lanes.md) over the evidence
(`process SCOPE TOOL` — the two positionals are order-independent; a known tool name
is the tool, and `SCOPE` is a collection name or a raw-evidence type):

```bash
dx process gowindowlicker      # one tool over all staged evidence of its type
dx process all                 # every tool that has evidence
```

Each lane runs its tool in a container and writes deterministic output under
`data_store/processed/`. Progress streams as plain line output on stderr (see
[the interface](the-interface.md)) while stdout stays clean for piping;
`process` is idempotent (already-processed inputs are skipped — pass `--force` to redo).

## 3. Normalise into CAR

```bash
dx byakugan build              # processed evidence → per-source MITRE CAR stores
```

This drives the external [Byakugan engine](https://github.com/Get-Sybers/Byakugan) to
turn every processed source into its own CAR store — one `car_<object>.jsonl` per
populated object plus `car_relationships.jsonl` (always written) — under
`data_store/processed/byakugan/<source>/`. Changed a
map or coverage? Re-derive with `--rebuild`. See the
[CAR pipeline](../architecture/car-pipeline.md).

## 4. Verify

```bash
dx byakugan verify             # the CAR correctness gate
```

Checks what the pipeline actually wrote — each exercised object populated, values sane,
every row traceable to one artefact. **Run this before you trust the CAR.**

## 5. Build a timeline

```bash
dx byakugan export-timeline data_store/processed/byakugan  # writes data_store/processed/byakugan/timeline.jsonl
```

Unions every source's object events and relationship edges into one time-ordered
`timeline.jsonl` — the behaviour timeline. Written under `data_store/processed/byakugan/` by
default. (Pass `--out-dir DIR` to put it elsewhere.)

## 6. Bring up the analysis backend

```bash
sudo sysctl -w vm.max_map_count=262144        # Elasticsearch requires this, or it crash-loops
dx deploy stack                                # Elasticsearch + Kibana + Fleet + Filebeat
```

`deploy stack` converges everything from the inventory: docker installed when
missing (Debian/Ubuntu), secrets generated into the per-host store
(`ansible/inventory/secrets/`, gitignored, vault-overridable), TLS material
generated, the services brought up in order and verified. Everything binds
`127.0.0.1`; Filebeat ships the processed evidence into `logs-dxdfir.<type>-*`
data streams. See [the stack](../architecture/the-stack.md).

> **Two things bite here on a first run:**
> - `vm.max_map_count=262144` must be set on the host or Elasticsearch won't start
>   (persist it in `/etc/sysctl.conf`).
> - The secret store (`ansible/inventory/secrets/`) holds real credentials and is
>   git-ignored — never commit it. Its README says how to override or rotate a value.

## 7. Explore

- **Kibana** at <http://127.0.0.1:5601> — Discover, detections, and ES|QL over the
  ingested evidence.
- **`dx`** (no args) — the [landing readout](the-interface.md): environment readiness,
  tracked collections, and staged evidence at a glance.

## Optional: the collection workflow

To group evidence into a named, tracked case and auto-sort a mixed pile:

```bash
# drop a mixed pile into data_store/raw/sort/case-a/, then:
dx register case-a                      # promote it to a tracked collection + SHA-1 hash it
dx sort case-a                          # magic-byte sort loose files into lane subdirs (add --dry-run to preview)
dx select case-a                        # make it the active target for later commands
dx process case-a all                   # process the whole collection
```

More in the [command reference](commands.md) and the [collection concept](../architecture/processing-lanes.md#collections).

## When something's off

- `byakugan build` / `byakugan export-timeline` fail → the Byakugan engine checkout is
  missing; re-run the [setup script](install.md).
- A lane finds nothing → evidence is in the wrong `data_store/raw/` subdir (step 1).
- Empty or stale CAR → you ran the steps out of order; the sequence is
  `process → byakugan build → byakugan verify`.
