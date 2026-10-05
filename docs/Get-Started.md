# Get Started

> These steps reflect the paths that actually work today. Read
> [THIRD_PARTY_NOTICES.md](../.github/THIRD_PARTY_NOTICES.md) for the terms that bind
> you as the operator (the tools, the fetched rulesets, the Elastic licence).

### Driving the pipeline

The **`dx` CLI** is the pipeline's front-end (three-layer design — see
[How It Runs](../README.md#how-it-runs)). Install it, then the numbered steps below
walk a run end to end:

```bash
scripts/setup-environment.sh  # builds the Go dx front-end (go/) + installs the processors and ansible-core
dx process plaso         # tools: zeek | gowindowlicker | godaemonhunter | anamnesis | plaso | signatures
dx byakugan build        # normalise every processed source into CAR (car_<object>.jsonl)
dx byakugan verify       # the CAR correctness gate over what was written
dx validate              # run the repo check harness
```

The processors write the tree the CAR lane builds from and Filebeat ships.
`dx --help` is the source of truth for the commands.

### Step 1: Setup Environment
- **Run setup-environment.sh:**
  ```bash
  DX_DFIR/scripts/setup-environment.sh
  ```
_Refer to [📁 Setup_Environment](scripts/Setup_Environment.md) for details on the script._

### Step 2: Place Raw Data
- **Disk Images (`.E01`):**
  ```bash
  DX_DFIR/data_store/raw/disk_images/
  ```

- **VMware VM Exports (one folder per VM):**
  ```bash
  DX_DFIR/data_store/raw/VM_files/
  ```

- **Network Captures (`.pcap`, `.pcapng`):**
  ```bash
  DX_DFIR/data_store/raw/pcaps/
  ```

- **Other Raw Data Sources:**
  ```bash
  DX_DFIR/data_store/raw/other_raw_data/
  ```

_Refer to [📁 Dir-Structure](Dir-Structure.md) for detailed directory structures._

### Step 3: Process Forensic Images (E01 / VMware)
```bash
dx process plaso
```
- Automates forensic analysis of all `.E01` disk images and VMware VM exports using Plaso.
- Output lands in `data_store/processed/log2timeline/<host>/` — the `.plaso` storage
  file and the rendered `timeline.jsonl` (Plaso `json_line`) side by side, each with
  its tool log; a collection-scoped run one level down (`log2timeline/<collection>/<host>/`).

### Step 4: Process PCAPs with Zeek
```bash
dx process zeek
```
- Automates processing of all network capture files (`.pcap` and `.pcapng`) using Zeek.
- Output lands in `data_store/processed/zeek/[<collection>/]<pcap-name>/`.

### Step 5: Parse Windows and Linux hosts (optional)
```bash
dx process gowindowlicker   # alias: evtx
dx process godaemonhunter   # alias: daemonhunter
```
- `gowindowlicker` converts `.evtx` in `data_store/raw/logs/winevt/<host>/` with
  **goevtx** and runs every Windows artefact parser (registry, MFT, Prefetch, SRUM, …)
  over the disk images' export; output lands in
  `processed/windowlicker/[<collection>/]<subtool>/<host>/<item>/`.
- `godaemonhunter` does the same for Linux hosts (`raw/logs/linux/<host>/` and the
  images' export) into `processed/daemonhunter/[<collection>/]<subtool>/<host>/<item>/`.
- Both ride `get-sybers/*` images built by `dx build images` — nothing operator-supplied.
- See [Scripts-Overview](scripts/Scripts-Overview.md) for the pipeline layers.

### Step 6: Build and verify the CAR
```bash
dx byakugan build                            # every source under data_store/processed
dx byakugan verify                           # the promotion gate over the result
dx byakugan export-timeline data_store/processed/byakugan # one time-ordered timeline across every source
```
- `byakugan build` drives the external [Byakugan](https://github.com/Get-Sybers/Byakugan)
  engine, run inside the hardened `get-sybers/byakugan` image — cloned + built at
  the `BYAKUGAN_REF` commit pinned in its Dockerfile by `dx build images`: each processed
  source becomes its own `car_<object>.jsonl` per populated CAR object plus
  `car_relationships.jsonl` (always written, even empty — the build's done/skip
  marker) under `data_store/processed/byakugan/<source>/`. A source whose
  `car_relationships.jsonl` exists is left alone; `--rebuild` re-derives it
  after a map change.
- `byakugan verify` asserts what was written: each exercised object populated, values
  sane (IPs, ports, SIDs, `car_action` in the engine model's vocabulary), every
  row traceable to one artefact, the relationship edges naming real endpoints.
  It reads `data_store/processed/byakugan` by default, or `--car-dir DIR`.
- The CAR JSON is the contract every sink reads — see the Byakugan engine's
  [CAR-Pipeline.md](https://github.com/Get-Sybers/Byakugan/-/blob/main/docs/CAR-Pipeline.md).

### Step 7: Bring up the Elastic-native backend
```bash
sudo sysctl -w vm.max_map_count=262144
dx deploy stack             # installs docker if missing, generates secrets + TLS, brings the stack up, verifies it
```
- Elasticsearch + Kibana (security **on**, TLS on the Elasticsearch API), Fleet
  Server, and Filebeat as the shipper — official Elastic images pinned to
  `ELASTIC_VERSION`, all published on `127.0.0.1`. Kibana is at
  `http://127.0.0.1:5601` (log in as `elastic`).
- Credentials live in the gitignored per-host secret store
  (`ansible/inventory/secrets/<host>/`) — generated on first deploy, never
  overwritten, overridable as ansible variables (`ansible-vault
  encrypt_string` works). **Never commit them.**
- Full detail (Fleet enrolment, the CA, shipping): [the stack](architecture/the-stack.md).

### Step 8: Deliver evidence to the backend
- Filebeat tails the tree mounted at `ELASTIC_INGEST_DIR` (`<type>/**/*.json[l]`)
  and writes each line into the `logs-dxdfir.<type>-<namespace>` data stream —
  point `ELASTIC_INGEST_DIR` at `data_store/processed` (or mount your own curated
  `<type>/` tree). Filebeat's own registry keeps re-runs idempotent. It excludes
  `processed/byakugan/` and `processed/byakugan-load/` — the CAR is delivered
  ECS-projected instead (next bullet), not as raw evidence.
- `dx byakugan load` bulk-loads the materialised CAR (`processed/byakugan/`) into
  the `logs-car.<object>-<namespace>` x13, `logs-car.rel-<namespace>`,
  `logs-car.inferred-<namespace>` and `logs-car.content-<namespace>` data
  streams (the `dxdfir_car_load` role,
  `byakugan load`, behind the stack's own bring-up gate). `--setup` (the
  default, first run) applies the index/component templates; `--no-setup` for
  routine repeat loads once they exist. The `car-detections` lookup-index
  writer retired with the host-python package — its contract
  (`join-keys.yml`, `_id <detection.id>:<event.id>`) rides the baked rules
  set, and the Detection Engine sweep that fills it is engine-side future
  work. The
  Phase-0 [risk gate](riskgate.md) proves the
  two assumptions it rests on (evidence-time detection runs, ES|QL
  `LOOKUP JOIN`) and documents the projection.

### Step 9: Detect and exchange
- The detections are Elastic rules-as-code — one ES|QL or EQL rule file per
  detection, [shipped with the Byakugan engine and baked into its image at
  `/rules`](https://github.com/Get-Sybers/Byakugan/-/blob/main/rules/README.md), validated by the engine's build gate and
  test suite (`rules/validate.py`) — run by Elastic's Detection Engine on the
  stack above.
- `dx byakugan export-stix` turns detection hits into STIX 2.1 sightings, and the
  `byakugan` namespace carries the OpenCTI exchange (indicators in, sightings back),
  each verb one confined run of the byakugan image's own exchange sub-tools
  via the `dxdfir_exchange` role; see `dx byakugan -h` and
  [the engine's STIX-Exchange.md](https://github.com/Get-Sybers/Byakugan/-/blob/main/docs/STIX-Exchange.md).

---

For detailed script usage, refer to the [📜 Scripts Overview](scripts/Scripts-Overview.md).
