# Get Started

> These steps reflect the paths that actually work today. Read
> [THIRD_PARTY_NOTICES.md](/.github/THIRD_PARTY_NOTICES.md) for the terms that bind
> you as the operator (the tools, the fetched rulesets, the Elastic licence).

### Driving the pipeline

The **`dxdfir` CLI** is the pipeline's front-end (three-layer design — see
[How It Runs](/README.md#how-it-runs)). Install it, then the numbered steps below
walk a run end to end:

```bash
scripts/setup-environment.sh  # builds the Go dxdfir front-end (go/) + installs the processors and ansible-core
dxdfir process plaso     # sources: plaso | zeek | evtx | memory | godfir-toolz | signatures
dxdfir build-car         # normalise every processed source into CAR (car_<object>.jsonl)
dxdfir verify-car        # the CAR correctness gate over what was written
dxdfir validate          # run the repo check harness
```

The processors write the tree the CAR lane builds from and Filebeat ships.
`man dxdfir` for the manual.

### Step 1: Setup Environment
- **Run setup-environment.sh:**
  ```bash
  DX_DFIR/scripts/setup-environment.sh
  ```
_Refer to [📁 Setup_Environment](/docs/scripts/Setup_Environment.md) for details on the script._

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

_Refer to [📁 Dir-Structure](/docs/Dir-Structure.md) for detailed directory structures._

### Step 3: Process Forensic Images (E01 / VMware)
```bash
dxdfir process plaso
```
- Automates forensic analysis of all `.E01` disk images and VMware VM exports using Plaso.
- Output lands in `data_store/processed/log2timeline/jsonl/<source>/timeline.jsonl`
  (Plaso `json_line`) and the `.plaso` storage files in `storage/<source>/`, each with
  its tool log beside it.

### Step 4: Process PCAPs with Zeek
```bash
dxdfir process zeek
```
- Automates processing of all network capture files (`.pcap` and `.pcapng`) using Zeek.
- Output lands in `data_store/processed/zeek/<pcap-name>/`.

### Step 5: Parse Windows Event Logs (optional)
```bash
dxdfir process evtx
```
- Converts `.evtx` in `data_store/raw/logs/winevt/<host>/` to normalised JSON
  using **goevtx** (`get-sybers/goevtx`, built by `dxdfir build-docker`) —
  nothing operator-supplied.
- See [Scripts-Overview](/docs/scripts/Scripts-Overview.md) for the pipeline layers.

### Step 6: Build and verify the CAR
```bash
dxdfir build-car                             # every source under data_store/processed
dxdfir verify-car                            # the promotion gate over the result
dxdfir build-timeline data_store/processed/byakugan # one time-ordered timeline across every source
```
- `build-car` drives the external [Byakugan](https://github.com/Get-Sybers/byakugan)
  engine, run inside the hardened `get-sybers/byakugan` image — cloned + built at
  the `BYAKUGAN_REF` commit pinned in its Dockerfile by `dxdfir build-docker`: each processed
  source becomes its own `car_<object>.jsonl` per populated CAR object plus
  `car_relationships.jsonl` (always written, even empty — the build's done/skip
  marker) under `data_store/processed/byakugan/<source>/`. A source whose
  `car_relationships.jsonl` exists is left alone; `--rebuild` re-derives it
  after a map change.
- `verify-car` asserts what was written: each exercised object populated, values
  sane (IPs, ports, SIDs, `car_action` in the engine model's vocabulary), every
  row traceable to one artefact, the relationship edges naming real endpoints.
  It reads `data_store/processed/byakugan` by default, or `--car-dir DIR`.
- The CAR JSON is the contract every sink reads — see the Byakugan engine's
  [CAR-Pipeline.md](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-Pipeline.md).

### Step 7: Bring up the Elastic-native backend
```bash
sudo sysctl -w vm.max_map_count=262144
dxdfir deploy stack             # installs docker if missing, generates secrets + TLS, brings the stack up, verifies it
```
- Elasticsearch + Kibana (security **on**, TLS on the Elasticsearch API), Fleet
  Server, and Filebeat as the shipper — official Elastic images pinned to
  `ELASTIC_VERSION`, all published on `127.0.0.1`. Kibana is at
  `http://127.0.0.1:5601` (log in as `elastic`).
- Credentials live in the gitignored per-host secret store
  (`ansible/inventory/secrets/<host>/`) — generated on first deploy, never
  overwritten, overridable as ansible variables (`ansible-vault
  encrypt_string` works). **Never commit them.**
- Full detail (Fleet enrolment, the CA, shipping): [the stack](/docs/architecture/the-stack.md).

### Step 8: Deliver evidence to the backend
- Filebeat tails the tree mounted at `ELASTIC_INGEST_DIR` (`<type>/**/*.json[l]`)
  and writes each line into the `logs-dxdfir.<type>-<namespace>` data stream —
  point `ELASTIC_INGEST_DIR` at `data_store/processed` (or mount your own curated
  `<type>/` tree). Filebeat's own registry keeps re-runs idempotent. It excludes
  `processed/byakugan/` and `processed/byakugan-load/` — the CAR is delivered
  ECS-projected instead (next bullet), not as raw evidence.
- `dxdfir load-car` bulk-loads the materialised CAR (`processed/byakugan/`) into
  the `logs-car.<object>-<namespace>` x13, `logs-car.rel-<namespace>`,
  `logs-car.inferred-<namespace>` and `logs-car.content-<namespace>` data
  streams (the `dxdfir_car_load` role,
  `byakugan load`, behind the stack's own bring-up gate). `--setup` (the
  default, first run) applies the index/component templates; `--no-setup` for
  routine repeat loads once they exist. `dxdfir stamp-detections` stamps the
  behaviour hits Byakugan's `--stix` export already materialises (STIX
  Sightings in each source's `stix_bundle.json`) into the `car-detections`
  lookup index — `join-keys.yml`'s own contract, `_id <detection.id>:<event.id>`;
  a sweep from the Detection Engine's own alerts is still future work. The
  Phase-0 [risk gate](/docs/riskgate.md) proves the
  two assumptions it rests on (evidence-time detection runs, ES|QL
  `LOOKUP JOIN`) and documents the projection.

### Step 9: Detect and exchange
- The detections are Elastic rules-as-code — one ES|QL or EQL rule file per
  detection under [`python/get_sybers_dxdfir/detect/rules/`](/python/get_sybers_dxdfir/detect/rules/README.md),
  validated by `python -m get_sybers_dxdfir.detect.rules_loader` — run by Elastic's
  Detection Engine on the stack above.
- `dxdfir stix export` turns detection hits into STIX 2.1 sightings, and the
  `stix` sub-app carries the OpenCTI exchange (indicators in, sightings back);
  see `dxdfir stix -h` and [python/get_sybers_dxdfir/stix/README.md](/python/get_sybers_dxdfir/stix/README.md).

---

For detailed script usage, refer to the [📜 Scripts Overview](/docs/scripts/Scripts-Overview.md).
