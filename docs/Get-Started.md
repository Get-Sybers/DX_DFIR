# Get Started

> These steps reflect the paths that actually work today. See the
> [pipeline task board](/project-progress.md) before you start, and
> read [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md) for the terms that bind
> you as the operator (the tools, the fetched rulesets, the Elastic licence).

### Driving the pipeline

The **`dxdfir` CLI** is the pipeline's front-end (three-layer design — see
[How It Runs](/README.md#how-it-runs)). Install it, then the numbered steps below
walk a run end to end:

```bash
scripts/setup-environment.sh  # builds the Go dxdfir front-end (go/) + installs the processors and ansible-core
dxdfir process plaso     # sources: plaso | zeek | evtx | volatility | zimmerman | signatures
dxdfir build-car         # normalise every processed source into CAR (car_<object>.jsonl)
dxdfir verify-car        # the CAR correctness gate over what was written
dxdfir validate          # run the repo check harness
```

The processors write the tree the CAR lane builds from (`--pipeline elastic`,
the default); the retiring SOF-ELK path is `dxdfir process <source> --pipeline
sofelk`, then the collection's `dxdfir-deploy-sofelk.yml` / `dxdfir-ingest-sofelk.yml`
playbooks. `man dxdfir` for the manual.

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
- Output lands in `data_store/processed/log2timeline/jsonl/` (Plaso `json_line`,
  one file per host), the `.plaso` databases in `plaso/`, and job logs in `logs/`.

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
- Converts `.evtx` in `data_store/raw/logs/winevt/<host>/` using EvtxECmd.
- Requires operator-supplied EvtxECmd — see
  [the README](/data_store/dependencies/evtxecmd/README.md). MIT licensed, no
  commercial-use restriction.
- See [Scripts-Overview](/docs/scripts/Scripts-Overview.md) for the pipeline layers.

### Step 6: Build and verify the CAR
```bash
dxdfir build-car                             # every source under data_store/processed
dxdfir verify-car                            # the promotion gate over the result
dxdfir car-timeline data_store/processed/car # one time-ordered timeline across every source
```
- `build-car` drives the external [Byakugan](https://github.com/Get-Sybers/byakugan)
  engine — the recursive checkout `scripts/setup-environment.sh` provisions at
  the commit pinned in `byakugan.ref` (default: `byakugan/` beside the repo;
  set `$BYAKUGAN_ROOT` to point elsewhere): each processed source becomes its
  own `car.db` + `superset.db` and one `car_<object>.jsonl` per populated CAR
  object (plus `car_relationships.jsonl`) under
  `data_store/processed/car/<source>/`. A source whose store exists is
  left alone; `--rebuild` re-derives it after a map change.
- `verify-car` asserts what was written: each exercised object populated, values
  sane (IPs, ports, SIDs, `car_action` in the engine model's vocabulary), every
  row traceable to one artefact, the relationship edges naming real endpoints.
  It reads `data_store/processed/car` by default, or `--car-dir DIR`.
- The CAR JSON is the contract every sink reads — see
  [docs/CAR-Pipeline.md](/docs/CAR-Pipeline.md).

### Step 7: Bring up the Elastic-native backend
```bash
cd docker/elastic
cp .env.example .env            # then replace EVERY placeholder (see the file)
sudo sysctl -w vm.max_map_count=262144
docker compose up -d
docker compose ps               # setup exits 0; the rest go (healthy)
```
- Elasticsearch + Kibana (security **on**, TLS on the Elasticsearch API), Fleet
  Server, and Filebeat as the shipper — official Elastic images pinned to
  `ELASTIC_VERSION`, all published on `127.0.0.1`. Kibana is at
  `http://127.0.0.1:5601` (log in as `elastic`).
- `.env` holds every credential and is gitignored — **never commit it**.
- Full detail (Fleet enrolment, the CA, shipping): [docker/elastic/README.md](/docker/elastic/README.md).

### Step 8: Deliver evidence to the backend
- Filebeat tails the tree mounted at `ELASTIC_INGEST_DIR` (`<type>/**/*.json[l]`)
  and writes each line into the `logs-dxdfir.<type>-<namespace>` data stream. The
  `dxdfir-ingest-sofelk.yml` playbook delivers a `processed/sofelk/<tool>/` tree
  into a watch dir with a delivery ledger — point `ELASTIC_INGEST_DIR` at the same
  path (process with `--pipeline sofelk` for that tree, or mount your own
  `<type>/` tree).
- The CAR→ECS load of `processed/car/` into the `logs-car.*` data streams and the
  `car-detections` lookup index is the next phase; the Phase-0
  [risk gate](/docs/riskgate.md) proves the two assumptions it rests on
  (evidence-time detection runs, ES|QL `LOOKUP JOIN`) and documents the
  projection.

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
