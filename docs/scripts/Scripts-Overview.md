# Scripts Directory (`./scripts`)

This directory contains **host provisioning** scripts — installing the
environment and seeding the analysis container images. Host artefacts are
collected with **the hardened GoDFIR-toolz containers**
(replacing the removed KAPE automation).

> **The `dxdfir` CLI and the `get_sybers.dxdfir` collection are the supported
> front-end** — see [How It Runs](/README.md#how-it-runs). Every data-pipeline
> shell script has been retired: the per-source `process-*.sh` scripts, the
> signature-lane scripts, and the deploy/apply/ingest scripts of the retired
> Kusto backend (`scripts/lib/`). Their behaviour lives in the collection's roles
> and the [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) tool
> containers they run: `dxdfir process <source>` and the CAR lane
> (`dxdfir build-car` / `dxdfir verify-car`); the analysis backend is the Elastic
> stack deployed by the `dxdfir_stack` role (`dxdfir deploy stack`).

---

## Processing

Per-source processing runs through the **`dxdfir` CLI** (`dxdfir process <source>`),
which drives the `get_sybers.dxdfir` roles (see [How It Runs](/README.md#how-it-runs)).
Each role builds its `docker run` purely from the tool image's `contract.yml` —
the tool's environment variables and mounts — and the container discovers,
batches and skips its own inputs; there is no host-side processor and no
processing shell script.

### Signature detection

The detection lane is the `get-sybers/signatures` image, run by the
`dxdfir_signatures` role: four sub-tools of one hardened container, each a
separate contract-driven run over the evidence tree it reads. Each writes
self-describing JSONL to `data_store/processed/detections/<sub-tool>/<item>/`.
Run all, or select with `dxdfir_signatures_lanes`; rulesets are baked into the
image, with operator rulesets mounted in their place — see
[Signature-Rules](/docs/Signature-Rules.md).

| Sub-tool | Input | Output |
|---|---|---|
| `yara` | **loose files** under `raw/other_raw_data/` and **memory images** under `raw/memory/` (scanned directly) | one hit record per rule match (rule, target, offsets/strings). |
| `suricata` | every capture under `raw/pcaps/` | Suricata EVE JSON per capture. |
| `hayabusa` | every `.evtx` tree: `raw/logs/winevt/` and the evtx lane's disk-image export (`processed/windows_logs/_extracted_evtx/`) | Hayabusa Sigma detection timeline (native binary, `verbose` profile). |
| `scan` | every disk image under `raw/disk_images/`, streamed by gomount through goyara in **userspace** — no `/dev/fuse`, nothing mounted on the host | goyara hit records per image. |

> Disk-image event logs reach Hayabusa through the evtx lane's one canonical
> export (`image_export --artifact_filters WindowsEventLogs`, event logs only),
> so an image is exported once for both lanes. Hayabusa needs real `.evtx`
> input — its `-J` JSON input does not detect.

---

## CAR and the backend

No shell scripts here either:

- **`dxdfir build-car`** runs the external Byakugan engine inside the hardened
  `get-sybers/byakugan` image (cloned + built at its Dockerfile pin by
  `dxdfir build-docker`), driven from the image's contract (`byakugan build`),
  over the processed tree: one `car_<object>.jsonl` per populated object plus
  `car_relationships.jsonl` (always written, even empty) per source, under
  `data_store/processed/byakugan/<source>/` (`--derive` adds
  `car_inferred.jsonl`).
  **`dxdfir verify-car`** is the engine's own gate over what was written;
  **`dxdfir build-timeline`** unions a tree into one timeline JSONL.
- The **Elastic-native backend** is deployed with `dxdfir deploy stack`
  ([the stack](../architecture/the-stack.md)). Filebeat tails the processed tree directly
  (`ELASTIC_INGEST_DIR` is the knob) into `logs-dxdfir.<type>-*` data
  streams; **`dxdfir load-car`** bulk-loads the materialised CAR into
  `logs-car.*` instead (the `dxdfir_car_load` role, `byakugan load`), and
  **`dxdfir stamp-detections`** stamps Byakugan's behaviour hits into the
  `car-detections` lookup index — the Detection-Engine-alert sweep is still
  future work ([risk gate](/docs/riskgate.md)).

## Provisioning scripts

The analysis container images are catalogued in [Containers](/docs/Containers.md).

| Script | Description |
|---|---|
| `setup-environment.sh` | Installs Docker and userland deps (distro-aware) and the git submodules; the Python venv, the Go toolchain and the `dxdfir` front-end. The Byakugan CAR engine is no longer a host checkout — it is cloned + built into the `get-sybers/byakugan` image by `dxdfir build-docker`. Image seeding is split into `save-docker-images.sh`. |
| `save-docker-images.sh` | Save the built hardened `get-sybers/*` images (+ the pulled Elastic-stack images) as tarballs; `--load` / `--verify` restore them and assert the hardened inventory. A launcher only — the sets, pulls, exports and loads are the `dxdfir_images` role's save/load tasks (`dxdfir-images-save.yml` / `dxdfir-images-load.yml`). |

The Splunk-era and KAPE PowerShell scripts were retired (git history and the frozen
`deprecated` branch keep them).

---

## Licensing before you run

The tools this pipeline runs are Apache/BSD/MIT; the Elastic stack runs under the
Elastic License 2.0 with only the free Basic-tier features enabled; the fetched
rulesets and sample corpora carry their own terms. Read
[THIRD_PARTY_NOTICES.md](/.github/THIRD_PARTY_NOTICES.md) before commercial use.

## Usage

- Ensure **Docker** is installed and running.
- Everything assumes the repository's **directory structure** (see
  [`data_store/README.md`](/data_store/README.md) for raw data sources).

```bash
dxdfir process zeek
dxdfir build-car
dxdfir verify-car
```

> ⚠️ The processing lanes `chmod 777` their output directories under
> `data_store/processed/` so the containers' non-root user can write them. Don't
> run them on a shared host.
