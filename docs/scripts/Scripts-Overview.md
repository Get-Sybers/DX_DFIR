# Scripts Directory (`./scripts`)

This directory contains **host provisioning** scripts: installing the
environment and seeding the analysis container images. Host artefacts are
collected with **the hardened GoDFIR-toolz containers**.

> **The `dx` CLI and the `get_sybers.dxdfir` collection are the supported
> front-end** (see [How It Runs](../../README.md#how-it-runs)). Processing runs
> through the collection's roles and the
> [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) tool containers they
> run, not host shell scripts: `dx process <source>` and the CAR lane
> (`dx byakugan build` / `dx byakugan verify`); the analysis backend is the
> Elastic stack deployed by the `dxdfir_stack` role (`dx deploy stack`).

---

## Processing

Per-source processing runs through the **`dx` CLI** (`dx process <source>`),
which drives the `get_sybers.dxdfir` roles (see [How It Runs](../../README.md#how-it-runs)).
Each role builds its `docker run` purely from the tool image's `contract.yml`
(the tool's environment variables and mounts), and the container discovers,
batches and skips its own inputs; there is no host-side processor and no
processing shell script.

### Signature detection

The detection lane is the `get-sybers/signatures` image, run by the
`godfir_signatures` role: four sub-tools of one hardened container, each a
separate contract-driven run over the evidence tree it reads. Each writes
self-describing JSONL to `data_store/processed/detections/<sub-tool>/<item>/`.
Run all, or select with `godfir_signatures_lanes`; rulesets are baked into the
image, with operator rulesets mounted in their place (see
[Signature-Rules](../Signature-Rules.md)).

| Sub-tool | Input | Output |
|---|---|---|
| `yara` | **loose files** under `raw/other_raw_data/` and **memory images** under `raw/memory/` (scanned directly) | one hit record per rule match (rule, target, offsets/strings). |
| `suricata` | every capture under `raw/pcaps/` | Suricata EVE JSON per capture. |
| `hayabusa` | every event-log host: `raw/logs/winevt/<host>/`, and every disk image under `raw/disk_images/` and `raw/VM_files/` read **on the image** (the baked gomount pulls its event logs into `/work` while hayabusa runs) | Hayabusa Sigma detection timeline (native binary, `verbose` profile). |
| `scan` | every disk image under `raw/disk_images/` and `raw/VM_files/` (E01/Ex01, raw, VMDK, VHDX, VHD, QCOW2, VDI), streamed by gomount through goyara in **userspace** (no `/dev/fuse`, nothing mounted on the host) | goyara hit records per image. |

> Disk-image event logs reach Hayabusa off the image itself: the signatures
> image's baked gomount pulls them into `/work` while hayabusa runs (it needs
> real `.evtx` input; its `-J` JSON input does not detect). Nothing is
> exported; `dxdfir_export` remains a utility.

---

## CAR and the backend

No shell scripts here either:

- **`dx byakugan build`** runs the external Byakugan engine inside the hardened
  `get-sybers/byakugan` image (cloned + built at its Dockerfile pin by
  `dx build images`), driven from the image's contract (`byakugan build`),
  over the processed tree: one `car_<object>.jsonl` per populated object plus
  `car_relationships.jsonl` (always written, even empty) per source, under
  `data_store/processed/byakugan/<source>/` (`--derive` adds
  `car_inferred.jsonl`).
  **`dx byakugan verify`** is the engine's own gate over what was written;
  **`dx byakugan export-timeline`** unions a tree into one timeline JSONL.
- The **Elastic-native backend** is deployed with `dx deploy stack`
  ([the stack](../architecture/the-stack.md)). Filebeat tails the processed tree directly
  (`ELASTIC_INGEST_DIR` is the knob) into `logs-dxdfir.<type>-*` data
  streams; **`dx byakugan load`** bulk-loads the materialised CAR into
  `logs-car.*` instead (the `dxdfir_car_load` role, `byakugan load`);
  **`dx byakugan export-stix`** carries the STIX/CTI exchange through the byakugan
  image's own exchange sub-tools (the `dxdfir_exchange` role). The
  `car-detections` Detection-Engine-alert sweep is still future work
  ([risk gate](../riskgate.md)).

## Provisioning scripts

The analysis container images are catalogued in [Containers](../Containers.md).

| Script | Description |
|---|---|
| `setup-environment.sh` | Bootstraps ansible (userland deps, venv, pinned collections), then provisions the Docker engine THROUGH it (`dxdfir-bootstrap.yml` → the `dxdfir_stack` role's `docker_ensure`); the git submodules; the Python venv, the Go toolchain and the `dx` front-end. The Byakugan CAR engine is cloned + built into the `get-sybers/byakugan` image by `dx build images`, not checked out on the host. Image seeding is split into `save-docker-images.sh`. |
| `save-docker-images.sh` | Save the built hardened `get-sybers/*` images (+ the pulled Elastic-stack images) as tarballs; `--load` / `--verify` restore them and assert the hardened inventory. A launcher only: the sets, pulls, exports and loads are the `dxdfir_images` role's save/load tasks (`dxdfir-images-save.yml` / `dxdfir-images-load.yml`). |

---

## Licensing before you run

The tools this pipeline runs are Apache/BSD/MIT; the Elastic stack runs under the
Elastic License 2.0 with only the free Basic-tier features enabled; the fetched
rulesets and sample corpora carry their own terms. Read
[THIRD_PARTY_NOTICES.md](../../.github/THIRD_PARTY_NOTICES.md) before commercial use.

## Usage

- Ensure **Docker** is installed and running.
- Everything assumes the repository's **directory structure** (see
  [`data_store/README.md`](../../data_store/README.md) for raw data sources).

```bash
dx process zeek
dx byakugan build
dx byakugan verify
```

> ⚠️ The processing lanes `chmod 777` their output directories under
> `data_store/processed/` so the containers' non-root user can write them. Don't
> run them on a shared host.
