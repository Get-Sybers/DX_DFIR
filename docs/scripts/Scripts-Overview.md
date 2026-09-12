# Scripts Directory (`./scripts`)

This directory contains **host provisioning** scripts — installing the
environment and seeding the analysis container images. Host artefacts are
collected with **the hardened EZ-tool containers**
(replacing the removed KAPE automation).

> **The `dxdfir` CLI and the `get_sybers.dxdfir` collection are the supported
> front-end** — see [How It Runs](/README.md#how-it-runs). Every data-pipeline
> shell script has been retired: the per-source `process-*.sh` scripts, the
> signature-lane scripts, and the deploy/apply/ingest scripts of the retired
> Kusto backend (`scripts/lib/`). Their behaviour lives in the `get_sybers_dxdfir`
> package and the collection's roles: `dxdfir process <source>` and the CAR lane
> (`dxdfir build-car` / `dxdfir verify-car`); the analysis backend is the Elastic
> stack under `docker/elastic/`, brought up with docker compose.

---

## Processing

Per-source processing runs through the **`dxdfir` CLI** (`dxdfir process <source>`),
which drives the `get_sybers.dxdfir` roles and the `get_sybers_dxdfir` Python processors
(see [How It Runs](/README.md#how-it-runs)); each is also runnable as
`python -m get_sybers_dxdfir.<source>`. The retired per-source `process-*.sh` scripts
have been removed — their behaviour lives in those processors. No processing shell
scripts remain.

### Signature detection (`get_sybers_dxdfir.signatures`)

The three signature lanes (formerly `scripts/process-signatures.sh` +
`scripts/signatures/`) are Python: `python -m get_sybers_dxdfir.signatures`, or the
`dxdfir_signatures` role. Each lane emits self-describing JSONL to
`data_store/processed/signatures/<tool>/`. Run all, or `--only <lane>`; `--fetch`
provisions rules when online (the YARA lane fetches the pinned
[DetectRaptor](https://github.com/mgreen27/DetectRaptor) ruleset). To supply
your own YARA or Suricata rules (and tune Suricata's `HOME_NET`), see
[Signature-Rules](/docs/Signature-Rules.md).

**Hayabusa** also runs inside the **evtx pipeline** (`dxdfir process evtx`,
or `python -m get_sybers_dxdfir.evtx --hayabusa`): it scans the same `.evtx` that
lane collects — loose logs or those extracted from a disk image via `--image-src`
— so disk-image EVTX reaches Hayabusa through the evtx lane's extraction rather
than needing a `/dev/fuse` mount.

| Lane | Input | Output |
|---|---|---|
| `suricata` | PCAPs | Suricata EVE JSON, `source_pcap`-tagged, alert+context event types. |
| `yara` | **files**, **disk images** (mounted read-only in place — `ewfmount`+`ntfs-3g`, never extracts; `--yara-sources` selects), **memory** (via Volatility `windows.vadyarascan`, matches carry PID context) | one JSON object per match (rule, target, offsets/strings). |
| `hayabusa` | loose `.evtx` (+ disk-image EVTX via the evtx lane's targeted `image_export --artifact_filters WindowsEventLogs` pull — event logs only, transient) | Hayabusa Sigma detection timeline (native binary). |

> **Mounting note.** Disk-image mounting needs `/dev/fuse`, which an LXC blocks by
> default; the YARA disk source skips images with a host-fix note until it's
> enabled (nothing is ever extracted out of an image for YARA).
> **Hayabusa's `-J` JSON input does not detect** (0 hits vs 792 natively) — real
> `.evtx` is required, from a mount or the targeted extraction.

---

## CAR and the backend

No shell scripts here either:

- **`dxdfir build-car`** drives the vendored byakugan engine (formerly
  PIIAT-MitreCar) over the processed tree: one `car.db` + `superset.db` and
  one `car_<object>.jsonl` per populated object per source, under
  `data_store/processed/car/<source>/`.
  **`dxdfir verify-car`** (`get_sybers_dxdfir.carcheck`) is the gate over what was
  written; **`dxdfir car-timeline`** unions a tree into one timeline JSONL.
- The **Elastic-native backend** (`docker/elastic/`) is brought up with
  `docker compose` (see its README). Filebeat ships the delivered evidence tree
  (`playbooks/dxdfir-ingest-sofelk.yml` delivers it) into `logs-dxdfir.<type>-*` data
  streams; the CAR→ECS load into `logs-car.*` is the next phase
  ([risk gate](/docs/riskgate.md)).

## Provisioning scripts

The analysis container images are catalogued in [Containers](/docs/Containers.md).

| Script | Description |
|---|---|
| `setup-environment.sh` | Installs Docker and userland deps (distro-aware); image seeding split into `save-docker-images.sh`. |
| `save-docker-images.sh` | Save the built hardened `dxdfir/*` images (+ the pulled .NET runtime) as tarballs; `--load` / `--verify` restore them and assert the hardened inventory. |
| `package-offline.sh` | Build ONE portable air-gap bundle: images, the `get_sybers_dxdfir` processor package + deps as wheels, the Go front-end's vendored modules (`go-vendor.tar`), pinned collections, the repo, and `data_store/dependencies/` (YARA/Suricata/Hayabusa rulesets + binary, Volatility symbols, EvtxECmd) under a `MANIFEST.sha256`. |
| `setup-offline.sh` | Set up from that bundle with zero network: manifest-verify everything, unpack the repo + detection dependencies, load images, install the package/collections offline, build the Go `dxdfir` front-end from the vendored modules, finish with `dxdfir verify-images` (or the same audit play via `ansible-playbook` when no Go toolchain is present). |

The Splunk-era and KAPE PowerShell scripts were retired (git history and the frozen
`deprecated` branch keep them).

---

## Licensing before you run

The tools this pipeline runs are Apache/BSD/MIT; the Elastic stack runs under the
Elastic License 2.0 with only the free Basic-tier features enabled; the fetched
rulesets and sample corpora carry their own terms. Read
[THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md) before commercial use.

## Usage

- Ensure **Docker** is installed and running.
- Everything assumes the repository's **directory structure** (see
  [`data_store/README.md`](/data_store/README.md) for raw data sources).

```bash
dxdfir process zeek
dxdfir build-car
dxdfir verify-car
```

> ⚠️ The processing lanes `chmod 777` their working directories under
> `data_store/` to work around Docker UID mismatches. Don't run them on a shared host.
