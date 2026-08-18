# 📜 Scripts Directory (`./scripts`)

This directory contains automation scripts for **forensic data processing** and
for **deploying, schema-loading and ingesting into the Kusto emulator** — the
DX_DFIR pipeline. Host artefacts are collected with **Velociraptor offline
collectors running the EZ Tools** (replacing the removed KAPE automation).

> **These scripts are the legacy layer.** The pipeline's front-end is now the
> **`dxdfir` CLI** driving the **`get_sybers.dfir` Ansible collection** (one role
> per source) — see [How It Runs](/README.md#how-it-runs). Each `process-*.sh`
> below has a matching `dfir_<source>` role (`dxdfir process <source>`); the
> deploy/apply/ingest scripts map to the `dfir_deploy_adx` / `dfir_ingest_adx`
> roles (`dxdfir deploy` / `dxdfir ingest`). Scripts are retired per source as each
> role's full path is proven (epic #46); until then both are available, and this
> page documents the scripts.

---

## 📂 Processing scripts

Each processor reads evidence from `data_store/raw/<type>/` and writes
ingest-ready output to `data_store/processed/<tool>/`. All are container-first and
resolve their own path, so they can be run from anywhere.

| Script | Reads | Produces |
|---|---|---|
| `process-log2timeline-Dynamic.sh` | disk images (E01/VMDK/raw) | Plaso `.plaso` → **JSON Lines** (`psort -o json_line`), split into **one `L2t<Parser>` table per top-level parser** (`scripts/lib/l2t-split.py`); events enriched with hostname / disk id / volume id. |
| `process-zeek-ALL.sh` | PCAPs | Zeek **JSON** logs, ISO-8601 timestamps — typed `conn` (`network.ZeekConn`) + a generic table for every other log type (`network.Zeek`). |
| `process-volatility.sh` | memory images | **Volatility 3** (containerised, `sk4la/volatility3`) → one JSONL file per plugin via a custom `jsonl_dfir` renderer. Ships custom plugins `dfir_processes` (psscan → full path/parent/DLLs) and `dfir_registry` (RECmd-style keys from RAM). |
| `process-evtx-EvtxECmd.sh` | Windows Event Logs (`.evtx`) | EvtxECmd → JSON (`host.EvtxEcmdJson`). ⚠️ needs operator-supplied EvtxECmd. |
| `process-velociraptor.sh` | Velociraptor offline-collector output (EZ Tools) | JSON for `host.VelociraptorJson` (RECmd registry, etc.). |
| `process-signatures.sh` | pcaps / files / images / EVTX | Signature/detection lanes — see **Signature detection** below. |

### Signature detection (`process-signatures.sh`)

Three standalone lanes under `scripts/signatures/`, each emitting self-describing
JSONL to `data_store/processed/signatures/<tool>/`. Run all, or `--only <lane>`;
`--fetch` provisions rules/binaries when online.

| Lane | Input | Output |
|---|---|---|
| `suricata.sh` | PCAPs | Suricata EVE JSON, `source_pcap`-tagged, alert+context event types. |
| `yara.sh` | **files**, **disk images** (mounted in place — `ewfmount`+`ntfs-3g`, never extracts), **memory** (via Volatility `windows.vadyarascan`, matches carry PID context) | one JSON object per match (rule, target, offsets/strings). |
| `hayabusa.sh` | loose `.evtx` + disk images | Hayabusa Sigma detection timeline (native binary). Disk-image EVTX come from a mount, or a **targeted** `image_export --artifact_filters WindowsEventLogs` pull (event logs only, transient). |

> **Mounting note.** Disk-image mounting needs `/dev/fuse`, which an LXC blocks by
> default; the lanes skip disk images with a host-fix message until it's enabled.
> **Hayabusa's `-J` JSON input does not detect** (0 hits vs 792 natively) — real
> `.evtx` is required, from a mount or the targeted extraction.

---

## 📂 Deployment & ingest scripts

| Script | Description |
|---|---|
| `setup-environment.sh` | Installs Docker and userland deps (distro-aware); image seeding split into `save-docker-images.sh`. |
| `save-docker-images.sh` | Pull / save / load the analysis Docker images for offline / air-gapped hosts. |
| `deploy-kusto.sh` | Deploys the **Kusto emulator** (analysis backend). Localhost-only by default (the emulator has **no auth**), isolated network, ephemeral database. ⚠️ Sets `ACCEPT_EULA=Y` on your behalf; `--help` for flags. |
| `apply-kusto-schema.sh` | Creates the Kusto databases, tables, ingestion mappings and the MITRE CAR functions. Idempotent. |
| `ingest-kusto.sh` | Loads `data_store/processed` into the emulator: **Plaso `L2t*`, EvtxECmd, Zeek (conn + generic), Volatility, Velociraptor**. `--only <source>` to load one. |

Shared libraries in `scripts/lib/`: `docker-lifecycle.sh` (container replace
policy, isolated network, readiness, egress verification), `kusto-api.sh` (the
emulator's REST endpoints, failure detection, reachability), and `l2t-split.py`
(splits Plaso json_line into per-parser `L2t*` tables). Signature-lane helpers live
in `scripts/signatures/lib/`.

The Splunk-era and KAPE PowerShell scripts were retired (git history and the frozen
`deprecated` branch keep them).

---

## 🧹 Self-cleanup

The docker-using processors (`process-evtx`, `process-log2timeline`,
`process-zeek`, `process-signatures`) run a `prune_dangling` trap on exit that
removes docker layers left dangling when a pulled `:latest` tag moves — only
untagged, unreferenced images; tool images and live containers are untouched.

---

## ⚠️ Licensing before you run

- **`deploy-kusto.sh` accepts Microsoft's Software License Terms for you**
  (`ACCEPT_EULA=Y`). The emulator is *as-is*, unsupported, and documented as
  generally unsuitable for production.

Full detail in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).

## ⚙️ Usage

- Ensure **Docker** is installed and running.
- Scripts assume the repository's **directory structure** (see
  [`data_store/README.md`](/data_store/README.md) for raw data sources).

```bash
./scripts/deploy-kusto.sh
./scripts/process-zeek-ALL.sh
./scripts/ingest-kusto.sh --only zeek
```

> ⚠️ The processing scripts run `chmod -R 777` on their working directories under
> `data_store/` to work around Docker UID mismatches. Don't run them on a shared host.
