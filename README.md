# DX_DFIR Pipeline

[![release](https://img.shields.io/github/v/release/Get-Sybers/DX_DFIR?include_prereleases&label=release)](https://github.com/Get-Sybers/DX_DFIR/releases)
[![checks](https://github.com/Get-Sybers/DX_DFIR/actions/workflows/checks.yml/badge.svg)](https://github.com/Get-Sybers/DX_DFIR/actions/workflows/checks.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](/LICENSE)

Point DX_DFIR at a disk image or a PCAP; it processes the evidence with
**[Plaso](https://github.com/log2timeline/plaso)**, **[Zeek](https://zeek.org/)**,
**goevtx**,
**[flashback](https://github.com/Get-Sybers/flashback)** (memory) and the
**[GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz)**, normalises it into the
**[MITRE CAR](https://car.mitre.org/data_model/)** data model — materialised, one
`car_<object>.jsonl` per object — and feeds an **Elastic-native analysis backend**
(`docker/elastic`: Elasticsearch + Kibana with security on, Fleet, Filebeat; Basic
licence, everything on `127.0.0.1`). Detections are ES|QL / EQL rules-as-code run
by Elastic's Detection Engine, tagging the CAR evidence lines they match, with a
STIX 2.1 / OpenCTI exchange on top. You get normalised CAR in a real analytics
stack instead of a pile of CSVs.

> **Pre-release software** — the version and maturity are whatever the badge above
> says (it reads the latest [Release](https://github.com/Get-Sybers/DX_DFIR/releases)
> live). Runs on the author's corpus; interfaces may still change. Release notes:
> [CHANGELOG.md](/CHANGELOG.md).

## Quick start

Fresh Debian/Ubuntu host — installs Docker and the `dxdfir` CLI:

```bash
git clone --recursive https://github.com/Get-Sybers/DX_DFIR.git
cd DX_DFIR
./scripts/setup-environment.sh      # Docker + dxdfir CLI (log out/in once for the docker group)
```

Run the pipeline:

```bash
dxdfir build-docker                 # build the hardened tool images (once per host, before first process)
# drop evidence under data_store/raw/<type>/ (see data_store/README.md), then per source:
dxdfir process evtx                 # zeek | evtx | volatility | plaso | godfir-toolz | signatures
dxdfir build-car                    # normalise every source into per-source CAR stores (car_<object>.jsonl)
dxdfir verify-car                   # the CAR correctness gate over what was written
dxdfir build-timeline data_store/processed/byakugan # one property-rich, time-ordered timeline JSONL
```

Bring up the backend:

```bash
sudo sysctl -w vm.max_map_count=262144         # Elasticsearch needs this (persist it in /etc/sysctl.conf)
cd docker/elastic && cp .env.example .env      # replace EVERY placeholder (keys: openssl rand -hex 32), then:
docker compose up -d                            # Elasticsearch + Kibana + Fleet + Filebeat, localhost-only
```

Kibana is at `http://127.0.0.1:5601`. Filebeat tails the processed evidence tree
(`<type>/**/*.json[l]`, pointed at by `ELASTIC_INGEST_DIR`) into
`logs-dxdfir.<type>-*` data streams — see [docker/elastic/README.md](/docker/elastic/README.md).
The CAR→ECS projection into `logs-car.*` and ES|QL `LOOKUP JOIN` flagging against
the `car-detections` lookup index are proven by the Phase-0
[risk gate](/docs/riskgate.md); the detection rules are data under
[`python/get_sybers_dxdfir/detect/rules/`](/python/get_sybers_dxdfir/detect/rules/README.md),
and `dxdfir stix export` turns their hits into STIX 2.1 sightings. `dxdfir --help`
lists every command (`man dxdfir` for the manual).

## How it runs
<a name="how-it-runs"></a>

A three-layer stack — the **`dxdfir` CLI** → the **`get_sybers.dxdfir` Ansible
collection** (one role per source, one action per task) → the **`get_sybers_dxdfir`
Python package** — writing the processed tree the CAR lane builds from and
Filebeat ships. Each source runs as `dxdfir process <source>` (driving the
matching `dxdfir_<source>` role); processors are also runnable as
`python -m get_sybers_dxdfir.<source>`.

## What it produces

| Source | Command | Lands in (`data_store/processed/`) |
|:---|:---|:---|
| Disk images / VM exports (Plaso) | `process plaso` | `log2timeline/jsonl/` (Plaso `json_line`, one file per host) |
| PCAP (Zeek) | `process zeek` | `zeek/<capture>/` (`conn.json` + every other Zeek log) |
| Windows event logs + Sysmon (goevtx) | `process evtx` | `windows_logs/<host>/` (goevtx JSON) |
| Memory ([flashback](https://github.com/Get-Sybers/flashback)) | `process volatility` | `volatility/<image>/` (per-plugin JSONL) |
| GoDFIR-toolz artefacts — SRUM, registry, … | `process godfir-toolz` | `godfir-toolz/` |
| YARA / Suricata / Hayabusa | `process signatures` | `signatures/<lane>/` (JSONL) |

The **CAR layer is materialised**: the [Byakugan](https://github.com/Get-Sybers/byakugan)
engine (formerly PIIAT-MitreCar) normalises each processed source into finished
CAR events — one `car_<object>.jsonl` per object (13 objects) plus
`car_relationships.jsonl` — under `processed/byakugan/<source>/`. The engine runs
entirely inside the hardened `get-sybers/byakugan` image, cloned + built at the
commit pinned in `sources.yml` by `dxdfir build-docker` — never a host checkout.
Extraction happens once, in the engine, so that JSON is the contract every sink
reads and cannot drift from what the engine emits.

**Validated** by the CI **smoke test** (the real EVTX → goevtx → CAR path over
pinned Sysmon fixtures, asserting the extracted field values) and by
**`dxdfir verify-car`** (each CAR object populated, values sane — IPs, ports, SIDs —
`car_action` checked against the engine's model vocabulary, every row traceable to
a source). The other lanes (Plaso, Zeek, Volatility, GoDFIR-toolz) are run by hand on
the author's corpus. The Elastic-side assumptions (evidence-time detection runs,
`LOOKUP JOIN`) have their own [risk gate](/docs/riskgate.md).

## Before you run anything

- **The backend holds evidence.** The Elastic stack (`docker/elastic`) runs with
  security **on** — authentication, RBAC, TLS on the Elasticsearch API — but its
  credentials live in `docker/elastic/.env` (gitignored; never commit it) and
  every port binds `127.0.0.1`. See [SECURITY.md](/.github/SECURITY.md).
- **This handles real evidence.** `data_store/` is gitignored deny-by-default, so
  unknown/extensionless formats are covered — a safety net, not a guarantee. Check
  `git status` before you commit.

## Docs

**Start at the [documentation hub](/docs/README.md)** — it routes you by what you want:

- **New here?** [What DX_DFIR is](/docs/getting-started/README.md) · [Install](/docs/getting-started/install.md) · [First run](/docs/getting-started/first-run.md) · [The interface](/docs/getting-started/the-interface.md) · [Command reference](/docs/getting-started/commands.md)
- **How it works:** [Architecture overview](/docs/architecture/README.md) · [Processing lanes](/docs/architecture/processing-lanes.md) · [CAR pipeline](/docs/architecture/car-pipeline.md) · [The stack](/docs/architecture/the-stack.md)
- **Contributing:** [Standards](/docs/reference/README.md) · [Repository map](/docs/reference/repository-map.md) · [Contributing](/.github/CONTRIBUTING.md) · [Security](/.github/SECURITY.md)
- **CAR engine reference** (owned by [Byakugan](https://github.com/Get-Sybers/byakugan)): [CAR pipeline](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-Pipeline.md) · [extraction rules](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-Extraction-Rules.md) · [relations](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-Relations.md)
- **Deep reference:** [risk gate](/docs/riskgate.md) · [detection rules-as-code](/python/get_sybers_dxdfir/detect/rules/README.md)

> The pre-beta code lives on the frozen
> [`deprecated`](https://github.com/Get-Sybers/DX_DFIR/tree/deprecated) branch —
> unsupported, keeps every defect later releases fixed. Don't build on it.

## Licence

Apache-2.0 at the repository root (see [LICENSE](/LICENSE)) — the terms of the
[MITRE CAR](https://github.com/mitre-attack/car) model the pipeline follows,
redistributed via the `get-sybers/byakugan` image (see [THIRD_PARTY_NOTICES.md](/.github/THIRD_PARTY_NOTICES.md)).
The pipeline code is offered under the more permissive **MIT** licence as
self-contained components: the `get_sybers_dxdfir` package (`python/`) and the
`get_sybers.dxdfir` collection (`ansible/collections/`); each subtree carries its
own declared licence. The Go `dxdfir` front-end (`go/`) declares none of its own
and so carries the repository's Apache-2.0. Third-party tool obligations that fall
on *you* are in [THIRD_PARTY_NOTICES.md](/.github/THIRD_PARTY_NOTICES.md); Apache-2.0 §4
attribution is in [NOTICE](/NOTICE).

---

🚀 **Happy hunting!**
