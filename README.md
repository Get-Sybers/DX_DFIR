# DX_DFIR Pipeline

[![release](https://img.shields.io/github/v/release/Get-Sybers/DX_DFIR?include_prereleases&label=release)](https://github.com/Get-Sybers/DX_DFIR/releases)
[![checks](https://github.com/Get-Sybers/DX_DFIR/actions/workflows/checks.yml/badge.svg)](https://github.com/Get-Sybers/DX_DFIR/actions/workflows/checks.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](/LICENSE)

Point DX_DFIR at a disk image or a PCAP; it processes the evidence with
**[Plaso](https://github.com/log2timeline/plaso)**, **[Zeek](https://zeek.org/)**,
**[EvtxECmd](https://github.com/EricZimmerman/evtx)**,
**[Volatility 3](https://github.com/volatilityfoundation/volatility3)** and the
**[Zimmerman EZ-Tools](https://ericzimmerman.github.io/)**, normalises it into the
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
# drop evidence under data_store/raw/<type>/ (see data_store/README.md), then per source:
dxdfir process evtx                 # zeek | evtx | volatility | plaso | zimmerman | signatures
dxdfir build-car                    # normalise every source into per-source CAR stores (car_<object>.jsonl)
dxdfir verify-car                   # the CAR correctness gate over what was written
dxdfir car-timeline data_store/processed/car   # one property-rich, time-ordered timeline JSONL
```

Bring up the backend:

```bash
cd docker/elastic && cp .env.example .env      # replace EVERY placeholder, then:
docker compose up -d                            # Elasticsearch + Kibana + Fleet + Filebeat, localhost-only
```

Kibana is at `http://127.0.0.1:5601`. Filebeat ships the delivered evidence tree
(`<type>/**/*.json[l]`, the layout `dxdfir-ingest-sofelk.yml` delivers) into
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
Python package** — writing the processed tree the CAR lane builds from
(`--pipeline elastic`, the default) or the retiring SOF-ELK delivery tree
(`--pipeline sofelk`). Each source runs as `dxdfir process <source>` (driving the
matching `dxdfir_<source>` role); processors are also runnable as
`python -m get_sybers_dxdfir.<source>`.

## What it produces

| Source | Command | Lands in (`data_store/processed/`) |
|:---|:---|:---|
| Disk images / VM exports (Plaso) | `process plaso` | `log2timeline/jsonl/` (Plaso `json_line`, one file per host) |
| PCAP (Zeek) | `process zeek` | `zeek/<capture>/` (`conn.json` + every other Zeek log) |
| Windows event logs + Sysmon (EvtxECmd) | `process evtx` | `windows_logs/<host>/` (EvtxECmd JSON) |
| Memory (Volatility 3 / [PIIAT-Mem](https://github.com/Get-Sybers/PIIAT-Mem)) | `process volatility` | `volatility/<image>/` (per-plugin JSONL) |
| EZ-Tools artefacts — SRUM, registry, … | `process zimmerman` | `zimmerman/` |
| YARA / Suricata / Hayabusa | `process signatures` | `signatures/<lane>/` (JSONL) |

The **CAR layer is materialised**: the [PIIAT-MitreCar](https://github.com/Get-Sybers/PIIAT-MitreCar)
engine normalises each processed source into finished CAR events — one
`car_<object>.jsonl` per object (13 objects) plus `car_relationships.jsonl` —
under `processed/car/<source>/`. Extraction happens once, in the engine, so that
JSON is the contract every sink reads and cannot drift from what the engine emits.

**Validated** by the CI **smoke test** (the real EVTX → EvtxECmd → CAR path over
pinned Sysmon fixtures, asserting the extracted field values) and by
**`dxdfir verify-car`** (each CAR object populated, values sane — IPs, ports, SIDs —
`car_action` checked against the engine's model vocabulary, every row traceable to
a source). The other lanes (Plaso, Zeek, Volatility, Zimmerman) are run by hand on
the author's corpus. The Elastic-side assumptions (evidence-time detection runs,
`LOOKUP JOIN`) have their own [risk gate](/docs/riskgate.md).

## Before you run anything

- **The backend holds evidence.** The Elastic stack (`docker/elastic`) runs with
  security **on** — authentication, RBAC, TLS on the Elasticsearch API — but its
  credentials live in `docker/elastic/.env` (gitignored; never commit it) and
  every port binds `127.0.0.1`. The retiring SOF-ELK stack (`docker/sof-elk`) has
  no security at all. See [SECURITY.md](/SECURITY.md).
- **This handles real evidence.** `data_store/` is gitignored deny-by-default, so
  unknown/extensionless formats are covered — a safety net, not a guarantee. Check
  `git status` before you commit.

## Docs

- [Get started](/docs/Get-Started.md) · [Directory structure](/docs/Dir-Structure.md)
- [The Elastic-native stack](/docker/elastic/README.md) · [Phase-0 risk gate](/docs/riskgate.md) · [detection rules-as-code](/python/get_sybers_dxdfir/detect/rules/README.md)
- [CAR pipeline](/docs/CAR-Pipeline.md) · [extraction rules](/docs/CAR-Extraction-Rules.md) · [relations](/docs/CAR-Relations.md)
- [Task board](/project-progress.md) · [Contributing](/CONTRIBUTING.md) · [Security](/SECURITY.md)

> The pre-beta code lives on the frozen
> [`deprecated`](https://github.com/Get-Sybers/DX_DFIR/tree/deprecated) branch —
> unsupported, keeps every defect later releases fixed. Don't build on it.

## Licence

Apache-2.0 at the repository root (see [LICENSE](/LICENSE)) — matched to the
vendored `car_data_model.json` from [MITRE CAR](https://github.com/mitre-attack/car).
The pipeline code is offered under the more permissive **MIT** licence as
self-contained components: the `get_sybers_dxdfir` package (`python/`) and the
`get_sybers.dxdfir` collection (`ansible/collections/`); each subtree carries its
own declared licence. The Go `dxdfir` front-end (`go/`) declares none of its own
and so carries the repository's Apache-2.0. Third-party tool obligations that fall
on *you* are in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md); Apache-2.0 §4
attribution is in [NOTICE](/NOTICE).

---

🚀 **Happy hunting!**
