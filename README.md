# DX_DFIR Pipeline

[![release](https://img.shields.io/github/v/release/Get-Sybers/DX_DFIR?include_prereleases&label=release)](https://github.com/Get-Sybers/DX_DFIR/releases)
[![checks](https://github.com/Get-Sybers/DX_DFIR/actions/workflows/checks.yml/badge.svg)](https://github.com/Get-Sybers/DX_DFIR/actions/workflows/checks.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](/LICENSE)

Point DX_DFIR at a disk image or a PCAP; it processes the evidence with
**[Plaso](https://github.com/log2timeline/plaso)**, **[Zeek](https://zeek.org/)**,
**goevtx**,
**[anamnesis](https://github.com/Get-Sybers/Anamnesis)** (memory) and the
**[GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz)**, normalises it into the
**[MITRE CAR](https://car.mitre.org/data_model/)** data model — materialised, one
`car_<object>.jsonl` per object — and feeds an **Elastic-native analysis backend**
(Elasticsearch + Kibana with security on, Fleet, Filebeat; Basic
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
./scripts/setup-environment.sh      # Docker + dxdfir CLI — usable in this shell as it is
```

Build the hardened tool images — first run, and again after every pull (images
whose pinned sources moved are rebuilt and the stale ones removed):

```bash
dxdfir build-docker
```

**Work a case** — evidence arrives, becomes a registered collection, gets
processed into CAR:

```bash
mkdir -p data_store/raw/sort/ACME-24            # the case's dropzone folder
cp /mnt/evidence/* data_store/raw/sort/ACME-24/
dxdfir register ACME-24             # promote the dropzone: lane-sort by content, SHA-1 hash, registry row
dxdfir select ACME-24               # the active collection subsequent commands target
dxdfir list collections             # the active one is starred, per-lane counts shown
dxdfir process ACME-24              # every lane with staged evidence — or one: dxdfir process ACME-24 memory
dxdfir build-car                    # normalise every source into per-source CAR stores (car_<object>.jsonl)
dxdfir verify-car                   # the CAR correctness gate over what was written
dxdfir build-timeline data_store/processed/byakugan   # one property-rich, time-ordered timeline JSONL
```

Evidence that arrives mid-case goes back through the dropzone: copy it into
`data_store/raw/sort/ACME-24/`, then `dxdfir sort ACME-24`.

**Quick look at loose evidence** — no collection, one artefact, one lane:

```bash
dxdfir unselect                     # with no active collection, lanes read data_store/raw/<type>/ directly
cp memdump.mem data_store/raw/memory/
dxdfir process memory               # zeek | evtx | memory | plaso | godfir-toolz | signatures
```

Bring up the backend:

```bash
sudo sysctl -w vm.max_map_count=262144         # Elasticsearch needs this (persist it in /etc/sysctl.conf)
dxdfir deploy stack                             # Elasticsearch + Kibana + Fleet + Filebeat, localhost-only
```

Deploy converges the whole stack from the inventory
(`ansible/collections/.../playbooks/group_vars/all.yml`): it installs Docker
when the host has none (Debian/Ubuntu), generates any secret not yet set into
`ansible/inventory/secrets/<host>/` (gitignored; override any as an ansible
variable — `ansible-vault encrypt_string` works), generates the TLS material,
and brings the services up in order, verified. Re-runs converge; a compose-era
deployment is migrated in place with its data volumes untouched.

Kibana is at `http://127.0.0.1:5601`. Filebeat tails the processed evidence tree
(`<type>/**/*.json[l]`, pointed at by `ELASTIC_INGEST_DIR`) into
`logs-dxdfir.<type>-*` data streams — see [the stack](/docs/architecture/the-stack.md).
The CAR→ECS projection into `logs-car.*` and ES|QL `LOOKUP JOIN` flagging against
the `car-detections` lookup index are proven by the Phase-0
[risk gate](/docs/riskgate.md); the detection rules are data
[shipped with the Byakugan engine and baked into its image at `/rules`](https://github.com/Get-Sybers/byakugan/blob/main/rules/README.md)
(build- and suite-gated engine-side), and `dxdfir stix export` turns their
hits into STIX 2.1 sightings via the engine's own exchange. `dxdfir --help`
lists every command (`man dxdfir` for the manual).

## How it runs
<a name="how-it-runs"></a>

A three-layer stack — the **`dxdfir` CLI** → the **`get_sybers.dxdfir` Ansible
collection** (one role per source, one action per task) → the
**[GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) tool containers** —
writing the processed tree the CAR lane builds from and Filebeat ships. Each
source runs as `dxdfir process <source>` (driving the matching
`dxdfir_<source>` role); the role builds every `docker run` purely from the
tool's `contract.yml` (its environment variables and mounts) and the container
discovers, batches and skips its own inputs. There is no host python layer:
the engine logic lives in the Byakugan image, the detection rules-as-code ride
that image at `/rules` (owned and build-gated by GoDFIR-toolz), and the image
supply-chain gate is ansible (the GoDFIR-toolz build galaxy's
`verify`/`audit` entries).

## What it produces

| Source | Command | Lands in (`data_store/processed/`) |
|:---|:---|:---|
| Disk images / VM exports (Plaso) | `process plaso` | `log2timeline/jsonl/<source>/timeline.jsonl` (Plaso `json_line`) + `log2timeline/storage/` (`.plaso`) |
| PCAP (Zeek) | `process zeek` | `zeek/<capture>/` (`conn.json` + every other Zeek log) |
| Windows event logs + Sysmon (goevtx) | `process evtx` | `windows_logs/<log>/goevtx.jsonl` |
| Memory ([anamnesis](https://github.com/Get-Sybers/Anamnesis)) | `process memory` | `memory/<image>/` (per-plugin JSONL + `car.db`) |
| GoDFIR-toolz artefacts — SRUM, registry, … | `process godfir-toolz` | `godfir-toolz/<subtool>/<item>/` |
| YARA / Suricata / Hayabusa / disk scan | `process signatures` | `detections/<sub-tool>/<item>/` (JSONL) |

The **CAR layer is materialised**: the [Byakugan](https://github.com/Get-Sybers/byakugan)
engine normalises each processed source into finished
CAR events — one `car_<object>.jsonl` per object (13 objects) plus
`car_relationships.jsonl` — under `processed/byakugan/<source>/`. The engine runs
entirely inside the hardened `get-sybers/byakugan` image, cloned + built at the
`BYAKUGAN_REF` commit pinned in its Dockerfile by `dxdfir build-docker` — never a host checkout.
Extraction happens once, in the engine, so that JSON is the contract every sink
reads and cannot drift from what the engine emits.

**Validated** by the CI **smoke test** (the real EVTX → goevtx → CAR path over
pinned Sysmon fixtures, asserting the extracted field values) and by
**`dxdfir verify-car`** (each CAR object populated, values sane — IPs, ports, SIDs —
`car_action` checked against the engine's model vocabulary, every row traceable to
a source). The other lanes (Plaso, Zeek, Memory, GoDFIR-toolz) are run by hand on
the author's corpus. The Elastic-side assumptions (evidence-time detection runs,
`LOOKUP JOIN`) have their own [risk gate](/docs/riskgate.md).

## Before you run anything

- **The backend holds evidence.** The Elastic stack runs with security **on**
  — authentication, RBAC, TLS on the Elasticsearch API — its credentials live
  in the gitignored per-host secret store (`ansible/inventory/secrets/`,
  generated by `dxdfir deploy stack`; vault-overridable) and every port binds
  `127.0.0.1`. See [SECURITY.md](/.github/SECURITY.md).
- **This handles real evidence.** `data_store/` is gitignored deny-by-default, so
  unknown/extensionless formats are covered — a safety net, not a guarantee. Check
  `git status` before you commit.

## Docs

**Start at the [documentation hub](/docs/README.md)** — it routes you by what you want:

- **New here?** [What DX_DFIR is](/docs/getting-started/README.md) · [Install](/docs/getting-started/install.md) · [First run](/docs/getting-started/first-run.md) · [The interface](/docs/getting-started/the-interface.md) · [Command reference](/docs/getting-started/commands.md)
- **How it works:** [Architecture overview](/docs/architecture/README.md) · [Processing lanes](/docs/architecture/processing-lanes.md) · [CAR pipeline](/docs/architecture/car-pipeline.md) · [The stack](/docs/architecture/the-stack.md)
- **Contributing:** [Standards](/docs/reference/README.md) · [Repository map](/docs/reference/repository-map.md) · [Contributing](/.github/CONTRIBUTING.md) · [Security](/.github/SECURITY.md)
- **CAR engine reference** (owned by [Byakugan](https://github.com/Get-Sybers/byakugan)): [CAR pipeline](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-Pipeline.md) · [extraction rules](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-Extraction-Rules.md) · [relations](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-Relations.md)
- **Deep reference:** [risk gate](/docs/riskgate.md) · [detection rules-as-code](https://github.com/Get-Sybers/byakugan/blob/main/rules/README.md)

> The pre-beta code lives on the frozen
> [`deprecated`](https://github.com/Get-Sybers/DX_DFIR/tree/deprecated) branch —
> unsupported, keeps every defect later releases fixed. Don't build on it.

## Licence

Apache-2.0 at the repository root (see [LICENSE](/LICENSE)) — the terms of the
[MITRE CAR](https://github.com/mitre-attack/car) model the pipeline follows,
redistributed via the `get-sybers/byakugan` image (see [THIRD_PARTY_NOTICES.md](/.github/THIRD_PARTY_NOTICES.md)).
The pipeline code is offered under the more permissive **MIT** licence as a
self-contained component: the `get_sybers.dxdfir` collection
(`ansible/collections/`), which carries its own declared licence. The Go `dxdfir` front-end (`go/`) declares none of its own
and so carries the repository's Apache-2.0. Third-party tool obligations that fall
on *you* are in [THIRD_PARTY_NOTICES.md](/.github/THIRD_PARTY_NOTICES.md); Apache-2.0 §4
attribution is in [NOTICE](/NOTICE).

---

🚀 **Happy hunting!**
