# DX_DFIR Pipeline

[![release](https://github.com/Get-Sybers/DX_DFIR/-/badges/release.svg)](https://github.com/Get-Sybers/DX_DFIR/-/releases)
[![pipeline](https://github.com/Get-Sybers/DX_DFIR/badges/main/pipeline.svg)](https://github.com/Get-Sybers/DX_DFIR/-/pipelines)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](/LICENSE)

> **Pre-release software** — the version and maturity are whatever the badge above
> says (it reads the latest [Release](https://github.com/Get-Sybers/DX_DFIR/-/releases)
> live). Runs on the author's corpus; interfaces may still change. Release notes:
> [CHANGELOG.md](CHANGELOG.md).

**DX_DFIR turns a pile of raw evidence into normalised, searchable forensic leads. Hand it packet captures, disk images, memory dumps, or Windows event logs.**

1. **Processes** each kind of evidence with the right specialist tool, in a hardened
   container: Zeek for PCAPs, goevtx for Windows logs, anamnesis (MemProcFS) for memory,
   Plaso and the GoDFIR-toolz parsers for disk images.
2. **Normalises** all of it into one common shape, the
   [MITRE CAR](https://car.mitre.org/data_model/) data model, written out as plain
   per-object JSONL files you can read, diff, and grep.
3. **Feeds** a security-on [Elastic stack](docs/architecture/the-stack.md)
   (Elasticsearch + Kibana, everything bound to `127.0.0.1`) where detections run as

## Who it's for

Incident responders and forensic analysts who want a repeatable, offline pipeline over
mixed evidence, and who'd rather run a handful of commands than wire five tools
together by hand. Everything runs on a single Debian/Ubuntu host; every published port
is localhost-only.

## Index

| I want to… | Go to |
|---|---|
| Understand what this is, and run my first case | [Get started](docs/Get-Started.md) |
| Install it on a fresh host | [Setup script](docs/scripts/Setup_Environment.md) |
| Look up a specific command | [Command reference](docs/dx-cli.md) |
| Understand how it works under the hood | [Architecture overview](docs/architecture/README.md) |
| See the processing lanes | [Processing lanes](docs/architecture/processing-lanes.md) |
| Contribute code that fits the house style | [Go standards](docs/reference/go-standards.md) · [Ansible standards](docs/reference/ansible-standards.md) |

## Quick start
### Setup
Clone Repo
  ```bash
  git clone https://github.com/Get-Sybers/DX_DFIR.git
  cd DX_DFIR
  ```

Run setup script
  ```bash
  ./scripts/setup-environment.sh
  ```

Build the docker images from [goDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz)

  ```bash
  dx build images
  ```

### Process
**Work a case** — evidence arrives, becomes a registered collection, gets
processed into CAR:

1. Place the evidence to be processed in `data_store/raw/sort/<case-name>/`
2. Sort the evidence into the correct lane for processing.
  ```bash
  dx sort <case-name>
  ```
3. Process evidence
  3.1. process case with all processing lanes. *not specifying a lane will default to all*
  ```bash
  dx process <case-name>
  ```
  3.2. process a case with a specific lane
  ```bash
  dx process <case-name> [zeek|gowindowlicker|godaemonhunter|anamnesis|log2timeline]
  ```

### Analyse
  1. Deploy the elastic stack
    - the password can either be specicified or read from `ansible/inventory/secrets/<host>/`

  ```bash
  dx deploy stack                                 # Elasticsearch + Kibana + Fleet + Filebeat, localhost-only
  ```

  2. Open Kibana is at `http://127.0.0.1:5601`

## Docs

The full documentation set:

- **Getting started:** [Get started](docs/Get-Started.md) · [Command reference](docs/dx-cli.md) · [Directory structure](docs/Dir-Structure.md)
- **How it works:** [Architecture overview](docs/architecture/README.md) · [Setup flow](docs/architecture/setup-flow.md) · [Processing lanes](docs/architecture/processing-lanes.md) · [CAR pipeline](docs/architecture/car-pipeline.md) · [The stack](docs/architecture/the-stack.md) · [Logical architecture](docs/architecture/dfir-suite-logical-architecture.md)
- **Pipeline internals:** [Tool containers](docs/Containers.md) · [Signature rules](docs/Signature-Rules.md) · [Risk gate](docs/riskgate.md) · [Scripts overview](docs/scripts/Scripts-Overview.md) · [Setup-environment script](docs/scripts/Setup_Environment.md)
- **Elastic stack:** [Config tree](elastic/README.md) · [Spaces](elastic/spaces.md) · [malcolm space](elastic/dashboards/malcolm/README.md) · [malcolm dashboards](elastic/dashboards/malcolm/DASHBOARDS.md) · Filebeat fields: [Zeek](elastic/filebeat/Zeek.md) · [Suricata](elastic/filebeat/Suricata.md) · [Winlog](elastic/filebeat/Winlog.md)
- **Contributing:** [Go standards](docs/reference/go-standards.md) · [Ansible standards](docs/reference/ansible-standards.md) · [Build & test](docs/reference/build-and-test.md) · [Contributing](.github/CONTRIBUTING.md) · [Security](.github/SECURITY.md)
- **Research:** [Research notes](docs/research/README.md) · [Evidence spine](docs/research/evidence-spine.md)
- **CAR engine reference** (owned by [Byakugan](https://github.com/Get-Sybers/Byakugan)): [CAR pipeline](https://github.com/Get-Sybers/Byakugan/blob/main/docs/CAR-Pipeline.md) · [extraction rules](https://github.com/Get-Sybers/Byakugan/blob/main/docs/CAR-Extraction-Rules.md) · [relations](https://github.com/Get-Sybers/Byakugan/blob/main/docs/CAR-Relations.md) · [detection rules-as-code](https://github.com/Get-Sybers/Byakugan/blob/main/rules/README.md)


## Licence

Apache-2.0 at the repository root (see [LICENSE](LICENSE)) — the terms of the
[MITRE CAR](https://github.com/mitre-attack/car) model the pipeline follows,
redistributed via the `get-sybers/byakugan` image (see [THIRD_PARTY_NOTICES.md](.github/THIRD_PARTY_NOTICES.md)).
The pipeline code is offered under the more permissive **MIT** licence as a
self-contained component: the `get_sybers.dxdfir` collection
(`ansible/collections/`), which carries its own declared licence. The Go `dx` front-end (`go/`) declares none of its own
and so carries the repository's Apache-2.0. Third-party tool obligations that fall
on *you* are in [THIRD_PARTY_NOTICES.md](.github/THIRD_PARTY_NOTICES.md); Apache-2.0 §4
attribution is in [NOTICE](NOTICE).

---

🚀 **Happy hunting!**