# DX_DFIR documentation

DX_DFIR is an offline, container-based digital-forensics pipeline. You point it at
raw evidence — packet captures, disk images, memory dumps, Windows event logs — and
drive the whole thing through one command, `dxdfir`. It processes each kind of
evidence with the right specialist tool, normalises everything into the
[MITRE CAR](https://car.mitre.org/data_model/) data model, and feeds a security-on
Elastic stack where detections run as rules-as-code.

New here? Start with **[What DX_DFIR is](getting-started/README.md)**.

## Pick your path

| I want to… | Go to |
|---|---|
| Understand what this is and whether it's for me | [Getting started → overview](getting-started/README.md) |
| Install it on a fresh host | [Getting started → install](getting-started/install.md) |
| Run my first case, command by command | [Getting started → first run](getting-started/first-run.md) |
| Drive it from the terminal UI | [Getting started → the interface](getting-started/the-interface.md) |
| Look up a specific command | [Getting started → command reference](getting-started/commands.md) |
| Understand how it works under the hood | [Architecture → overview](architecture/README.md) |
| See the processing lanes | [Architecture → processing lanes](architecture/processing-lanes.md) |
| Contribute code that fits the house style | [Reference → standards](reference/README.md) |

## The three doc sets

- **[Getting started](getting-started/README.md)** — for a first-time visitor. What the
  tool offers, how to install it, and the exact commands to run a case from evidence to
  analysis. Written from the operator's side of the screen.
- **[Architecture](architecture/README.md)** — for someone who wants to understand the
  mechanics: how setup provisions a host, the processing lanes, the CAR pipeline, the
  Elastic stack, and the logical boundaries between the layers.
- **[Reference](reference/README.md)** — for a contributor: the Go and Ansible standards,
  the build/test harness, and a map of the Get-Sybers repositories this one is built on.

## Deep reference (existing material)

These pre-date this hub and go deeper than the pages above; they're linked from the
relevant sections:

- [CAR pipeline](CAR-Pipeline.md) · [extraction rules](CAR-Extraction-Rules.md) ·
  [cross-source linkage](CAR-CrossSource.md) · [relationships](CAR-Relations.md)
- [CAR provenance ledger](car-provenance/README.md) — one field-map per CAR object
- [Signature rules](Signature-Rules.md) · [risk gate](riskgate.md)
- [Directory structure](Dir-Structure.md) · [tool containers](Containers.md) ·
  [scripts overview](scripts/Scripts-Overview.md)
- [Research notes](research/README.md) — the linkage / behaviour-timeline programme

---

> **Pre-release software.** Interfaces may still change. When a page and the CLI
> disagree, trust `dxdfir --help` and open an issue. Release notes:
> [CHANGELOG.md](../CHANGELOG.md).
