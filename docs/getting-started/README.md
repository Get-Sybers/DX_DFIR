# What DX_DFIR is

**DX_DFIR turns a pile of raw evidence into normalised, searchable forensic data in a
real analytics stack — offline, from one command.**

You hand it packet captures, disk images, memory dumps, or Windows event logs. It:

1. **Processes** each kind of evidence with the right specialist tool, in a hardened
   container — Zeek for PCAPs, goevtx for Windows logs, Volatility 3 for memory,
   Plaso and the GoDFIR-toolz parsers for disk images.
2. **Normalises** all of it into one common shape — the
   [MITRE CAR](https://car.mitre.org/data_model/) data model — written out as plain
   per-object JSONL files you can read, diff, and grep.
3. **Feeds** a security-on [Elastic stack](../architecture/the-stack.md)
   (Elasticsearch + Kibana, everything bound to `127.0.0.1`) where detections run as
   ES|QL/EQL rules-as-code, with a STIX 2.1 exchange on top.

Instead of a pile of unrelated CSVs, you get normalised evidence in a proper analytics
backend — every line traceable to the artefact it came from.

## Who it's for

Incident responders and forensic analysts who want a repeatable, offline pipeline over
mixed evidence — and who'd rather run a handful of commands than wire five tools
together by hand. Everything runs on a single Debian/Ubuntu host; every published port
is localhost-only.

## What you actually touch

Under the hood `dxdfir` is a Go front-end over an Ansible collection and a Python
processing package driving Docker containers (see the
[architecture overview](../architecture/README.md)). As a user you only touch:

- the **`dxdfir`** command and its verbs,
- **one setup script**, and
- **docker compose** (or `dxdfir deploy stack`) for the analysis backend.

## The five-minute path

```bash
git clone --recursive https://github.com/Get-Sybers/DX_DFIR.git
cd DX_DFIR
./scripts/setup-environment.sh --yes      # host prep (log out/in once for the docker group)
dxdfir build-docker                        # build the hardened tool images
# drop evidence under data_store/raw/<type>/ …
dxdfir process evtx                        # process a lane
dxdfir build-car && dxdfir verify-car      # normalise into CAR + gate it
```

Then bring up the backend and explore in Kibana. The full, annotated walk-through is
**[First run](first-run.md)**.

## Next

- **[Install](install.md)** — prerequisites and what the setup script does.
- **[First run](first-run.md)** — the command journey from evidence to analysis.
- **[The interface](the-interface.md)** — the `dxdfir` terminal UI.
- **[Command reference](commands.md)** — every command in one table.
- **[Architecture](../architecture/README.md)** — how it works underneath.
