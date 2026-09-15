# The analysis stack

The processing pipeline writes files; the analysis stack ingests and searches them. They
are a **separate data plane** — Filebeat tails the processed tree, and neither side drives
the other. The default stack is Elastic-native; the legacy **SOF-ELK** path (an older,
security-less ELK delivery target) is retiring.

## What's in it

`stacks/elastic/` is a security-on, localhost-only Elastic stack:

| Service | Role | Port (127.0.0.1) |
|---|---|---|
| **Elasticsearch** | Store + search, security on, TLS, Basic licence | `9200` |
| **Kibana** | UI, Discover, detections, Fleet | `5601` |
| **Fleet Server** | Manages the agent (an elastic-agent) | `8220` |
| **Filebeat** | Ships the processed evidence into data streams | — |

Bring it up with `dxdfir stack deploy` or directly:

```bash
sudo sysctl -w vm.max_map_count=262144       # Elasticsearch requires this (persist in /etc/sysctl.conf)
cd stacks/elastic && cp .env.example .env    # then fill in the placeholders
docker compose up -d
```

> **Host + credentials:** Elasticsearch won't start without `vm.max_map_count=262144`. In
> `.env`, passwords need ≥ 6 chars and each encryption key must be `openssl rand -hex 32`
> (the `.env.example` comments say which is which). The file holds credentials, binds
> nothing off `127.0.0.1`, and is git-ignored — **never commit it.** Full details:
> [stacks/elastic/README.md](../../stacks/elastic/README.md).

## How evidence gets in

Filebeat tails `/ingest/*/**/*.{json,jsonl}` (the processed tree), dissects the first
path segment as the evidence type, and ships each record into a data stream named
**`logs-dxdfir.<type>-<namespace>`** — e.g. `logs-dxdfir.evtx-default`. Kibana at
<http://127.0.0.1:5601> is where you explore; the [Kibana tab](../getting-started/the-interface.md#kibana)
in `dxdfir` runs ES|QL against the same streams without leaving the terminal.

## Two index families

| Family | Holds | From |
|---|---|---|
| `logs-dxdfir.*` | Raw processed evidence, per type | Filebeat over `data_store/processed/` |
| `logs-car.*` | The materialised [CAR](car-pipeline.md), projected to ECS | The CAR→ECS projection (the [risk gate](../riskgate.md)) |

## Detections and STIX

Detections are **rules-as-code** for Elastic's Detection Engine. One YAML file per rule
under [`python/get_sybers_dxdfir/detect/rules/`](../../python/get_sybers_dxdfir/detect/rules/README.md),
each carrying an ES|QL or EQL query plus the contract for the evidence line it tags
(shape, fields, `car_join`, ATT&CK technique/tactic ids). Queries request
`METADATA _id,_index,_version` so the engine emits one alert per matched document.
Examples: `win-defender-tamper`, `vol-malfind-injection`, `zeek-dns-oversized-query`,
`sig-yara-match`.

The **STIX** side turns detection hits into a STIX 2.1 bundle:

```bash
dxdfir stix export --hits detections.jsonl --out bundle.json [--push]
```

Each rule becomes an indicator whose pattern *is* the rule query; `indicates`
relationships point at MITRE's own ATT&CK object ids (none minted locally); each row is a
sighting; hosts are identities; network/file entities become connected observed-data
objects. OpenCTI is the wire. Deep reference:
[stix/README.md](../../python/get_sybers_dxdfir/stix/README.md),
[detect/rules/README.md](../../python/get_sybers_dxdfir/detect/rules/README.md),
[risk gate](../riskgate.md), [signature rules](../Signature-Rules.md).

## Lifecycle

```bash
dxdfir stack status                  # what's running
dxdfir stack stop                    # stop, keep containers
dxdfir stack destroy --volumes -y    # remove everything, INCLUDING ingested data
```
