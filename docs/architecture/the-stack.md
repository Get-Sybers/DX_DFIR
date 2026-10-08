# The analysis stack

The processing pipeline writes files; the analysis stack ingests and searches them. They
are a **separate data plane**: Filebeat tails the processed tree, and neither side drives
the other.

## What's in it

Deploy a security-on, localhost-only Elastic stack with `dx deploy stack` (the
`dxdfir_stack` role), converged from inventory data:

| Service | Role | Port (127.0.0.1) |
|---|---|---|
| **Elasticsearch** | Store + search, security on, TLS, Basic licence | `9200` |
| **Kibana** | UI, Discover, detections, Fleet | `5601` |
| **Fleet Server** | Manages the agent (an elastic-agent) | `8220` |
| **Filebeat** | Ships the processed evidence into data streams | n/a |

Official Elastic images, all pinned to one version (`dxdfir_elastic_version`),
each service one docker container on the `byakugan_default` network with named
`byakugan_*` data volumes.

## Bring it up

```bash
sudo sysctl -w vm.max_map_count=262144   # Elasticsearch requires this (persist in /etc/sysctl.conf)
dx deploy stack
```

Deploy converges the whole stack from the inventory: it installs Docker when
the host has none (Debian/Ubuntu), generates any secret not yet set, generates
the TLS material, then brings the services up in bootstrap order and verifies
them. Re-running it is a no-op on a healthy stack and a repair on a broken
one; data volumes and, on a root deploy, the CA and operator credentials carry
over untouched.

## Configuration and secrets

Everything lives in the **inventory layer**
([`ansible/collections/get_sybers.dxdfir/playbooks/group_vars/all.yml`](../../ansible/collections/get_sybers.dxdfir/playbooks/group_vars/all.yml),
the `dxdfir_elastic_*` variables): the version pin, ports, heap, the ingest
tree, network/volume names, and the secrets. Each secret is generated on
first deploy into the per-host **secret store**
(`ansible/inventory/secrets/<host>/`, gitignored, `0750 root:docker` on a root
deploy) and reused on every run; override any of them as an ansible variable
(`host_vars`, `ansible-vault encrypt_string`, or `-e`) and no file is ever
generated for it. Deploy also writes two artifacts there for tools outside
ansible:

- `elastic.env`: the generated credential handoff the [risk gate](../riskgate.md)
  reads (regenerated every deploy; edit the per-secret files or override the
  variables instead).
- `certs/`: the stack's TLS material (CA at `certs/ca/ca.crt`), generated
  host-side by `community.crypto` state modules and bind-mounted read-only
  into the containers. Host-side clients verify against that CA file; nothing
  reaches into a docker volume for it.

> **Host requirement:** Elasticsearch won't start without
> `vm.max_map_count=262144`. Deploy's failure message says so when it bites.

## Identities

| User | Role | Privileges | Used by |
|---|---|---|---|
| `elastic` | superuser | everything | bootstrap, Fleet, and any `dx byakugan load --setup` run (template + saved-object creation needs cluster privileges the loader below deliberately lacks) |
| `kibana_system` | built-in | Kibana -> Elasticsearch | Kibana |
| `byakugan_loader` | `logs_car_writer` (created by deploy) | `create_doc`, `create_index`, `read`, `view_index_metadata` on `logs-car.*` only, no cluster privileges | routine (non-`--setup`) `dx byakugan load` runs |

`byakugan_loader` is scoped so it can land evidence and read it back but never
alter, delete or re-template what is already indexed: least privilege
enforced at the credential layer, not by convention. Deploy reconciles all
three against the live Elasticsearch API: read first, change only what
differs.

## Fleet enrolment

`fleet-server` bootstraps itself: with `KIBANA_FLEET_SETUP=1` it runs Fleet
setup through Kibana (as `elastic`), obtains a service token unless
`dxdfir_elastic_fleet_service_token` is set, and enrols into
`fleet-server-policy`. The policy, the Fleet Server host
(`https://fleet-server:8220`) and the default Elasticsearch output are
preconfigured in the role's `kibana.yml`. Its state persists in the
`byakugan_fleetdata` volume, so restarts keep the enrolment.

To enrol another agent, create an enrolment token in Kibana (Fleet ->
Enrollment tokens) and run an `elastic-agent` container on the
`byakugan_default` network with the stack's certs tree mounted at `/certs`:

```bash
docker run --rm --network byakugan_default \
  -v "$(pwd)/ansible/inventory/secrets/localhost/certs:/certs:ro" \
  -e FLEET_ENROLL=1 -e FLEET_URL=https://fleet-server:8220 -e FLEET_CA=/certs/ca/ca.crt \
  -e FLEET_ENROLLMENT_TOKEN=<token> \
  docker.elastic.co/elastic-agent/elastic-agent:9.4.3
```

## How evidence gets in

Filebeat tails `/ingest/*/**/*.{json,jsonl}` (the processed tree), dissects the first
path segment as the evidence type, and ships each record into a data stream named
**`logs-dxdfir.<type>-<namespace>`**, e.g. `logs-dxdfir.zeek-default`. Cluster-side,
each stream's default pipeline (`logs-dxdfir-router`) hands the record to its
evidence type's ingest pipeline: evidence time → `@timestamp` (ingest time stays in
`event.ingested`; evidence is never re-stamped), `event.module`/`event.dataset`,
grok over composite strings, and the cheap ECS copies. Kibana at
<http://127.0.0.1:5601> is where you explore: Discover, detections, and ES|QL over
the same streams.

## The config tree (`elastic/`)

What the stack ingests and shows is **configuration as data** at the repo root —
[`elastic/`](../../elastic/README.md): the Filebeat config, the ingest pipelines
(one JSON file per pipeline; grok lives here), the `logs-dxdfir.*`
component/index templates, and the Kibana saved objects (data views, searches,
dashboards). Deploy reconciles the tree read-first on every
`dx deploy stack` / `dx update stack` — edit a file, re-converge, done; an
unchanged tree is `changed=0`. The path is the inventory's
`dxdfir_elastic_config_dir`.

## The dashboards

The config tree's `dashboards/` is what Kibana shows. Beside the default
space's evidence overview, deploy creates the **`malcolm` Kibana space** and
imports its 36 dashboards, derived from [cisagov/Malcolm](https://github.com/cisagov/Malcolm)
and converted to the Zeek (`logs-dxdfir.zeek-*`) and Suricata
(`logs-dxdfir.detections-*`) documents the pipelines produce: Overview,
Connections, Files, Executables, Zeek Weird and Suricata Alerts; one
dashboard per Zeek protocol log (DNS, HTTP, SSL, SMB, Kerberos, …); Modbus
and DNP3. The space is at <http://127.0.0.1:5601/s/malcolm/app/dashboards>;
[`elastic/dashboards/malcolm/`](../../elastic/dashboards/malcolm/README.md)
lists [every dashboard](../../elastic/dashboards/malcolm/DASHBOARDS.md) and
the field conversion. Like the rest of the tree, the space is re-imported
in place whenever its files change.

## Two index families

| Family | Holds | From |
|---|---|---|
| `logs-dxdfir.*` | Raw processed evidence, per type | Filebeat over `data_store/processed/` |
| `logs-car.*` | The materialised [CAR](car-pipeline.md), projected to ECS | The CAR→ECS projection (the [risk gate](../riskgate.md)) |

## Detections and STIX

Detections are **rules-as-code** for Elastic's Detection Engine. One YAML file per rule,
[shipped with the Byakugan engine and baked into its image at `/rules`](https://github.com/Get-Sybers/Byakugan/blob/main/rules/README.md)
(the image build gates them),
each carrying an ES|QL or EQL query plus the contract for the evidence line it tags
(shape, fields, `car_join`, ATT&CK technique/tactic ids). Queries request
`METADATA _id,_index,_version` so the engine emits one alert per matched document.
Examples: `win-defender-tamper`, `mem-malfind-injection`, `zeek-dns-oversized-query`,
`sig-yara-match`.

The **STIX** side turns detection hits into a STIX 2.1 bundle, engine-side
(`byakugan stix-export` through the `dxdfir_exchange` role, a confined
container run like every lane):

```bash
dx byakugan export-stix [HITS_DIR] [--case CASE-17] [--push --network NET]
```

Each rule becomes an indicator whose pattern *is* the rule query; `indicates`
relationships point at MITRE's own ATT&CK object ids (none minted locally); each row is a
sighting; hosts are identities; network/file entities become connected observed-data
objects. OpenCTI is the wire. Deep reference:
[the engine's STIX-Exchange.md](https://github.com/Get-Sybers/Byakugan/blob/main/docs/STIX-Exchange.md),
[the baked rules-as-code](https://github.com/Get-Sybers/Byakugan/blob/main/rules/README.md),
[risk gate](../riskgate.md), [signature rules](../Signature-Rules.md).

## Lifecycle

```bash
dx status stack                      # what's running
dx stop stack                        # stop, keep containers
dx restart stack                     # stop then start, no data removed
dx update stack                      # re-converge onto the current inventory/images
dx purge stack --volumes -y          # remove everything, INCLUDING ingested data
```
