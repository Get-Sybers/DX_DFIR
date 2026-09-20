# Byakugan Elastic stack (security ON)

Byakugan's **own Elastic-native stack** — the foundation for the Elastic-native
DFIR detection engine: Elasticsearch + Kibana with security **on**, Fleet, and
Filebeat as the shipper. Everything stays inside the Elastic ecosystem on a
**Basic licence**.

| Service | Image | Role |
|---|---|---|
| `setup` | `elasticsearch` (one-shot) | generates the CA + node certs, sets the `kibana_system` password, creates the `logs_car_writer` role + `byakugan_loader` user, exits |
| `elasticsearch` | `elasticsearch` | single node, security on, TLS on HTTP + transport, Basic licence |
| `kibana` | `kibana` | UI + Fleet; talks to Elasticsearch over TLS as `kibana_system` |
| `fleet-server` | `elastic-agent` | Fleet Server, self-enrols into the preconfigured `fleet-server-policy` |
| `filebeat` | `filebeat` | the Elastic-native shipper — delivered evidence -> `logs-dxdfir.<type>-<ns>` data streams |

Pinned to Elastic **9.4.3** — override with `ELASTIC_VERSION` (compose
variable-with-default, same convention as the other `docker/*` builds). All
published ports bind to **127.0.0.1**; data lives in named volumes (`certs`,
`esdata`, `kibanadata`, `fleetdata`, `filebeatdata`).

## Bring it up

```bash
cd docker/elastic
cp .env.example .env            # then replace EVERY placeholder (see the file)
sudo sysctl -w vm.max_map_count=262144
docker compose up -d
docker compose ps               # setup exits 0; the rest go (healthy)
```

- Elasticsearch -> https://127.0.0.1:9200 (`elastic` / `ELASTIC_PASSWORD`, CA in the `certs` volume)
- Kibana -> http://127.0.0.1:5601 (log in as `elastic`)
- Fleet Server -> https://127.0.0.1:8220

`config/setup.sh` refuses to run while `ELASTIC_PASSWORD` / `KIBANA_SYSTEM_PASSWORD` /
`BYAKUGAN_LOADER_PASSWORD` still hold the `.env.example` placeholders. `.env` and
`ingest/` are gitignored — **never commit real secrets**. To fetch the CA for
host-side clients:
`docker compose cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt .`

## Security posture

| | `docker/elastic` |
|---|---|
| licence | Basic (`xpack.license.self_generated.type: basic`) |
| `xpack.security` | **on** — authentication + RBAC |
| Elasticsearch TLS | none | HTTP + transport, own CA (`config/setup.sh`) |
| Kibana -> ES | anonymous, plain HTTP | `kibana_system` over TLS with CA verification |
| shipper | Logstash (+ Filebeat -> Logstash) | Filebeat -> Elasticsearch directly |
| Fleet | n/a | Fleet Server with TLS, preconfigured policy + output |
| ports | 127.0.0.1 | 127.0.0.1 |

Credentials are only ever read from the environment (`.env`): `ELASTIC_PASSWORD`,
`KIBANA_SYSTEM_PASSWORD`, `BYAKUGAN_LOADER_PASSWORD`, the three Kibana encryption
keys, and an optional `FLEET_SERVER_SERVICE_TOKEN`. Kibana itself is served over
plain HTTP on the loopback interface; the Elasticsearch API, transport and Fleet
Server are TLS.

### Identities

| User | Role | Privileges | Used by |
|---|---|---|---|
| `elastic` | superuser | everything | bootstrap (`setup`), Fleet, and any `dxdfir load-car --setup` run (index/component template + Kibana saved-object creation needs cluster privileges the loader below deliberately lacks) |
| `kibana_system` | built-in | Kibana -> Elasticsearch | Kibana |
| `byakugan_loader` | `logs_car_writer` (created by `config/setup.sh`) | `create_doc`, `create_index`, `read`, `view_index_metadata` on `logs-car.*` only — no cluster privileges | routine (non-`--setup`) `dxdfir load-car` runs |

`byakugan_loader` is scoped so it can land evidence and read it back (the
`_search` ids-query it verifies loads with needs only `read`) but never alter,
delete or re-template what is already indexed — least privilege enforced at
the credential layer, not by convention. Its password never reaches a `docker
run` argv in cleartext (the `dxdfir_lane` Ansible role writes it to a 0600
`--env-file` instead of `-e`); see `ansible/collections/get_sybers.dxdfir/roles/dxdfir_car_load/`.

## Fleet enrolment

`fleet-server` bootstraps itself: with `KIBANA_FLEET_SETUP=1` it runs Fleet setup
through Kibana (as `elastic`), obtains a service token unless
`FLEET_SERVER_SERVICE_TOKEN` is set, and enrols into `fleet-server-policy` — the
policy, the Fleet Server host (`https://fleet-server:8220`) and the default
Elasticsearch output (`https://elasticsearch:9200`, CA `/certs/ca/ca.crt` on the
agent side) are preconfigured in `config/kibana.yml`. Its state is persisted in
`fleetdata`, so restarts keep the enrolment.

To enrol another agent, create an enrolment token in Kibana (Fleet -> Enrollment
tokens, or `POST /api/fleet/enrollment_api_keys`) and run an `elastic-agent`
container on the `byakugan_default` network with the `certs` volume mounted at
`/certs`:

```bash
docker run --rm --network byakugan_default -v byakugan_certs:/certs:ro \
  -e FLEET_ENROLL=1 -e FLEET_URL=https://fleet-server:8220 -e FLEET_CA=/certs/ca/ca.crt \
  -e FLEET_ENROLLMENT_TOKEN=<token> \
  docker.elastic.co/elastic-agent/elastic-agent:9.4.3
```

Agents outside the compose network need a Fleet Server host they can resolve —
add one under Fleet -> Settings. The `fleet_server` package is bundled with
Kibana; other integrations are fetched from the Elastic Package Registry
(`xpack.fleet.registryUrl` for a self-hosted mirror when air-gapped).

## Shipping evidence

`ELASTIC_INGEST_DIR` is mounted read-only at `/ingest`. Filebeat
(`config/filebeat.yml`) tails `<type>/**/*.json` and `*.jsonl` — the tree
the processors write under `data_store/processed/` (`zeek/`, `plaso/`, ...;
keep type dirs lowercase) — stamps `labels.type` from the directory, and writes each line into
the data stream `logs-dxdfir.<type>-<DFIR_NAMESPACE>` (one namespace per case works
well). Data streams are created by Elasticsearch's built-in `logs-*-*` template;
native -> ECS normalisation is Elastic-native too (ingest pipelines on those
streams) and lands in a later phase, together with the CAR-driven detection
rules that tag these evidence lines.

`processed/byakugan/` (the materialised CAR) and `processed/byakugan-load/`
(a load run's own bundles/manifest/report) are excluded from this input
(`prospector.scanner.exclude_files`) even though they sit under the same
ingest tree: the CAR already lands ECS-projected in `logs-car.*` via
`dxdfir load-car`, and raw `car_<object>.jsonl` double-ingesting here too
would duplicate it into `logs-dxdfir.byakugan-*` and compete with the ECS
projection instead of complementing it.

## Notes

- Elasticsearch needs `vm.max_map_count=262144` on the host.
- Filebeat writes as `elastic` for now; a least-privilege writer role is a follow-up.
  `byakugan_loader` / `logs_car_writer` ([Identities](#identities) above) is that
  pattern's first instance — scoped to `create_doc`/`create_index`/`read`/
  `view_index_metadata` on `logs-car.*` only — so Filebeat's own follow-up now has
  a working counter-example to copy rather than a design to invent.
- An **Ansible deploy role is intentionally deferred** to a follow-up; when it is
  added it must conform to the bits-n-bobs Ansible standard (like the existing
  `get_sybers.dxdfir` roles). Until then this compose file is the deployment.
