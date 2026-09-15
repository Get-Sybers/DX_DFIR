# SOF-ELK container (from source)

> **Retiring.** Byakugan's own Elastic-native stack — security ON, Fleet, Filebeat
> instead of Logstash — lives in [`stacks/elastic/`](../../stacks/elastic/README.md) and
> replaces this one. This directory stays only until `dxdfir_deploy_sofelk` (which
> builds from it) is retired with it.

SOF-ELK® ([philhagen/sof-elk](https://github.com/philhagen/sof-elk)) ships as a VM,
so there is no canonical public image. This builds one **from the upstream repo** so
the `dxdfir_deploy_sofelk` role has a real stack to run.

- **`Dockerfile`** — clones SOF-ELK to `/usr/local/sof-elk` (the path its configs
  reference for grok patterns, ruby helpers and lookup dictionaries), bakes its
  parsing configs into an official **Logstash** image, and co-locates **Filebeat**
  (as on the SOF-ELK box — Filebeat ships the `/logstash/<type>/` dirs to Logstash on
  `localhost:5044`). An entrypoint starts Filebeat, then Logstash.
- **`docker-compose.yml`** — **Elasticsearch** + the SOF-ELK image + **Kibana**,
  localhost-only, no security (dead-box posture; `stacks/elastic` — which is
  replacing this stack — runs with security on).

Pinned to Elastic **9.4.3** (SOF-ELK `main`'s pin) — override with `ELASTIC_VERSION`.

## Build + run
```bash
cd docker/sof-elk
ELASTIC_VERSION=9.4.3 SOFELK_INGEST_DIR=/abs/path/to/delivered docker compose up -d --build
```
- Elasticsearch → http://127.0.0.1:9200 · Kibana → http://127.0.0.1:5601
- Deliver evidence with `dxdfir_ingest_sofelk` into `SOFELK_INGEST_DIR`; Filebeat picks
  up `<type>/**/*.json[l]` and Logstash parses it into Elasticsearch.

## Ingest layout
SOF-ELK routes by the sub-directory a file lands in — `/logstash/zeek/`,
`/logstash/plaso/`, `/logstash/nfarch/`, … (see `lib/filebeat_inputs/` in the repo).
Deliver each processor's `sofelk` output into the matching `<type>/` dir.

## Notes
- The non-default Logstash plugins are installed from **SOF-ELK's own declared list**
  (`ansible/roles/logstash/defaults/main.yaml` → `logstash_plugins`) read out of the
  clone — so a rebuild tracks upstream instead of drifting from a hardcoded copy.
- **GeoLite2 databases are seeded** into `/usr/local/share/GeoIP/` (where SOF-ELK's
  geoip filters expect them) from the copies the `logstash-filter-geoip` plugin
  already bundles, so the image is config-valid out of the box; refresh them with a
  MaxMind licence via SOF-ELK's `geoip_bootstrap.sh`.
- The image only patches ONE upstream line — the Elasticsearch output's host, which
  SOF-ELK hardcodes to `localhost` — making it `${ES_HOSTS:localhost:9200}` so the
  containerised Logstash reaches the `elasticsearch` service. Everything else is
  upstream, unmodified.
- Elasticsearch may need `vm.max_map_count=262144` on the host
  (`sysctl -w vm.max_map_count=262144`).
