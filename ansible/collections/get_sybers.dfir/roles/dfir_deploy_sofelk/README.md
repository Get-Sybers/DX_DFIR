# dfir_deploy_sofelk

Deploy the **from-source SOF-ELK stack**. The role asserts inputs, runs a preflight
(docker, the compose plugin, the `docker/sof-elk` Dockerfile + compose file, the host
ingest dir), then **builds the SOF-ELK image** from `docker/sof-elk/Dockerfile`
(which sources the upstream [philhagen/sof-elk](https://github.com/philhagen/sof-elk)
repo) and brings up the compose stack with `community.docker.docker_compose_v2`.

The stack is **Elasticsearch + the SOF-ELK image (Logstash with Filebeat co-located)
+ Kibana**, localhost-only — see `docker/sof-elk/README.md` for the build details.
Filebeat lives in the Logstash container (as on the SOF-ELK box), shipping the
`/logstash/<type>/` dirs to Logstash on `localhost:5044`.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dfir_deploy_sofelk_compose_dir` | `<repo>/docker/sof-elk` | Dir with the Dockerfile + `docker-compose.yml`. |
| `dfir_deploy_sofelk_ingest_dir` | `<repo>/data_store/sofelk-delivered` | Host dir mounted at `/logstash` — **match `dfir_ingest_sofelk_target_dir`**. |
| `dfir_deploy_sofelk_elastic_version` | `9.4.3` | Elastic stack version (SOF-ELK `main`'s pin). |
| `dfir_deploy_sofelk_sofelk_ref` | `main` | SOF-ELK git ref to build from. |
| `dfir_deploy_sofelk_build` | `true` | Build the image as part of the deploy. |
| `dfir_deploy_sofelk_env_file` | `<repo>/data_store/sofelk.env` | Runtime env file for compose interpolation. |

## Composition
`dfir_deploy_sofelk` mounts the ingest dir into the stack at `/logstash`;
`dfir_ingest_sofelk` delivers into that **same** host dir. Point both at the same
path and delivery lands where SOF-ELK's Filebeat watches.

## Idempotence
`docker_compose_v2` + the build cache are idempotent: a first deploy builds + starts
the stack (`changed=true`); a re-deploy with the image built and services up is
`changed=false`.

## Prerequisites
Docker + the compose plugin, and enough resources for Elasticsearch (~2–4 GB; the
host may need `sysctl -w vm.max_map_count=262144`). The image builds from the upstream
repo, so the first build needs network + is slow (multi-GB Elastic base images).

## Example
```bash
ansible-playbook playbooks/dfir-deploy-sofelk.yml
# then deliver:
ansible-playbook playbooks/dfir-ingest-sofelk.yml \
  -e dfir_ingest_sofelk_target_dir=<repo>/data_store/sofelk-delivered
```

## Testing
The **Molecule** scenario builds the image and brings up the stack, verifies the
`elasticsearch` + `sof-elk` services are running, and tears it down in `cleanup` — it
needs a resourced Docker host (Elasticsearch), so it is not run in the lightweight CI
environment. There is no automated Logstash config-compilation check; `docker/sof-elk`
bakes SOF-ELK's own parsing configs unmodified.
