# dxdfir_stack

Deploy and run the **Elastic analysis stack** — Elasticsearch, Kibana, Fleet
Server and Filebeat, security on, TLS, everything on `127.0.0.1` — as
ansible-native state: a docker network, named `byakugan_*` data volumes and
one container per service, brought up in bootstrap order with explicit waits
and verified. No compose, no scripts, no operator `.env`: the whole
definition lives in the **inventory layer**
(`playbooks/group_vars/all.yml`, the `dxdfir_elastic_*` variables), which
this role and every other consumer (`dxdfir_car_load`, the offline image
save) reference from one place.

One role, five actions (`dxdfir_stack_action`); **the playbook decides**,
the role groups, the tasks act.

What the stack *ingests and shows* is configuration as data in the repo-root
**Elastic config tree** (`elastic/`, the inventory's
`dxdfir_elastic_config_dir`): the Filebeat config filebeat mounts, the
ingest pipelines and `logs-dxdfir.*` templates `deploy_ingest.yml`
reconciles read-first against the live APIs, and the Kibana saved objects
it imports (gated on the tree's content hash, a deploy artifact in the
secret store), into the default space and into every space the tree
defines (`dashboards/<id>/space.json`, created or updated first). It also
rolls over every existing `logs-dxdfir.*` stream when a template changed
(and once when a stream's write index is not yet on the router pipeline), so
the change applies from the next document on. The role carries no pipeline
or dashboard bodies of its own — see `elastic/README.md`.

Documents already indexed keep what they were indexed with, Filebeat never
re-reads a file it has finished, and a stream's failure store (the rows
Elasticsearch rejected) is never replayed. **`dxdfir_stack_reingest: true`
on one deploy** replays the processed tree from scratch
(`tasks/deploy_reingest.yml`, right before the filebeat step): the filebeat
container is stopped and removed, the `logs-dxdfir.*` data streams are
deleted (their failure stores with them), the shipper's registry volume
(`dxdfir_stack_volumes['filebeatdata']`) is wiped and recreated, and the
filebeat step brings the shipper up again over the converged tree, reading
every file anew. `logs-car.*`, the Kibana objects and the evidence on disk
are not touched. Set it for one run (`playbooks/host_vars/<host>.yml`, or
`-e dxdfir_stack_reingest=true` on a direct `ansible-playbook` run of
`dxdfir-stack-deploy.yml`) and unset it after — it WIPES the indexed
evidence, which the full re-read then restores.

## Actions and their playbook decisions

| Action | Playbook | Decisions it sets |
|---|---|---|
| `deploy` | `dxdfir-stack-deploy.yml` | install a missing docker engine, start a stopped daemon, run the pull-capacity gate; absence is its starting point |
| `start` | `dxdfir-stack-start.yml` | start a stopped daemon, pull gate; an absent stack is **flagged** (deploy creates) |
| `stop` / `destroy` | `dxdfir-stack-stop.yml` / `-destroy.yml` | an absent stack is **flagged**; destroy takes `dxdfir_stack_remove_volumes` (WIPES ingested data) |
| `status` | `dxdfir-stack-status.yml` | an absent stack is **reported** and the host ends cleanly — the answer, not a failure |

Preflight reads the host before anything can fail on a requirement: the
docker engine's state first (`tasks/docker_ensure.yml` — an engine-less or
daemon-less host is answered by the same `dxdfir_stack_when_absent`
decision; its daemon probes escalate with the deploy, so a shell that does
not yet carry the operator's docker-group membership cannot make a running
daemon look stopped), then the operator's own access to the daemon
(`tasks/docker_access.yml`, which names the `newgrp docker` / re-login
remedy instead of letting the first docker module fail with a
PermissionError), then stack presence by label — the role's own
(`com.get-sybers.stack`) and the compose-era project label, so a stack
deployed before the compose retirement is still seen. `stop`, `destroy` and
`status` need no credentials at all.

## Secrets and TLS

Deploy generates what it needs into the gitignored per-host **secret store**
(`ansible/inventory/secrets/<host>/` — see its README): one file per secret
via file-backed `password` lookups (generated once, byte-stable, never
logged; overriding the `dxdfir_elastic_*` variable — `host_vars`,
`ansible-vault encrypt_string`, `-e` — wins and materialises nothing), the
`elastic.env` handoff for tools outside ansible, and the TLS tree
(`community.crypto` state modules; CA at `certs/ca/ca.crt`, node keys
`root:root 0640`). The service containers read the node keys as gid 0, so the
keys must be `root:root`; `dx deploy stack` (and `dx update stack`) holds that
posture automatically — when not already root it escalates only the TLS key
lifecycle and the docker-engine setup (`dxdfir_stack_become`) and prompts once
for the sudo password, running the rest of the play as the operator. A direct
playbook run that neither is root nor sets `dxdfir_stack_become` refuses to
weaken the keys to `0644` unless `dxdfir_stack_allow_world_readable_keys` opts
in. The compose-era `setup` service's
API bootstrap is idempotent `uri` tasks: the `kibana_system` password, the
least-privilege `logs_car_writer` role and the `byakugan_loader` user are
read first and changed only when they differ.

To rotate a generated secret, edit or remove its file under the secret
store and redeploy — rotating a password Elasticsearch already knows also
needs the matching API change or a wiped `esdata` volume. The generated
`elastic.env` is a handoff, never an input: edit the per-secret files or
override the variables, not that file. `dxdfir_elastic_version` in
`playbooks/group_vars/all.yml` is the ONE Elastic pin (every stack image
rides it);
`byakugan_*` volume names match the compose-era stack so existing
deployments keep their data.

## Migration from the compose era

A host still running the retired `docker/elastic` compose stack migrates on
its next deploy: the old containers are replaced (the `byakugan_*` data
volumes carry over untouched), operator-set secrets are imported from a
surviving `.env` (placeholders never), and — on a root deploy — the CA is
imported from the old certs volume so enrolled agents keep their trust.

## Reusable entry points

- `tasks/docker_ensure.yml` — the engine gate (install/start/group on the
  opt-ins); `dxdfir-bootstrap.yml` drives it for `setup-environment.sh`.
- `tasks/docker_access.yml` — the operator's own access to the daemon,
  never escalated: `docker version` as the connection user, failing with
  the remedy (`newgrp docker`, a new login, or root) when a docker-group
  membership is missing or newer than the shell. The preflight runs it right
  after `docker_ensure`; `dxdfir_images` runs it before its first pull.
- `tasks/ensure_running.yml` — start the required services' EXISTING
  containers and wait until running/healthy; never deploys as a side
  effect. Live-stack consumers (`dxdfir_car_load`) include it before
  depending on Elasticsearch.

## Role variables

The full, typed surface lives in `meta/argument_specs.yml`; the headline
knobs:

| Variable | Default | Description |
|---|---|---|
| `dxdfir_stack_action` | `status` | deploy \| destroy \| start \| stop \| status. |
| `dxdfir_stack_when_absent` | `continue` | What an absent stack means: continue / report / fail — the playbook's call. |
| `dxdfir_stack_install_docker` / `_start_docker` | `false` | Engine install (Debian/Ubuntu, Docker's apt repo) and daemon start opt-ins. |
| `dxdfir_stack_pull_gate` / `_min_free_gib` | `false` / `15` | Image-store capacity gate before pulls (reclaims once when short). |
| `dxdfir_stack_required_services` | `[elasticsearch, kibana]` | What ensure_running requires for "up". |
| `dxdfir_stack_remove_volumes` | `false` | destroy: also remove the data volumes (WIPES ingested data). |
| `dxdfir_stack_reingest` | `false` | deploy: replay the processed tree from scratch — WIPES the `logs-dxdfir.*` streams and the shipper's registry, then reads every file again. One-shot opt-in. |
| `dxdfir_stack_wait_retries` / `_wait_delay` | `60` / `5` | Bring-up readiness probes. |
| `dxdfir_stack_es_memlock` | `true` | Unlimited memlock on elasticsearch; false for runtimes that cannot grant it. |
| `dxdfir_stack_allow_world_readable_keys` | `false` | Explicit opt-in before an unprivileged deploy writes 0644 node keys. |
| `dxdfir_stack_become` | `false` | Escalate (sudo) only the privileged tasks (TLS key lifecycle + docker-engine setup) so node keys land `root:root 0640`. Set automatically by the converge verbs (`dx deploy stack` / `dx update stack`); no effect when already root. |

Identity, images, ports, paths and secrets resolve from `dxdfir_elastic_*`
(the inventory, the single source of truth) through direct references in
`defaults/main.yml` — there is no fallback, so a run without that inventory
layer fails rather than silently using role-local values. The role's own
constants and the security/TLS "magic lists" live in `vars/main.yml`.

## Usage

```bash
dxdfir deploy stack        # converge everything; re-runs are changed=0
dxdfir status stack        # read-only; "no analysis stack" is an answer
dxdfir destroy stack       # containers + network; volumes only with the flag
```
