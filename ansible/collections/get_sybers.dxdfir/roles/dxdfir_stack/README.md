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
decision), then stack presence by label — the role's own
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
`root:root 0640` — an unprivileged deploy refuses to weaken them without
`dxdfir_stack_allow_world_readable_keys`). The compose-era `setup` service's
API bootstrap is idempotent `uri` tasks: the `kibana_system` password, the
least-privilege `logs_car_writer` role and the `byakugan_loader` user are
read first and changed only when they differ.

## Migration from the compose era

A host still running the retired `docker/elastic` compose stack migrates on
its next deploy: the old containers are replaced (the `byakugan_*` data
volumes carry over untouched), operator-set secrets are imported from a
surviving `.env` (placeholders never), and — on a root deploy — the CA is
imported from the old certs volume so enrolled agents keep their trust.

## Reusable entry points

- `tasks/docker_ensure.yml` — the engine gate (install/start/group on the
  opt-ins); `dxdfir-bootstrap.yml` drives it for `setup-environment.sh`.
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
| `dxdfir_stack_wait_retries` / `_wait_delay` | `60` / `5` | Bring-up readiness probes. |
| `dxdfir_stack_es_memlock` | `true` | Unlimited memlock on elasticsearch; false for runtimes that cannot grant it. |
| `dxdfir_stack_allow_world_readable_keys` | `false` | Explicit opt-in before an unprivileged deploy writes 0644 node keys. |

Identity, images, ports, paths and secrets resolve from `dxdfir_elastic_*`
(inventory) with self-contained fallbacks in `defaults/main.yml`.

## Usage

```bash
dxdfir deploy stack        # converge everything; re-runs are changed=0
dxdfir status stack        # read-only; "no analysis stack" is an answer
dxdfir destroy stack       # containers + network; volumes only with the flag
```
