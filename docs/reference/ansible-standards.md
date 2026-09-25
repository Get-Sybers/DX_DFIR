# Ansible standards

The `get_sybers.dxdfir` collection (`ansible/collections/get_sybers.dxdfir/`, namespace
`get_sybers`) is where the pipeline's orchestration lives. One motto governs it:

> **The role groups; the playbook decides. Idempotence lives in the Python processor, not
> a task's `when:`.**

## A task does one action, with no logic

A task runs one thing — usually invoking the `get_sybers_dxdfir` Python package as a
single action. The *logic* — which lanes run —
lives in the **playbook**, which is a thin, single-purpose wrapper (`hosts: localhost`,
`gather_facts: false`). This keeps every task legible and independently reasoned about.

## One role per source or action

`dxdfir_zeek`, `dxdfir_evtx`, `dxdfir_memory`, `dxdfir_plaso`, `dxdfir_godfir_toolz`,
`dxdfir_signatures` (the [lanes](../architecture/processing-lanes.md)), plus `dxdfir_byakugan`,
`dxdfir_images`, `dxdfir_stack`, `dxdfir_cleanup`, and the ingest/deploy roles. Every
lane role carries only its own per-lane piece — asserting inputs and building the
processor argv — and delegates the run to the shared **`dxdfir_lane`** skeleton
(`preflight → process → verify`). That's the collection-port template: to add a lane,
copy a role and change the argv.

Each role ships typed `meta/argument_specs.yml`, `defaults/main.yml`, and a
`molecule/default/` scenario with a real fixture. Molecule dirs are `build_ignore`d from
the Galaxy artifact.

## Idempotence in the processor, not the task

Ansible roles carry no idempotence in `when:`. A source whose output already exists is
skipped **in the Python processor**; the role's task uses `changed_when` derived from the
processor's `{processed, skipped, failed}` summary, then gates on that summary plus an
on-disk `find`. This is why the Go front-end can reconstruct progress by watching output
files land — see [the interface](../getting-started/the-interface.md).

## The walk is dynamic; the inventory is static

The default inventory is the workstation itself (`ansible/inventory/hosts.yml`,
local connection, wired in `ansible.cfg`; the Go front-end passes the equivalent
`-i localhost,`). What *varies* is discovered: lanes find the items to process
rather than hard-coding hosts, and remote/fleet targets join the inventory and
are selected per run with `-e dxdfir_hosts=<pattern>`. The Go front-end passes
`ANSIBLE_ROLES_PATH` so roles resolve from the in-tree collection without being
Galaxy-installed, and role defaults derive `repo_root` so `data_store/` paths resolve.

**Shared identities live in the inventory layer, not per-role.** Values more than
one role must agree on — the Elastic backend's version pin, network and volume
names, ports, paths and secrets — are defined once as `dxdfir_elastic_*` in
playbook-adjacent `group_vars`
(`ansible/collections/get_sybers.dxdfir/playbooks/group_vars/all.yml`, which load
under any inventory source) and each role's variables reference them
(`dxdfir_stack_elastic_password`, `dxdfir_car_load_elastic_password` →
`dxdfir_elastic_password`). Role defaults keep a self-contained fallback so a
role still runs in isolation; inventory vars override defaults, `-e` overrides
both.

**Secrets are inventory data, generated once, never committed.** Each stack
secret is a file-backed `ansible.builtin.password` lookup into the per-host
secret store (`ansible/inventory/secrets/<host>/`, gitignored): the first
deploy generates it, every later run reads the same value back, and an
operator override (`host_vars`, `ansible-vault encrypt_string`, `-e`) simply
wins — an overridden variable never materialises a file. Every task that could
carry a value is `no_log`. Tools outside ansible read the deploy's generated
`elastic.env` handoff in the same store rather than parsing anything of their
own.

## Pinned dependencies

`requirements.yml` is the single source of pinned collection deps, every entry an **exact
`X.Y.Z` pin** — never `:latest`, never a bare branch: `community.docker==3.10.3`,
`ansible.posix==2.1.0` (the latter enables the per-task timing callback). `galaxy.yml`
bounds each dependency below its next major so a Galaxy install can't pull a breaking
change. A check asserts every `galaxy.yml` dependency has a matching exact pin and that
`setup-environment.sh` installs `requirements.yml`.

## Robustness

Preflight gate tasks **skip or short-circuit** a lane when its inputs or tools are absent,
rather than failing the whole run — so a missing evidence type is a note, not a crash. A
`block`/`rescue` around the processor surfaces its JSON summary + stderr as one
diagnostic. `ansible-lint --profile production` runs over the collection as a
[CI gate](build-and-test.md).

Two reusable, **idempotent self-healing** container preconditions back this up, so every
play that runs a container ensures its precondition at the point — in a serial `process
all`, once per lane, right before that lane creates its container. **`dxdfir_images`
`ensure_built`** (`tasks_from: ensure_built`, fed `dxdfir_images_required`) builds any tool
image not yet built on the host (a no-op when already built); the shared `dxdfir_lane`
preflight and the `dxdfir_byakugan` preflight both call it, ahead of the run-time
supply-chain guard that enforces the hardened contract on what is built. **`dxdfir_stack`
`ensure_running`** (`dxdfir_stack_required_services`, default `elasticsearch` + `kibana`)
brings the compose services up (`state: present`, a no-op when already running) and verifies
they came up; stack `deploy` and `start` both run through it. Both are idempotent, so a
fresh or half-provisioned host self-heals in place instead of failing the run.

## The one external seam

The `dxdfir_byakugan` role drives the external [Byakugan engine](https://github.com/Get-Sybers/byakugan),
pinned by its Dockerfile's `BYAKUGAN_REF` — not vendored. See the [CAR pipeline](../architecture/car-pipeline.md).
