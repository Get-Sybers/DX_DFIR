# Ansible standards

The `get_sybers.dxdfir` collection (`ansible/collections/get_sybers.dxdfir/`, namespace
`get_sybers`) is where the pipeline's orchestration lives. One motto governs it:

> **The role groups; the playbook decides. Idempotence lives in the Python processor, not
> a task's `when:`.**

## A task does one action, with no logic

A task runs one thing — usually invoking the `get_sybers_dxdfir` Python package as a
single action. The *logic* — which lanes run, the `--pipeline elastic|sofelk` choice —
lives in the **playbook**, which is a thin, single-purpose wrapper (`hosts: localhost`,
`gather_facts: false`). This keeps every task legible and independently reasoned about.

## One role per source or action

`dxdfir_zeek`, `dxdfir_evtx`, `dxdfir_volatility`, `dxdfir_plaso`, `dxdfir_zimmerman`,
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

The inventory is a static `localhost,` (local connection). What *varies* is discovered:
lanes find the items to process rather than hard-coding hosts. The Go front-end passes
`ANSIBLE_ROLES_PATH` so roles resolve from the in-tree collection without being
Galaxy-installed, and role defaults derive `repo_root` so `data_store/` paths resolve.

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

## The one external seam

The `dxdfir_byakugan` role drives the external [Byakugan engine](https://github.com/Get-Sybers/byakugan),
pinned by `byakugan.ref` — not vendored. See the [CAR pipeline](../architecture/car-pipeline.md).
