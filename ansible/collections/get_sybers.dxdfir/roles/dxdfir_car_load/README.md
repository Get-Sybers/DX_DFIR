# dxdfir_car_load

Bulk-load a materialised CAR tree into this repo's Elastic stack
(`logs-car.<object>-<ns>` ×13 plus the `rel`, `inferred` and `content`
streams) via the byakugan image's `load` sub-tool. One role, one action for
now (`dxdfir_car_load_action: load`); the playbook picks it — the same shape
as `dxdfir_byakugan`, driven from the same contract (a different declared
sub-tool). Variables: `meta/argument_specs.yml`.

## How a load runs

1. **The stack first.** The services this pushes to must be running, so the
   role runs `dxdfir_stack`'s `ensure_running` gate (via `include_role`, not
   a bare `include_tasks`, so that role's own defaults — container names,
   the required elasticsearch+kibana set — resolve correctly from outside
   it), then attaches the run to the stack's docker network, resolving
   `elasticsearch`/`kibana` by their service aliases.
2. **Credentials by reference.** The inventory layer's `dxdfir_elastic_*`
   definitions — the same variables `dxdfir_stack` deployed with — are
   referenced directly: no file to parse, no second secret store to drift.
   Empty fallbacks make a bare role run fail the non-empty assert instead of
   loading with empty credentials. Credentials never reach the docker run
   argv: they go through `dxdfir_lane`'s `secret_env` (a 0600 `--env-file`).
3. **The lane skeleton drives the container.** `/input` is the CAR tree
   `byakugan build` wrote (ro), `/output` this run's bundles + manifest +
   report (rw) — a **sibling** of `byakugan/`, not inside it, so each gets
   its own chain in `data_store/.gitignore` and Filebeat's raw-evidence
   exclusion can name each one — and `/certs` the stack's host-side TLS tree
   (ro). `BYAKUGAN_LOAD_ES_CA_FILE` defaults to `/certs/ca/ca.crt` in the
   contract and `_INPUT_DIR`/`_OUT_DIR` to `/input`/`/output`, all matching
   the mounts, so none is restated. Push mode always (`BYAKUGAN_LOAD_ES_URL`
   set): this role's whole job is delivering the CAR into the live stack,
   never bundle-only.

## Which identity authenticates

`dxdfir_car_load_setup` decides (default **on**, first-run-friendly — a
fresh stack has no `logs-car.*` templates yet, so the first load must set
them up):

- **setup run** → the `elastic` superuser: the template PUTs (and, when the
  separately-opted-in Kibana saved-objects import is on — the contract
  requires setup for it) need cluster/Kibana privileges the loader identity
  deliberately does not have.
- **steady-state run** (`--no-setup`, templates already exist) →
  `byakugan_loader`, whose `logs_car_writer` role is
  create_doc/create_index/read/view_index_metadata on `logs-car.*` **only**
  — evidence immutability at the credential layer, and the counter-example
  to "filebeat writes as elastic" (docs/architecture/the-stack.md).

`dxdfir_car_load_force` re-renders bundles and re-pushes even when the
manifest/report already show the run complete (`BYAKUGAN_LOAD_FORCE`). The
namespace convention matches the raw streams: one namespace per case
(`dxdfir_elastic_namespace` for `logs-dxdfir.*`).
