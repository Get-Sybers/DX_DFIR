# dxdfir_lane

The shared "run a hardened DFIR tool lane" skeleton. A per-tool lane role
(`dxdfir_zeek`, `dxdfir_plaso`, `dxdfir_evtx`, `dxdfir_memory`,
`dxdfir_signatures`, `dxdfir_godfir_toolz`, `dxdfir_byakugan`) asserts its
own input rules, declares its runs — one GoDFIR-toolz tool image each,
driven purely by that tool's `contract.yml` — and delegates here. The role
groups; the playbook decides. Idempotence lives in each tool container (an
item with valid output is skipped unless `<TOOL>_FORCE`), never in a task's
`when:`. Variables are specified in `meta/argument_specs.yml`.

## The flow

`build → preflight → process`, as one guarded unit:

1. **build** (`tasks/build.yml` + `tasks/argv.yml`) turns every declared run
   into a confined `docker run` argv. Facts persist for the whole play, so
   the built list is reset first — a serial "process all" runs several lanes
   in one play.
2. **preflight** (`tasks/preflight.yml`) checks the docker daemon, ensures
   this lane's `get-sybers/*` images are **built** (via
   `dxdfir_images tasks_from: ensure_built` — idempotent and self-healing: a
   fresh host provisions itself at the head of the lane instead of failing a
   run hours in), then runs the **supply-chain guard** (via
   `dxdfir_images tasks_from: verify`, the build galaxy's gate): every image
   about to run must be a known hardened manifest image still carrying the
   contract on this host. A substituted or un-hardened image stops the lane
   before any evidence is touched; non-namespace refs are out of scope.
3. **process** (`tasks/process.yml`) runs each container, judges every run
   against the contract's uniform exit table, collects the one-line JSON
   summaries, and gates on output.

The block's `always:` removes every secret env-file on **every** exit path —
whether process ran, the container failed, or the lane never got that far (a
preflight failure, a later run's build refusal). A password never outlives
the lane invocation that wrote it.

## The run spec (`dxdfir_lane_runs`)

Each entry is ONE confined `docker run` of one GoDFIR-toolz tool image,
built from that tool's `contract.yml`:

| key | meaning |
| --- | ------- |
| `name` | label for task output |
| `contract` | absolute path of the tool's `contract.yml` — the source of truth |
| `image` | optional image ref overriding `contract.image` (e.g. a digest pin) |
| `subtool` | the dispatcher argument of a multi-tool image (plaso, signatures, byakugan); empty for a self-orchestrating tool |
| `env` | `{NAME: value}` overrides of the contract's env, rendered as `-e NAME=VALUE`; every NAME must be declared in the contract, bool-typed vars are normalised to 1/0, empty strings are omitted (the image default applies) |
| `secret_env` | overrides exactly like `env` (same contract rules, same bool normalisation) for values that must never appear on the argv (a password): written to a 0600 temp file passed as `--env-file`, created by argv.yml with `no_log`, removed by the lane's `always:` block |
| `mounts` | `[{host, path, mode}]` host binds, or `[{source, volume: true, path, mode}]` a docker **named volume** (e.g. the elastic stack's compose `certs` volume). Every mount names exactly one of `host` or `source` — never both, never neither. `path` must be a container path the contract declares, or one a declared env override names (how a contract asks for a mounted filter file/ruleset it does not list as a mount); anything else is refused. Every contract mount with `required: true` must be bound |
| `network` | a docker network NAME (e.g. `byakugan_default`, to resolve compose services by name); `--network NAME` replaces `--network none`, honoured only when the contract declares `network: optional`. There is no bridge/boolean form — a boolean-shaped value is never a network name (a CLI extra-var arrives as a string, so `"true"` etc. are rejected too), and every other run gets `--network none` regardless. (The one boolean user was the memory lane's symbol fetch; its symbols are baked in now and that lane is always offline.) |
| `entrypoint` / `args` | the argv pass-through the contracts reserve for debugging; no lane in the pipeline uses it |

## What argv.yml enforces and builds

Everything is validated against the contract before anything runs, read-only
(the daemon is untouched, no directory is created) except the secret
env-file write:

- every env/secret_env override is a declared contract variable (the
  contract doesn't care HOW a value reaches it);
- every bound container path is contract-declared or env-named; every
  required mount is bound; a multi-tool image is given one of its declared
  sub-tools (unless the debug pass-through is used deliberately);
- read-only host mounts are the evidence: they must exist (docker would
  otherwise create an empty root-owned directory in their place) and their
  owning group is granted via `--group-add`, so the image's non-root uid can
  read a locked-down tree (`data_store` is root:docker 750 on a hardened
  host) without running as root. A `volume: true` mount has no host path to
  stat and is excluded from both checks;
- the argv layers: the shared confinement (`dxdfir_lane_confinement`), a
  tmpfs for `/tmp` and every unbound optional read-write contract mount (the
  tool's scratch under the read-only rootfs), the network decision, group
  grants, the binds, `-e` pairs (secrets via `--env-file`), the image and
  its sub-tool. The jinja there is filter-only expressions on purpose — a
  jinja block would come back as a string, not a list.

## How process judges a lane

- The containers run without self-judgement (`failed_when: false`); the
  verdict is taken over the registered list explicitly, so no condition ever
  reads a single `.rc`/`.stdout` off a looped register.
- Exit table (docs/framework/03 §3.5): 0 success and 1 nothing-to-do pass;
  3 partial passes the table and is judged by the summary line; 2 config
  error — or anything outside the table, docker itself failing — fails the
  lane naming the run.
- One JSON summary line per run; the lane "changed" when any run processed
  something (an idempotent rerun skips every item, processed 0).
- `dxdfir_lane_require_no_failures` (default true) asserts every summary
  reported `failed == 0`; lanes whose tools legitimately exit 3 with
  per-item failures (plaso per-image, memory per-plugin without symbols,
  godfir-toolz per-tool, the detection sub-tools) set it false and gate
  purely on output.
- Default output gate: something landed in `dxdfir_lane_verify_dir`
  matching `dxdfir_lane_verify_glob`, unless every run genuinely had nothing
  to do (`inputs == 0` across the lane). An empty glob skips the on-disk
  verify and the default gate. `dxdfir_lane_gate_extra` replaces the
  default gate with the lane's own task file (a trusted literal assert on
  `dxdfir_lane_summaries` + `dxdfir_lane_verify`) — kept as a task, not an
  expression string, because ansible-core rejects evaluating
  variable-sourced templates in `that:`.
- On any failure the rescue surfaces each run's own summary line + stderr
  as one diagnostic instead of a raw traceback, then fails the play.
- Every read-write mount is pre-created world-writable: the tools run as
  the image's non-root uid (2000) and write into their bind-mounted output.
- In check mode the containers are skipped, so the gates on their output
  are too.
