# get_sybers.dxdfir

The DX_DFIR forensic processing pipeline as an Ansible Galaxy collection. The heavy
logic lives in the `get_sybers_dxdfir` Python package (`python/`); each Ansible **task
is one action** that invokes it, and the **playbook** holds every decision — which
roles run and the `--pipeline elastic|sofelk` selection.

Conforms to the Get-Sybers Ansible standards (naming/structuring + one-action-per-task
+ robustness) — see `Get-Sybers/Ludus-Ansible` `docs/standards/ansible/`.

## Roles
One role per evidence source; each invokes its `get_sybers_dxdfir.<source>` processor
as a single action.

| Role | Source | Processor |
|---|---|---|
| `dxdfir_zeek` | PCAPs → Zeek JSON | `get_sybers_dxdfir.zeek` |
| `dxdfir_volatility` | Memory images → Volatility 3 per-plugin JSONL | `get_sybers_dxdfir.volatility` |
| `dxdfir_evtx` | Windows Event Logs (`.evtx`) → EvtxECmd JSON | `get_sybers_dxdfir.evtx` |
| `dxdfir_plaso` | Disk images / VM exports → Plaso JSONL | `get_sybers_dxdfir.plaso` |
| `dxdfir_signatures` | YARA / Suricata / Hayabusa detections | `get_sybers_dxdfir.signatures` |

Deploy + deliver roles: **`dxdfir_ingest_sofelk`** (deliver processed output into a
watch dir — the `<type>/…` tree the Elastic-native stack's Filebeat and the retiring
SOF-ELK both read), **`dxdfir_deploy_sofelk`** (builds the from-source SOF-ELK stack —
`docker/sof-elk/`, retiring). The Elastic-native analysis backend (`docker/elastic/`)
is brought up with docker compose; an Ansible deploy role for it is a follow-up
(see its README).

**`dxdfir_images`** builds every tool container the processors run — hardened,
from in-repo Dockerfiles, with ansible as the container's only execution path
(Splunk-docker posture: pinned `ansible-playbook` ENTRYPOINT + embedded
allow-listed run role, uid 0 renamed `ansible` and locked, no sudo/su, no
package managers, tool runs as uid 2000) — and verifies the contract per build.
No third-party tool image is pulled at runtime.
A start-time **inventory guard** (`get_sybers_dxdfir.images`) refuses to process against anything but a known hardened `dxdfir/*` image — each processor preflight asserts the exact image it will run is hardened, and `dxdfir verify-images` audits the whole namespace for missing, un-hardened, or unexpected images (something added that shouldn't be). Run `playbooks/dxdfir-build-images.yml` once per host (and after `docker/`
changes); see [the role README](roles/dxdfir_images/README.md).

Detection is not a role: the detections are Elastic rules-as-code
(`python/get_sybers_dxdfir/detect/rules/`, ES|QL/EQL loaded and validated by
`get_sybers_dxdfir.detect.rules_loader`) run by Elastic's Detection Engine on the
`docker/elastic` stack. The CAR lane (`dxdfir build-car` / `dxdfir verify-car`)
prepares and gates the materialised CAR they read.

## Usage
The **`dxdfir` front-end** (the Go binary built from `go/`) drives these roles for
you; the `get_sybers_dxdfir` Python package provides the processors the roles invoke:
```bash
dxdfir process zeek --pipeline elastic  # = the dxdfir_zeek role, preflight → process → verify
dxdfir process signatures               # all lanes
```
Or run a playbook directly; each source has one under `playbooks/`, which selects
the role and passes the pipeline:
```bash
ansible-playbook playbooks/dxdfir-process-zeek.yml -e dxdfir_zeek_pipeline=elastic
ansible-playbook playbooks/dxdfir-process-volatility.yml -e dxdfir_volatility_pipeline=elastic
ansible-playbook playbooks/dxdfir-process-evtx.yml -e dxdfir_evtx_pipeline=elastic
ansible-playbook playbooks/dxdfir-process-plaso.yml -e dxdfir_plaso_pipeline=elastic
ansible-playbook playbooks/dxdfir-process-signatures.yml -e dxdfir_signatures_pipeline=elastic
```

## Testing (molecule)

Every role ships a molecule scenario (`roles/<role>/molecule/default/`,
delegated driver — the role runs its own tool containers). Run them without
installing molecule on the host via the containerised harness:

```bash
./tests/run-molecule.sh                    # default set (see script header)
./tests/run-molecule.sh dxdfir_zeek          # one role
```

Scenarios that need operator-supplied fixtures (a sample `.evtx` + EvtxECmd
release, a disk image, a memory image) read them from `MOLECULE_SAMPLE_*` /
`MOLECULE_EVTXECMD_DIR` env vars and are skipped with a note when absent —
see the script header for the full list.

## Standards alignment

The collection tracks the common Ansible best-practice set; where a practice
does not fit a localhost forensic pipeline, the deviation is deliberate and
recorded here rather than half-implemented.

| Practice | Where it lives here |
|---|---|
| Structure, naming, docs | One role per evidence source; `main -> preflight -> process` task files; house task-name prefix `<role>-<stage> \| description`; per-role `README.md` + `meta/argument_specs.yml`; collection `CHANGELOG.md`; playbooks under `playbooks/`. |
| Variables, no hardcoding | Everything flows through `defaults/main.yml` with the `dxdfir_<role>_` prefix; inputs validated with `assert` at play start; the elastic\|sofelk decision is a resolved variable (`dxdfir_<role>_out_dir`), not duplicated task files. |
| Idempotency | State lives in the Python processors (skip-if-done); `changed_when` reads each processor's JSON summary; exit codes are re-run-safe; molecule enforces `changed=0` on the second run. Check mode is supported: command tasks skip and their gates skip with them. |
| Roles for reusability | Single-responsibility roles invoked by thin playbooks; shared behaviour lives in the Python package, not copy-pasted tasks; versioned as a collection (`galaxy.yml`, pinned deps in `requirements.yml`). |
| Error handling & validation | Preflight asserts prerequisites before anything runs; the process/verify/gate unit runs in a `block` whose `rescue` surfaces the processor's JSON summary and stderr as one diagnostic before failing. |
| Dynamic inventory | **Deviation, verified inapplicable:** the pipeline is localhost-only by design (evidence never leaves the analysis host); tool containers are resources the roles manage, not inventory hosts, so there is nothing to discover. Becomes applicable only if remote acquisition/collector hosts ever become targets. |
| Testing in CI/CD | `ansible-lint` (production profile, config in `.ansible-lint`) + the repo harness run on every push/PR; molecule scenarios run the roles for real (`tests/run-molecule.sh`), idempotence included. |
| Cross-platform conditionals | **Principle implemented, mechanics inapplicable:** the practice's point — one adaptable unit instead of near-identical copies — is exactly the shared `process.yml` + resolved `dxdfir_<role>_out_dir`, applied to the elastic\|sofelk axis. OS-family `when` ladders have no surface: targets are tool containers on a Linux analysis host, single-platform by design. |
| Vault / secrets | **No secrets exist in the collection by design** — verified: no credentials anywhere (SOF-ELK included), every published port binds `127.0.0.1`, and the Elastic stack's credentials live in its gitignored `docker/elastic/.env`, never in the collection. The practice's pre-commit secret hook is replaced by a CI-time pattern scan (private keys, AWS/GitHub/GitLab/Slack tokens) in the repo harness — a deliberate adaptation, because commits land via the GitHub API here, so pre-commit hooks would never execute; CI is the only enforceable choke point. When an Ansible deploy role for the Elastic stack lands, its secrets go through Ansible Vault, never defaults. |
| Hardened execution containers | Every tool container is built in-repo by `dxdfir_images` with ansible as its only execution path (allow-listed run role), uid0 renamed+locked, no escalation/installers, non-root runtime; every `docker run` adds `--cap-drop ALL --security-opt no-new-privileges --network none` (volatility symbol fetch is the one explicit opt-in). |
| Monitor, log, audit | Repo-root `ansible.cfg` appends every run to `logs/ansible.log` and enables `ansible.posix.profile_tasks` for per-task timing; every processor emits a machine-readable JSON summary that the roles gate on. The log captures task output, which includes evidence-derived metadata (paths, resolved hostnames, artefact names) — it is therefore treated like evidence: gitignored (only `logs/.gitkeep` is tracked) and never leaves the analysis host. |
