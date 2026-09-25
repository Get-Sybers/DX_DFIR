# get_sybers.dxdfir

The DX_DFIR forensic processing pipeline as an Ansible Galaxy collection. Every
tool is a [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) container
image driven purely by its `contract.yml` (environment variables + mounts); each
Ansible **task is one action** — a role declares its runs, the shared skeleton
builds each confined `docker run` from the contract and runs it — and the
**playbook** holds every decision: which roles run.

Conforms to the Get-Sybers Ansible standards (naming/structuring + one-action-per-task
+ robustness) — see `Get-Sybers/Ludus-Ansible` `docs/standards/ansible/`.

## Roles
One role per evidence source; each declares its tool runs and delegates to
`dxdfir_lane`, which reads the tool's contract, asserts the run fits it, builds the
confined `docker run` (`-e` per declared variable, `-v` per mount, behind
`--cap-drop ALL --security-opt no-new-privileges --pids-limit 512 --read-only`, tmpfs
scratch, `--network none`, `--group-add` for the evidence group), preflights the daemon
and the image supply chain, runs each container in order and gates on its single JSON
summary line.

| Role | Source | Tool image(s) (contract) |
|---|---|---|
| `dxdfir_zeek` | PCAPs → Zeek JSON | `get-sybers/zeek` |
| `dxdfir_memory` | Memory images → per-plugin JSONL (anamnesis / MemProcFS) | `get-sybers/anamnesis` |
| `dxdfir_evtx` | Windows Event Logs (`.evtx`) → goevtx JSON Lines | `get-sybers/goevtx` (+ `get-sybers/plaso` `image_export` for disk images) |
| `dxdfir_plaso` | Disk images / VM exports → Plaso JSON Lines | `get-sybers/plaso` (`log2timeline`, `psort`) |
| `dxdfir_godfir_toolz` | Disk images → the GoDFIR-toolz artefact parse | `get-sybers/plaso` `image_export` + `get-sybers/{gore,gojle,gole,goamcache,goappcompat,gosbe,gorb,gomft,goese,goprefetch}` |
| `dxdfir_signatures` | YARA / Suricata / Hayabusa / disk-scan detections | `get-sybers/signatures` (`yara`, `suricata`, `hayabusa`, `scan`) |
| `dxdfir_byakugan` | Processed tree → materialised MITRE CAR (build / verify / timeline) | `get-sybers/byakugan` (`build`, `timeline`) |

Stack lifecycle: **`dxdfir_stack`** (deploy/destroy/start/stop/status for the
Elastic analysis backend, the `dxdfir_stack` role). The stack's Filebeat tails the
processed `<type>/…` tree directly (`ELASTIC_INGEST_DIR`), so there is no
delivery role — the tools write, Filebeat ships.

**`dxdfir_images`** builds every tool container the roles run — hardened, from
the GoDFIR-toolz submodule, tool runs as uid 2000, no shell or python beyond what
the tool irreducibly needs — and verifies the contract per build. No third-party
tool image is pulled at runtime. A start-time **inventory guard**
(`get_sybers_dxdfir.images`) refuses to run anything but a known hardened
`get-sybers/*` image — each lane preflight asserts every image it is about to run
is hardened, and `dxdfir verify-images` audits the whole namespace for missing,
un-hardened, or unexpected images (something added that shouldn't be). Run
`playbooks/dxdfir-build-images.yml` once per host (and after a submodule bump);
see [the role README](roles/dxdfir_images/README.md).

Detection is not a role: the detections are Elastic rules-as-code
(`python/get_sybers_dxdfir/detect/rules/`, ES|QL/EQL loaded and validated by
`get_sybers_dxdfir.detect.rules_loader`) run by Elastic's Detection Engine on the
analysis stack. The CAR lane (`dxdfir build-car` / `dxdfir verify-car`)
prepares and gates the materialised CAR they read.

## Usage
The **`dxdfir` front-end** (the Go binary built from `go/`) drives these roles for
you:
```bash
dxdfir process zeek                     # = the dxdfir_zeek role, build → preflight → process → verify
dxdfir process signatures               # every detection sub-tool
```
Or run a playbook directly; each source has one under `playbooks/`, which selects
the role:
```bash
ansible-playbook playbooks/dxdfir-process-zeek.yml
ansible-playbook playbooks/dxdfir-process-memory.yml
ansible-playbook playbooks/dxdfir-process-evtx.yml
ansible-playbook playbooks/dxdfir-process-plaso.yml
ansible-playbook playbooks/dxdfir-process-godfir-toolz.yml
ansible-playbook playbooks/dxdfir-process-signatures.yml -e '{"dxdfir_signatures_lanes":["yara"]}'
ansible-playbook playbooks/dxdfir-build-car.yml
```

## Testing (molecule)

Every lane role ships a molecule scenario (`roles/<role>/molecule/default/`,
delegated driver — the role runs its own tool containers). Run them without
installing molecule on the host via the containerised harness:

```bash
./.github/tests/run-molecule.sh                    # default set (see script header)
./.github/tests/run-molecule.sh dxdfir_zeek          # one role
```

Scenarios that need operator-supplied fixtures (a sample `.evtx`, a disk image,
a memory image) read them from `MOLECULE_SAMPLE_*` env vars and are skipped with
a note when absent — see the script header for the full list.

## Standards alignment

The collection tracks the common Ansible best-practice set; where a practice
does not fit a localhost forensic pipeline, the deviation is deliberate and
recorded here rather than half-implemented.

| Practice | Where it lives here |
|---|---|
| Structure, naming, docs | One role per evidence source; `main -> build -> preflight -> process` task files in the shared skeleton; house task-name prefix `<role>-<stage> \| description`; per-role `README.md` + `meta/argument_specs.yml`; collection `CHANGELOG.md`; playbooks under `playbooks/`. |
| Variables, no hardcoding | Everything flows through `defaults/main.yml` with the `dxdfir_<role>_` prefix; inputs validated with `assert` at play start; each lane's output base is a resolved variable (`dxdfir_<role>_out_dir`); every `docker run` is built from the tool's `contract.yml` — no argv, image name or mount path is hardcoded in a task. |
| Idempotency | State lives in the tool containers (an item with valid output is skipped unless `<TOOL>_FORCE`); `changed_when` reads each container's JSON summary line; the contract's exit table is honoured; molecule enforces `changed=0` on the second run. Check mode is supported: the container runs skip and their gates skip with them. |
| Roles for reusability | Single-responsibility roles invoked by thin playbooks; shared behaviour lives in `dxdfir_lane`, not copy-pasted tasks; versioned as a collection (`galaxy.yml`, pinned deps in `requirements.yml`). |
| Error handling & validation | The run spec is asserted against the contract before anything runs (undeclared env, unbound required mounts, an unknown sub-tool); preflight asserts prerequisites; the process/verify/gate unit runs in a `block` whose `rescue` surfaces every run's summary line and stderr as one diagnostic before failing. |
| Dynamic inventory | **Deviation, verified inapplicable:** the pipeline is localhost-only by design (evidence never leaves the analysis host); tool containers are resources the roles manage, not inventory hosts, so there is nothing to discover. Becomes applicable only if remote acquisition/collector hosts ever become targets. |
| Testing in CI/CD | `ansible-lint` (production profile, config in `.ansible-lint`) + the repo harness run on every push/PR; the smoke workflow runs the evtx and CAR lanes for real; molecule scenarios run the roles for real (`.github/tests/run-molecule.sh`), idempotence included. |
| Cross-platform conditionals | **Principle implemented, mechanics inapplicable:** the practice's point — one adaptable unit instead of near-identical copies — is exactly the shared `dxdfir_lane` skeleton. OS-family `when` ladders have no surface: targets are tool containers on a Linux analysis host, single-platform by design. |
| Vault / secrets | **No secrets exist in the collection by design** — verified: no credentials anywhere, every published port binds `127.0.0.1`, and the Elastic stack's credentials live in the gitignored per-host secret store (`ansible/inventory/secrets/`, generated by the `dxdfir_stack` role, vault-overridable), never in the collection. The practice's pre-commit secret hook is replaced by a CI-time pattern scan (private keys, AWS/GitHub/GitLab/Slack tokens) in the repo harness — a deliberate adaptation, because commits land via the GitHub API here, so pre-commit hooks would never execute; CI is the only enforceable choke point. |
| Hardened execution containers | Every tool container is built by `dxdfir_images` from the GoDFIR-toolz submodule (non-root runtime, no escalation/installers, no shell/python beyond what the tool needs); every `docker run` the skeleton builds adds `--cap-drop ALL --security-opt no-new-privileges --pids-limit 512 --read-only`, tmpfs scratch and `--network none` (the memory lane's symbol fetch is the one contract-declared opt-in). |
| Monitor, log, audit | Repo-root `ansible.cfg` appends every run to `logs/ansible.log` and enables `ansible.posix.profile_tasks` for per-task timing; every tool container emits one machine-readable JSON summary line that the roles gate on. The log captures task output, which includes evidence-derived metadata (paths, resolved hostnames, artefact names) — it is therefore treated like evidence: gitignored (only `logs/.gitkeep` is tracked) and never leaves the analysis host. |
