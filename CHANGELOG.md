# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major version
is `0`, anything may change without notice.

## [Unreleased]

### Changed (the multi-tool matrices: gowindowlicker + godaemonhunter; the ansible-only container rule)
- **The Windows parsers deploy as the gowindowlicker sweep.** GoDFIR-toolz
  ships the parser dozen as one multi-tool image (gitlink bumped to the
  merged inventory: 8 images, the `.NET` per-tool lane retired):
  `dxdfir_godfir_toolz` runs `gowindowlicker lick` once over the artefact
  export beside the unchanged `godaemonhunter hunt` — writing the same
  `<out_dir>/<subtool>/<item>/<subtool>.jsonl` tree the retired per-tool
  runs wrote, `gowxt` riding the sweep like the rest — and `dxdfir_evtx`
  drives the same image's `goevtx` sub-tool under its canonical `GOEVTX_*`
  block. Layouts, record shapes and file names are unchanged; the CAR path
  is untouched.
- **Strict rule, enforced: only ansible interacts with the containers.**
  The molecule harness is a committed playbook
  (`playbooks/dxdfir-molecule.yml`; `.github/tests/run-molecule.sh` is only
  its launcher, the runner image's Dockerfile a real file), the smoke
  test's direct docker preflights are gone — each lane's ansible preflight
  (daemon check → `ensure_built` → hardened `verify`) is the gate — and
  `dev-scripts/purge-docker.sh` is retired: `dxdfir-cleanup.yml` is the
  wipe. Read-only daemon observation (the CLI health probe, the TUI
  containers panel) is the one documented exception (collection README,
  standards table).

### Changed (the two-galaxy split: GoDFIR-toolz builds, DX_DFIR deploys)
- **GoDFIR-toolz owns the image inventory and the build logic; DX_DFIR only
  consumes them.** The submodule gained its canonical root `images.yml` — all
  24 images (the pipeline five, the 12 Windows Go parsers, godaemonhunter,
  gomount, and the five `.NET` per-tool images as ordinary manifest entries),
  exactly where its own `conform.sh` always looked — plus the `godfir_build`
  role and `build_images` playbook (ansible end to end: manifest/alias
  resolution, source-stamped BuildKit builds, and the hardening verification,
  with each image's own `/etc/dfir-hardened` posture declaration held to the
  actual filesystem — no name lists in any role). GoDFIR-toolz installs as
  the `get_sybers.godfir_toolz` collection (`galaxy.yml`), and its
  `build-all.sh` is a thin launcher of the collection playbook.
- **DX_DFIR's repo-root `images.yml` is deleted.** The `dxdfir_images` role
  and CI read the submodule's manifest at the gitlink pin (the runtime
  verify/audit gates below read the same file through the build galaxy);
  the role's build path delegates to the build galaxy's `godfir_build`
  (resolved from the submodule, so the gitlink stays the only pin) and keeps the
  deploy-shaped parts: the set decision, the run-as uid knob, offline
  save/load and the `ensure_built` lane gate.
- **Smoke CI builds the whole manifest.** A new `images` job builds every
  manifest image through the build galaxy (hardening asserted on all of
  them, nightly included) alongside the fast goevtx+byakugan pipeline job.
- **The runtime image guard is ansible; `images.py` is retired.** Lane
  preflights and `dxdfir verify-images` gate through the build galaxy's
  `verify`/`audit` entries (same manifest, same contract, ansible end to
  end); the python module, its tests and the nine-role `*_python_path`
  plumbing that existed only to find it are deleted.
- **The build galaxy is never installed as a copy.** `docker/GoDFIR-toolz/roles`
  sits on the repo-root `roles_path`, so `godfir_build` resolves IN PLACE from
  the submodule checkout at the gitlink pin — the same mechanism the deploy
  galaxy's own roles already use; no tarball-mediated install, nothing to
  drift or reinstall on a bump. The CI and setup install steps are gone; a
  checkout without the submodule has the galaxy imported by `ansible-galaxy`
  from the `.gitmodules` source at the gitlink revision into the shared
  collections path (`roles_path`'s degraded-only last entry), and a repo
  check asserts the roles_path wiring.

- **No symlink shims anywhere.** setup-environment.sh stops symlinking
  `ansible*`, `go` and `dxdfir` into `/usr/local/bin`: one managed
  `/etc/profile.d/dxdfir.sh` puts the real tool locations on PATH (the venv
  bin appended, so the system python/pip keep winning by order), and legacy
  shims from previous installs are retired on the next run.

### Added (post-#293 follow-through)
- **Smoke CI builds its images through the images role** instead of raw
  `docker build`, so the goevtx/byakugan CI builds carry the
  `com.get-sybers.src` stamp and pass the role's post-build hardening
  asserts — including the filesystem scan #293 brought back to life — the
  same gate every operator build goes through. The last `docker rmi` in the
  build flow (removing the untagged image a rebuild replaces) is
  `docker_image state: absent` now, and the `dxdfir_stack` role carries its
  own README.

### Removed (unreleased-branch follow-through)
- The last compose-era vestiges: `dxdfir deploy stack`'s dead `--build` /
  `--no-build` flags (they fed the retired `dxdfir_stack_build` compose
  variable; the stack runs prebuilt images and the tool images have their
  own build verb), the `docker-compose-plugin` package from the engine
  install (nothing invokes compose any more), and every remaining
  `docker/elastic`/compose mention in docs, role READMEs and playbook
  headers.

### Added
- **`setup-environment.sh` no longer carries its own Docker installer**
  (entanglement-audit refactor, the flagship duplication): the script
  bootstraps ansible (userland tools, venv, pinned collections) and then
  provisions the engine THROUGH it — the new `dxdfir-bootstrap.yml` drives
  the `dxdfir_stack` role's `docker_ensure` entry point with the
  install/start decisions on, so the engine, daemon, docker group and the
  sudo'ing operator's membership are the same idempotent state tasks
  `dxdfir deploy stack` runs. The two hand-mirrored implementations (both
  carried comments promising to match the other) are one. Group/membership
  handling moved out of the fresh-install-only path in `docker_ensure` and
  runs on every bring-up verb as root (never on status/stop/destroy — read
  verbs do not mutate host accounts), with a log-out note when membership
  was just granted.
- **The offline image mechanism is Ansible, not shell** (entanglement-audit
  refactor). `scripts/save-docker-images.sh` is a launcher now: the image
  sets, pulls, exports and loads live in the `dxdfir_images` role's save/load
  entry points (`dxdfir-images-save.yml` / `dxdfir-images-load.yml`) using
  `docker_image` / `docker_image_export` / `docker_image_load` — the built
  set from the `images.yml` manifest the role already reads, the Elastic set
  from the inventory layer's new `dxdfir_elastic_images` map (which
  `dxdfir_stack` now references too, so deploy and offline-carry share one
  definition). The awk-parsing of Ansible's own variable files is gone, and
  `--verify` runs the real `dxdfir-verify-images.yml` instead of
  re-implementing it.
- **`dxdfir cleanup docker` speaks the docker API** (entanglement-audit
  refactor): discovery via `docker_host_info` (label-filtered), removal via
  `docker_image state: absent`, dangling layers via `docker_prune` — the
  `{% raw %}{% endraw %}`-shielded CLI formatting is gone, `--check` now
  reports exactly what would be removed, and an unreachable daemon still
  degrades to a clear skip.
- **The elastic docker compose is retired: `dxdfir deploy stack` deploys the
  analysis stack from inventory data** (#290). `docker/elastic/`
  (docker-compose.yml, `.env`/`.env.example`, `config/setup.sh`) is gone; the
  `dxdfir_stack` role now converges the stack itself — docker network, named
  `byakugan_*` volumes and one container per service, brought up in bootstrap
  order with explicit waits, health checks ported, everything on `127.0.0.1`.
  Settings live in the inventory layer (playbook-adjacent
  `group_vars/all.yml`, `dxdfir_elastic_*`: version pin, ports, heap,
  namespace, ingest tree, network/volume names), which every consumer
  references instead of re-deriving — `dxdfir_car_load` authenticates with
  the same variables and no longer parses `.env` at all.
  - **Secrets are generated inventory data.** Each secret is a file-backed
    `password` lookup into the gitignored per-host secret store
    (`ansible/inventory/secrets/<host>/`, `0750 root:docker` on a root
    deploy): generated on first deploy, reused forever, never logged;
    overriding the variable (`host_vars`, `ansible-vault encrypt_string`,
    `-e`) wins and materialises nothing. Deploy renders an `elastic.env`
    handoff there for the tools outside ansible — the TUI's Kibana tab,
    `dxdfir stamp-detections`, the riskgate — which read it (with the
    compose-era `.env` as fallback) instead of `docker/elastic/.env`.
  - **TLS material is generated host-side as state modules**
    (`community.crypto`, pinned 2.26.9): CA + es01/fleet-server pairs under
    the secret store's `certs/`, bind-mounted read-only into the containers
    — no cert scripts, no certutil container, and the CA is a plain host
    file every client verifies against (`certs/ca/ca.crt`). An unprivileged
    deploy refuses to weaken node-key permissions unless explicitly opted
    in (`dxdfir_stack_allow_world_readable_keys`).
  - **The compose `setup` service became idempotent API tasks**: the
    kibana_system password, the least-privilege `logs_car_writer` role and
    the `byakugan_loader` user are reconciled against the live
    Elasticsearch API — read first, change only what differs.
  - **A compose-era deployment migrates in place**: presence/status/stop/
    destroy also honour the old compose project label, deploy replaces the
    old containers (data volumes untouched), imports operator-set secrets
    from a surviving `.env`, and — on a root deploy — imports the CA from
    the old certs volume so enrolled agents keep their trust.
  - stop/destroy/status no longer need credentials at all: every query and
    action is label-driven.
- **`dxdfir deploy stack` installs Docker when the host has none, and every
  stack verb checks the engine first.** The preflight reads the engine's
  state before anything else (`tasks/docker_ensure.yml`): no engine or a
  stopped daemon is answered by the same playbook decision as an absent
  stack — `status` reports it and ends cleanly, `stop`/`destroy` flag it.
  The deploy playbook opts in to installing the engine
  (`dxdfir_stack_install_docker`: Docker's apt repository on Debian/Ubuntu
  families, the `scripts/setup-environment.sh` flow as idempotent state
  modules, docker-group membership for the sudo'ing operator), and deploy
  and start opt in to starting a stopped daemon
  (`dxdfir_stack_start_docker`).
- **Every stack verb reads the host before requiring anything, and each
  playbook decides what absence means** (`dxdfir_stack_when_absent`):
  `status` reports "no analysis stack on this host" and ends cleanly (the
  answer, not a failure), `start`/`stop`/`destroy` flag it (nothing to act
  on), `deploy` continues — absence is its starting point. A default
  inventory (`ansible/inventory/hosts.yml`, wired in `ansible.cfg`) makes
  the workstation explicit; the pull-capacity gate is a playbook decision
  too (`dxdfir_stack_pull_gate`, deploy/start), leaving the role free of
  per-action branches.
- **`dxdfir deploy stack` self-heals a short image store instead of dying
  mid-pull** (containerd: "no space left on device"). The `dxdfir_stack`
  preflight gains a pull-capacity gate on deploy/start: while stack images are
  still to be pulled it measures the image stores
  (`dxdfir_stack_image_store_paths`), reclaims once when short (docker prune —
  stopped containers, dangling images, unused networks, build cache;
  `dxdfir_stack_reclaim_all_images` widens it), and asserts
  `dxdfir_stack_min_free_gib` with one clear failure otherwise. A host whose
  images are already local is never gated; stop/destroy/status stay ungated.

### Changed
- **The memory lane recovers the PDB-derived process fields offline.** The
  pinned anamnesis engine (Anamnesis#18–#20) recovers `command_line`, `cwd`
  and `env_vars` from the PEB-anchored parameter block, `create_time` from
  the in-memory ntoskrnl's own accessor export, and `sid`/`user` from the
  constraint-solved process token — no PDB, no network — teaching itself a
  per-build `(GUID, age)` offset store in the symbol-cache mount
  (`anamnesis-offsets/`) that converges and self-heals across runs. Process
  rows also carry the restored pslist/psscan contrast as separate signals:
  raw `Unlinked`, MemProcFS's `Terminated`, `ExitTime`, and `Hidden` as the
  unlinked-and-still-running consensus verdict.
- **The memory lane's PDB symbol cache is a persistent read-write bind
  mount, not a build-time bake.** The anamnesis image no longer downloads a
  seed memory image or any PDB at build time (the bake's in-build symbol
  fetch produced nothing and failed the build); it ships an empty
  `/opt/anamnesis/lib/Symbols` mount point and `dxdfir_memory` bind-mounts
  `dxdfir_memory_symbols_dir` (default
  `data_store/dependencies/memprocfs-symbols`) read-write there — the one
  directory MemProcFS uses as its local symbol cache when writable, so the
  cache persists and accumulates across runs (symsrv layout; externally
  obtained PDBs can be dropped straight in). The lane stays always offline.
  GoDFIR-toolz pin → the `symbols`-mount contract.
- The memory lane follows the Anamnesis plugin-id rename
  (`windows.piiat.*` → `windows.anamnesis.*`) and the stix docs/tests call the
  CAR engine's pass-through bundles Byakugan bundles — the last piiat-era
  naming. Both `sources.yml` pins predate the renames; bump them once the
  renames land on the tools' default branches.
- **Every tool lane runs its container from ansible, driven by the tool's
  GoDFIR-toolz `contract.yml`.** The `dxdfir_lane` skeleton builds each confined
  `docker run` from the contract (`-e` per declared variable, `-v` per mount) and
  gates on the container's single JSON summary line; the tools discover, batch
  and skip their own inputs. Output layouts follow the contracts
  (`windows_logs/<log>/goevtx.jsonl`, `log2timeline/{storage,jsonl}/<source>/`,
  `godfir-toolz/<tool>/<item>/`, `detections/<subtool>/<item>/`). The CAR
  `verify` action runs the engine's `verify` sub-tool through the same env
  contract (`BYAKUGAN_VERIFY_INPUT_DIR` / `BYAKUGAN_VERIFY_OUT_DIR`), is judged
  on the summary's `status: ok`, and leaves its report as `verify.txt` beside
  the stores.
- **The Byakugan engine pin moves to the main that ships the engine's own
  `byakugan.cli` dispatcher** (`build` / `timeline` / `verify` / `car-vocab`)
  and the framework-layout discovery — `build-car` finds
  `windows_logs/<item>/goevtx.jsonl`, `jsonl/<source>/timeline.jsonl` and
  `godfir-toolz/<tool>/<item>/` sources; the `get-sybers/byakugan` image
  ENTRYPOINT delegates to that dispatcher.
- `dxdfir build-car` drops the single-source `--in/--host/--artefacts` mode (the
  contract has no env for it) and gains `--derive` / `--stix`; `--out` names the
  CAR tree. `dxdfir build-timeline --out-dir DIR` replaces `--out PATH`
  (`timeline.jsonl` lands beside the stores by default) and gains `--force`.

### Removed
- **The Python and shell container wrappers.** `get_sybers_dxdfir.zeek`,
  `.evtx`, `.plaso`, `.godfir_toolz`, `.imageexport`, `.mitrecar`, `.carcheck`,
  `.container` and `.signatures.{yara,suricata,hayabusa,__main__}` (with their
  tests) and the mounted psort output module `dev-scripts/plaso/l2t_json_dxdfir.py`
  are gone — no host-side code builds a container argv any more. The package
  keeps the image supply-chain guard (`images`), the ruleset fetchers
  (`signatures.detectraptor`, `signatures.suricata_rules`), the detection
  rules-as-code and the STIX exchange. The smoke test drives the lanes with
  `ansible-playbook`.
- **SOF-ELK, eradicated.** The Elastic-native stack is the one analysis backend;
  the legacy SOF-ELK path is gone end to end: `docker/sof-elk/` (the from-source
  image + compose stack), the `dxdfir_deploy_sofelk` / `dxdfir_ingest_sofelk`
  roles and their playbooks, `get_sybers_dxdfir.sofelk` (the delivery
  script + ledger — Filebeat's own registry already provides idempotent
  ingest of the processed tree), the `--pipeline elastic|sofelk` axis on
  `dxdfir process` (and the `dxdfir_<lane>_pipeline` /
  `*_elastic_out_dir` / `*_sofelk_out_dir` role variables — collapsed into one
  `dxdfir_<lane>_out_dir`), the `--stack` selector on `dxdfir stack`, and the
  `get-sybers/sof-elk` allow-list entry in `images.yml`. Removing the from-source
  SOF-ELK build also removes the repo's least-pinned fetches (a floating
  `philhagen/sof-elk@main` clone, `FROM alpine/git:latest`, unpinned Logstash
  plugins).

### Changed
- **The `dxdfir` grammar reads verb first.** `register collection NAME`,
  `unregister collection NAME`, `select collection NAME`, `unselect collection`,
  `sort collection [NAME]`, `list collections` and `deploy | destroy | start |
  stop | status stack` replace the noun-first `collection <verb>` / `stack <verb>`
  groups. The collection verbs also take a bare NAME in place of the noun
  (`register NAME`, `sort NAME`, `select NAME`; `register NAME` gains `--from`).
  `list` keeps its `lanes` (default) / `raw` / `processed` views as subcommands
  and adds `collections`; `cleanup processed|car|docker` and `stix …` were
  already verb first and are unchanged. The old spellings still run as hidden
  aliases that print the verb-first form to stderr; they are removed in the next
  minor. `dxdfir --help` is sectioned (Setup / Evidence and collections /
  Processing / CAR / Analysis stack / Housekeeping) to mirror the command
  reference, and the man page now documents the collection, stack and cleanup
  verbs. The noun takes either spelling — singular or plural
  (`list collection` == `list collections`, `register collections` ==
  `register collection`) — and `car-timeline` became `build-timeline` (the
  verb-first spelling; `car-timeline` stays as an alias).
- **All tool-image builds live in the GoDFIR-toolz submodule; the Elastic stack
  is back home at `docker/elastic/`.** The byakugan/plaso/signatures/zeek build
  items moved from `docker/<name>/` into the submodule (one dir per image,
  submodule-root build context — the piiat-mem pattern), so `docker/` holds only
  `elastic/` and the submodule. `images.yml`'s default context is now
  `docker/GoDFIR-toolz`; the `dxdfir_images` preflight no longer syncs
  `harden.yml` into a generated `docker/hardening/` mirror (every Dockerfile
  COPYs the canonical copy from the shared context) and its submodule gate now
  says `git submodule update --init --recursive`. The Elastic stack moved from
  `stacks/elastic/` to `docker/elastic/` (reverting #219's `stacks/` detour);
  `stacks/` is gone.
- **The Eric Zimmerman tool family is now all-Go, and the zimmerman lane runs the
  Go substitutes end to end.** The last five .NET EZ tools were ported to
  static-Go `FROM scratch` images in
  [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) and the pipeline was
  switched onto them: **RECmd→`gore`**, **SBECmd→`gosbe`** (both replay the
  `.LOG1/.LOG2` dirty-hive transaction logs via `regparser.RecoverHive` into a
  writable `/work` tmpfs, matching .NET fidelity), **LECmd→`gole`**,
  **JLECmd→`gojle`**, **WxTCmd→`gowxt`**. `gore` drops the `--bn`/`--nl` flags
  and uses its own baked, redistributable `/batch/default.reb` (a substitute for
  the non-redistributable Kroll batch). Only **SQLECmd** remains .NET (its YAML
  Maps engine is a separate, larger port and it is not pipeline-invoked). The
  GoDFIR-toolz submodule is bumped to the commit carrying all twelve Go tools.
  Also restored the `dxdfir_images` "no shell/python" hardening assertion for the
  Go images, whose real names (`goamcache`/`gomft`/…) had drifted out of the
  check's tool list during the earlier renames.
- **The zimmerman lane's SRUM and Prefetch now run through the Linux-native Go
  substitutes** instead of Plaso: SRUM via `get-sybers/goese` (`goese`,
  replacing the old plaso `esedb/srum` two-step) and a new Prefetch pass via
  `get-sybers/goprefetch` (`goprefetch`). The Byakugan engine gains two new
  MITRE data sources (`esedump_srum`, `prefetch_dump`) that normalise the tools'
  JSONL into the same CAR objects (SRUM→flow/process, Prefetch→process/create)
  with their own identity, coexisting with Plaso's coverage; the Go tools keep
  higher fidelity (second-precision timestamps, decoded device paths/SIDs).
  `byakugan.ref` bumped to the engine commit carrying those maps.
- **Container images renamed to the `get-sybers/` namespace** (was `dxdfir/`) and
  the **[GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) repo added
  as a submodule** (`third_party/GoDFIR-toolz/`) — the single source for the
  Eric Zimmerman container family. EvtxECmd, the EZ tool family (recmd, mftecmd,
  amcacheparser, appcompatcacheparser, lecmd, jlecmd, sbecmd, sqlecmd, rbcmd,
  wxtcmd) and the two Linux-native Go substitutes now build from the submodule;
  DX_DFIR's duplicated `docker/eztool` + `docker/evtxecmd` were removed. yara,
  suricata, zeek, plaso stay in `docker/`; volatility from Anamnesis.
- **Two new Go substitute images** for the Windows-bound EZ tools, built into the
  image set: `get-sybers/goprefetch` (`goprefetch`, replaces PECmd) and
  `get-sybers/goese` (`goese`, replaces SrumECmd/SumECmd) — both `FROM
  scratch`, no shell/python. (Wiring the zimmerman lane onto them is a follow-up.)
- **The hardening playbook has one canonical home** — the GoDFIR-toolz
  submodule (`hardening/harden.yml`). The submodule's images use it directly; the
  image role's preflight syncs it into `docker/hardening/harden.yml` (now
  generated + git-ignored) so DX_DFIR's own images can `COPY` it.

### Added
- **A Go/[termui](https://github.com/gizak/termui) front-end for `dxdfir`** (`go/`),
  replacing the Python Typer CLI as the user-facing entry point while keeping the
  same verb/flag surface, exit-code contract, and repo-root discovery. It drives
  the existing `get_sybers.dxdfir` Ansible collection and the `get_sybers_dxdfir`
  processors by shelling out — no processing is re-implemented. Presentation is
  **adaptive**: `process` and collection creation (`register`, `collection sort`)
  render a live dashboard — overall gauge, per-lane board, a bounded *filtered*
  log-tail for the long-pole lanes (volatility/plaso), and an exceptions panel —
  while quick verbs stay concise plain output and anything piped/CI/non-TTY
  streams the same progress as plain lines. Because Ansible buffers a lane's
  output until it exits, progress is reconstructed by **watching the deterministic
  per-item output files land on disk**, so a multi-hour run is never silent and
  the tools' firehose never reaches the screen. Built as broken-down Go packages
  (`cmd/dxdfir` + `internal/{cli,model,repo,run,lanes,collect,tui,plain,termdetect,style}`),
  the module structure the original 980-line `cli.py` never had.
- Thin, additive `python -m` front-end contracts so the Go binary can drive the
  processors from a checkout: `get_sybers_dxdfir.collection` (a non-interactive
  JSON + `::dxdfir::` progress-sentinel CLI for status/lanes/state/register/sort/
  hash/select — magic-byte classification and SHA-1 hashing stay the Python
  detectors, the source of truth), `get_sybers_dxdfir.stix` (`__main__` shim), a
  `timeline` subcommand on `get_sybers_dxdfir.mitrecar`, and optional progress
  callbacks on `collection.sort_into` / `write_manifest` / `hash_collection` /
  `_hash_file` (all backward-compatible; defaults unchanged).
- **The pipeline stages the CLI ran outside Ansible are now Ansible roles**, so
  the front-end drives Ansible for the whole pipeline (not just processing +
  image builds): `dxdfir_car` (build / verify / timeline of the materialised
  CAR — the epic-#86 stage that had no role), `dxdfir_stack`
  (deploy/destroy/start/stop/status for the Elastic-native and SOF-ELK stacks,
  reusing the previously-orphaned `dxdfir_deploy_sofelk` for the SOF-ELK build)
  and `dxdfir_cleanup` (processed/car/docker teardown), plus the thin
  `dxdfir-verify-images.yml` audit play. Each follows the `dxdfir_lane`
  conventions (preflight → act → verify/gate, FQCN, house task-naming) and
  passes `ansible-lint --profile production`.

### Changed
- The `dxdfir` command is the Go binary built from `go/` (see `go/README.md`);
  the Python package no longer installs a console script (the interim
  `dxdfir-py` fallback went with the Typer CLI — see Removed).
- **The Go CLI now drives Ansible for build-car, verify-car, car-timeline,
  verify-images, `stack *` and `cleanup *`** (previously in-process Python or a
  direct `docker`/`bash` subprocess) via the new roles/playbooks above —
  `cleanup --dry-run` maps to `ansible-playbook --check`. `list` stays native
  (filesystem inventory), and `collection`/`register`/`stix` keep the streaming
  `python -m` contract (Ansible buffers per-file progress; stix's stdout is data).
- **Build + dependency wiring for the Go front-end.** `scripts/setup-environment.sh`
  installs the Go toolchain when absent — or older than go.mod's 1.24 floor,
  since the build pins `GOTOOLCHAIN=local` — and builds+installs the `dxdfir`
  binary (and its man page) as the only front-end; `.github/workflows/checks.yml` adds
  `actions/setup-go` and `tests/run-checks.sh` gains a guarded "Go front-end
  (gofmt / vet / build / test)" check group; `THIRD_PARTY_NOTICES.md` records the
  Go build-time modules + licences; and `scripts/{package-offline,setup-offline}.sh`
  vendor the Go modules (`go mod vendor`) for reproducible air-gapped builds.
- **The Go front-end builds its `ansible-playbook` invocations with
  [go-ansible](https://github.com/apenella/go-ansible) v2.4.1** (typed command
  options instead of hand-assembled argv). go-ansible only *builds* the command
  — the in-repo run engine still executes it — and extra vars stay ordered,
  repeated `-e KEY=VALUE` pairs so the user's overrides keep their last-wins
  contract (never a collapsed JSON blob). The Go toolchain floor moves
  1.22 → 1.24 with it (`go.mod`, `setup-environment.sh` installs 1.24.7, CI
  `setup-go` 1.24); `go mod tidy` also bumped cobra v1.8.1 → v1.10.1 and pflag
  v1.0.5 → v1.0.10.
- The **`stix` sub-CLI is reimplemented on stdlib argparse** (typer is gone) with
  an identical surface: same commands, options, defaults, exit codes
  (usage 2, validation/push failures 1) and the same stdout=data /
  stderr=summary stream split the Go passthrough relies on. Only the help
  rendering changed (plain argparse text instead of rich boxes).
- **Offline installs without a Go toolchain get no fallback front-end**:
  `setup-offline.sh` says so and drives the collection playbooks directly with
  the venv's `ansible-playbook` (the image-inventory audit runs
  `dxdfir-verify-images.yml` that way), instead of symlinking the retired
  Python CLI as `dxdfir`. A toolchain older than go.mod's 1.24 floor takes the
  same path (air-gapped, `GOTOOLCHAIN=local` cannot upgrade itself); when the
  front-end does build, the venv's ansible tools are symlinked onto PATH and
  the verify step pins resolution via `DXDFIR_PYTHON`.
- **CI installs the Python package under the `python/constraints.txt` lock**
  (`checks` and `smoke` both), so the pinned resolution the installers ship is
  the one the tests exercise.
- **The Byakugan engine (formerly PIIAT-MitreCar) is no longer vendored** as
  the `third_party/piiat-mitrecar` submodule: DX_DFIR now plugs into an
  **external recursive checkout** — `$BYAKUGAN_ROOT` when set, else a
  `byakugan/` directory beside the repo — pinned by the new repo-root
  `byakugan.ref` file (the same commit the old gitlink pinned) and provisioned
  by `scripts/setup-environment.sh`, the CI smoke workflow, and the offline
  bundle. The bundle now actually ships the engine (`byakugan.tar`, nested
  model submodules included) and the Anamnesis tree (`piiat-mem.tar`):
  `git archive` never carried submodule content, so no submodule had ever
  reached a bundle and `build-car` had never worked air-gapped.

### Removed
- **The Python Typer front-end.** `python/get_sybers_dxdfir/cli.py` (the
  980-line Typer app) and the `dxdfir-py` console script are gone — the Go
  binary (`go/`) is the only front-end; the Python package keeps the processors
  and the `python -m` contract modules it drives. The typer dependency chain
  left `python/constraints.txt` with it (typer 0.27.2, rich 15.0.0,
  Pygments 2.21.0, markdown-it-py 4.2.0, mdurl 0.1.2, shellingham 1.5.4,
  annotated-doc 0.0.5); the surviving pins are unchanged. The man page moved
  to `go/man/dxdfir.1` with the verbs it documents.
- **The Kusto/ADX layer.** The Azure Data Explorer emulator was the analysis
  backend from 0.2.0; the Elastic-native path (`docker/elastic`, the ES|QL/EQL
  detection rules-as-code, the CAR→ECS projection and its Phase-0 risk gate,
  the STIX/CTI exchange) supersedes it, so the whole stack is gone:
  `kusto/schema/` (databases, tables, ingestion mappings, the generated
  `mitre.car_*` tables and views), the `dxdfir_deploy_adx` / `dxdfir_ingest_adx` /
  `dxdfir_detect_adx` roles and playbooks, `get_sybers_dxdfir.deploy`, the
  `get_sybers_dxdfir.ingest` package (the Kusto REST client, the `.ingest` loader
  and its record shaping), the Kusto detection runner and registry
  (`get_sybers_dxdfir.detect` keeps only the Elastic rules-as-code loader), the
  `dxdfir deploy` / `ingest` / `detect` verbs, `docs/Kusto-Port.md`, the ADX
  check groups in `tests/run-checks.sh`, and the emulator's EULA/licensing
  notices. The `smoke` workflow no longer deploys an emulator.

### Changed
- `--pipeline adx` is now `--pipeline elastic` (the default): the processed
  tree the CAR lane builds from. The roles' `dxdfir_<role>_adx_out_dir` variables
  are now `dxdfir_<role>_elastic_out_dir` (same default paths); `sofelk` is
  unchanged.
- **`dxdfir verify-car`** reads the materialised CAR directly
  (`data_store/processed/car/<source>/car_<object>.jsonl`, or `--car-dir`)
  instead of querying the emulator — the same assertions (populated,
  value-sane, `car_action` in the engine model's vocabulary, traceable,
  relationship edges naming real endpoints) over the JSON that is the contract
  every sink reads.
- The **smoke test** asserts the Sysmon-derived CAR fields in the
  `car_<object>.jsonl` the engine writes and then runs the `verify-car` gate
  over the same tree; it needs no backend.
- `tests/run-checks.sh` (and the `checks` workflow) now run the Python unit
  tests when pytest is installed.
- **The CAR engine's GitHub repository was renamed** PIIAT-MitreCar →
  [byakugan](https://github.com/Get-Sybers/byakugan): `.gitmodules` now points
  the `third_party/piiat-mitrecar` submodule at the new URL. The vendored path
  (`third_party/piiat-mitrecar`) and the `piiat_mitrecar` Python package are
  unchanged upstream — only the repository name changed — so no code changes.

### Added
- **`dxdfir stix behaviour-sightings`** — joins the detection lanes
  (suricata / hayabusa / yara) to the CAR entities they touch, against the
  finished CAR (`car_<object>.jsonl` per source), and emits each join as a STIX 2.1 **Sighting of the
  ATT&CK attack-pattern** the detection names, over an `observed-data` keyed on
  the matched CAR row's spindle `guid` (the behaviour timeline as the primary
  axis), with the host as `where_sighted_refs`. suricata → the `flow` for the
  alert's connection pair (a C2 IP read as its resolved `dest_fqdn`); hayabusa →
  the `process` by ProcessGuid; yara → the `process` by pid or `file` by hash.
  Reuses the exchange's object builders and validation, so a behaviour bundle
  merges object-for-object with `stix export` and PIIAT's projection. Documented
  in Byakugan's [cross-source-linkage/09-behaviour-sightings.md](https://github.com/Get-Sybers/byakugan/blob/main/docs/research/cross-source-linkage/09-behaviour-sightings.md).

### Fixed
- The YARA **memory** lane's Volatility renderer defaulted to a nonexistent
  `dev-scripts/volatility/` path (the lane had never run), so
  `dxdfir process signatures --yara-sources memory` could not scan; it now
  resolves the renderer the vendored Anamnesis tool owns
  (`third_party/piiat-mem/jsonl_dfir_renderer.py`).

## [0.6.0] - 2026-08-30

### Added
- Materialized MITRE CAR: the engine ([PIIAT-MitreCar](https://github.com/Get-Sybers/PIIAT-MitreCar)) normalises each source to `car_<object>.jsonl`, ingested as the 13 `mitre.car_*` tables + `car_relationships`, with `Car()`/`CarObjects()` views.
- `dxdfir build-car` (build the per-source CAR stores) and `dxdfir car-timeline` (one property-rich, time-ordered timeline from car.db + superset.db).
- `dxdfir ingest --only car` loads the CAR stores into `mitre.car_*`.
- Zimmerman (EZ-Tools) lane: hardened `dxdfir/*` containers (RECmd, SRUM via Plaso, MFT, …) → CAR.

### Changed
- CAR extraction moved into the PIIAT-MitreCar engine (pinned submodule); memory/Volatility driven via the [Anamnesis](https://github.com/Get-Sybers/Anamnesis) CLI. `40-mitre.kql` is now the materialized tables, schema generated from the engine model.
- `dxdfir verify-car` rewritten against the `mitre.car_*` tables; `car_action` validated against the engine model's vocabulary.

### Removed
- The query-time `Car*()` / `Car<Object>_<Artefact>()` KQL functions — no backwards compatibility; read the `car_*` tables directly.
- The Velociraptor lane (role, playbook, ingest source, `host.VelociraptorJson`).

## [0.5.0] - 2026-08-28

### Added
- **Plaso loose-artefact sources** (`--loose-dir` / `dxdfir_plaso_loose_dir`): one
  folder per host (/var/log copies, mobile filesystem dumps, triage output),
  parsed by log2timeline as directory sources — how the non-image OS families
  reach the timeline. Opt-in (loose trees can be very large).
- **Per-OS CAR validation**: `dxdfir verify-car` now asserts the Linux-facing
  sources with expected values (utmp login/logout + user round-trip, sshd
  logins with client port, cron command/exe round-trip) and reports an
  **OS-family coverage summary** (Windows events/disk/memory, Linux/Unix,
  macOS utmpx/fseventsd, network) so the release gate requires every family,
  not one standing in for all. Proven 66/0 over: Windows XP + Security/Sysmon,
  the 2020 Linux threat-analysis server logs (CentOS + Debian-style + pfSense;
  84k cron runs, real attacker logins), the macOS 2019 tuck image, an Android
  Nexus image, Volatility memory, and Zeek captures.
- **`dxdfir verify-car`** (`get_sybers_dxdfir.carcheck`) — the promotion gate for
  CAR correctness at the ADX level across EVERY lane, ported to Python from the
  original shell harness: asserts expected field VALUES (not just presence) per
  CAR source, round-trip fidelity (each normalized field == its native source
  field), per-artefact identity (every row carries a non-empty SourceFile —
  never data compiled together), roll-up no-fabrication (union == sum of
  sources), that no-producer sources (velociraptor: Srum/RECmd) stay empty, and
  the Plaso-extraction guards (process exe is a program never a parsed
  .pf/hive/$MFT; MFT names the file it describes; UsnJrnl deletes surface).
  Proven green (59/0) on a clean run over host Sysmon + Windows Security,
  network Zeek, memory Volatility (7 objects), and a Windows disk image
  (prefetch/amcache/MFT/UsnJrnl). Replaces the retired `tests/car-runthrough.sh`.

### Fixed
- **CAR-model logic (from a Fable audit against the pinned Volatility 2.28.0 /
  Plaso 20260720 field names)** — bugs a value run-through over Sysmon-dominated
  evidence could not surface: `CarProcess_Plaso` mapped exe/image_path to the
  parsed artefact's own path (a `.pf`/hive/`$MFT`) instead of the executed
  program (H1/H2); `CarFile_Plaso` labelled every MFT row `\$MFT` (H3) and every
  UsnJrnl row `modify`, hiding deletes (M3); `CarService_Evtx` read 7045's keys
  for 4697 (M1); `CarUserSession_Security` read the wrong keys for 4778/4779
  (M2); Sysmon-23 file hashes dropped (M5); svcscan `Binary (Registry)` skipped
  (M6); amcache sha1 / BAM sid mis-sourced (M4/M7); plus identity/representation
  fixes (SourceFile aliases, Velociraptor host/fqdn, packet_count null,
  vocabulary calls for 4625/4648/4779). Also added provider/Channel guards.
- The `dxdfir` CLI now declares the Python docker SDK (`requests`, `docker`) as
  dependencies — `dxdfir deploy`/`ingest` drive community.docker and failed on a
  clean install (and would have failed from the offline wheel bundle, which is
  built from these declared deps).


### Changed
- **Container posture reworked from the ansible-run-role model to a minimal /
  attack-surface-reduction model** — stronger against both container escape and
  a supply-chain-compromised tool. The runtime images no longer ship ansible or
  an in-container allow-list; each is stripped to the tool (tool-as-ENTRYPOINT),
  with no shell or python except where the tool needs them (yara keeps sh;
  volatility/plaso keep python). Build-time ansible hardening is kept (removed
  from the final image): uid 0 renamed `ansible` and locked, sudo/su and
  package managers/pip removed, setuid stripped, runs as uid 2000. Every
  processor `docker run` now adds `--read-only --tmpfs /tmp --pids-limit 512`
  on top of `--cap-drop ALL --security-opt no-new-privileges --network none`.
  Images shrank substantially (yara 66→40MB, suricata 209→55MB, evtxecmd
  263→93MB).

### Added
- **Offline packaging** (`scripts/package-offline.sh` + `scripts/setup-offline.sh`):
  one portable `dxdfir-offline-<ver>-<arch>.tar.gz` carrying the hardened
  images, the CLI + deps as wheels, the pinned collections, the repo, and
  `data_store/dependencies/` (signature rulesets, Hayabusa binary, Volatility
  symbols, EvtxECmd) — set up on an air-gapped host with zero network:
  manifest-verified first, `dxdfir verify-images` proves the loaded inventory
  last. `save-docker-images.sh` now saves the built `dxdfir/*` images instead of
  pulling them, and gained `--build` / `--verify`.
- **Start-time image inventory guard** (`get_sybers_dxdfir.images` /
  `dxdfir verify-images`): each processor preflight refuses to run unless the
  tool image is a known hardened `dxdfir/*` image (label + uid 2000 + expected
  name); the audit flags any unexpected `dxdfir/*` image on the host — something
  added to the namespace that should not be there. The role verifies each build
  with a shell-free `docker export` scan.


## [0.4.0] - 2026-08-27

### Added
- **Build-it-yourself hardened tool containers** (`docker/{yara,suricata,zeek,
  volatility,plaso,evtxecmd}`), Splunk-docker posture: ansible is the
  container's only execution path (pinned `ansible-playbook` ENTRYPOINT running
  the embedded allow-listed run role, `docker/runtime`); interpreters are
  pinned to baked wrappers; the uid-0 account is renamed `ansible` and locked;
  sudo/su and package managers removed; every setuid bit stripped; tools run as
  uid 2000. Hardening is applied by ansible inside every build
  (`docker/hardening/harden.yml`) and squashed.
- `dxdfir_images` role + `dxdfir-build-images.yml` playbook: builds every image and
  verifies the hardening contract statically and from inside the running
  container; molecule scenario proves a non-allow-listed argv is refused.
- Runtime breakout mitigations on every processor `docker run`
  (`get_sybers_dxdfir.container`): `--cap-drop ALL`,
  `--security-opt no-new-privileges`, `--network none`; Volatility ISF symbol
  fetch is an explicit opt-in (`--symbols-online` /
  `dxdfir_volatility_symbols_online`).
- Suricata per-pcap tuning template with the consolidated `SURICATA_VARS`
  registry; every stock suricata.yaml var auto-derived from each capture's own
  traffic and recorded for the operator.
- ansible-lint (production profile) gate; `requirements.yml` wired into
  setup-environment and enforced in CI; pipeline-agnostic `process.yml` per
  role with block/rescue diagnostics and check-mode support; molecule
  scenarios repaired and runnable via the containerised harness.

- The `dxdfir_deploy_adx` role now carries the retired shell deploy's remaining
  security properties: an isolated (masquerade-off, never `--internal`) docker
  network on by default (`dxdfir_deploy_adx_isolated`) with egress probed from
  inside the container after start, a read-back assertion that no port is bound
  to the wildcard address, and a preflight gate that refuses a non-local bind
  unless `dxdfir_deploy_adx_expose=true` is set as well (the Ansible equivalent
  of the shell's "type `expose`" prompt).
- The YARA lane's **disk** and **memory** sources are now in the Python processor
  (`get_sybers_dxdfir.signatures.yara`): disk images mounted read-only in place
  (ewfmount → ntfs-3g, FUSE; nothing extracted) → `disk.jsonl`, and process
  memory via Volatility 3 `windows.vadyarascan` (matches carry PID context) →
  `memory.jsonl`. `--yara-sources` selects sources; the mount/scan invocations
  are pure, unit-tested helpers.

### Changed
- Plaso is built from pinned PyPI with the libyal stack compiled from source
  (GIFT stable lags the `--output_fallback_hostname` the pipeline requires).
- No third-party tool image is pulled at runtime; the proprietary Kusto
  emulator (localhost-gated) and the stock .NET runtime (operator-supplied
  EvtxECmd mode) are the only remaining pulls.
- `data_store/.gitignore` prunes traversal (anchored skeleton whitelist);
  `git status` 25s → 0.014s.

### Removed
- The last data-pipeline shell scripts: `deploy-kusto.sh`,
  `apply-kusto-schema.sh`, `ingest-kusto.sh` and `scripts/lib/`
  (`docker-lifecycle.sh`, `kusto-api.sh`, `l2t-split.py`). The framework fully
  implements them — `dxdfir deploy` (the `dxdfir_deploy_adx` role +
  `get_sybers_dxdfir.deploy`) and `dxdfir ingest` (the `dxdfir_ingest_adx` role +
  `get_sybers_dxdfir.ingest`, whose `prepare.split_l2t` superseded `l2t-split.py`).
  The smoke test now deploys its throwaway emulator through `dxdfir deploy`,
  and the check harness asserts the localhost-bind, EULA-disclosure, isolation,
  ephemeral-default, readiness, endpoint-routing, Zeek-routing, l2t fan-out and
  staging-hygiene guarantees against the role and the Python modules instead of
  the deleted scripts. Not carried over: `KUSTO_REPLACE` (the role converges
  idempotently; remove the container for a fresh ephemeral instance) and
  `--purge`/`--purge-only` (ephemeral default — `docker rm -f kusto-emulator`
  is the purge).
- The retired per-source `process-*.sh` scripts (`process-zeek-ALL.sh`,
  `process-evtx-EvtxECmd.sh`, `process-volatility.sh`,
  `process-log2timeline-Dynamic.sh`, `process-velociraptor.sh`) and the dead
  `process-log2timeline-JSON_Line.sh` — their behaviour lives in the
  `get_sybers_dxdfir` processors (`dxdfir process <source>`). The deploy/apply/ingest
  scripts remain.
- The signature-lane shell scripts (`process-signatures.sh`,
  `scripts/signatures/{yara,suricata,hayabusa}.sh`, `scripts/signatures/lib/disk-image.sh`)
  — fully ported to `get_sybers_dxdfir.signatures` (the `dxdfir_signatures` role /
  `python -m get_sybers_dxdfir.signatures`). Not carried over: the shell lanes'
  online provisioning of the YARA-Forge starter, ET Open (`suricata-update`) and
  the Hayabusa binary — rules/binaries are operator-supplied (the Python
  `--fetch` provisions the pinned DetectRaptor YARA set).

## [0.3.1] - 2026-08-26

### Fixed
- `dxdfir` CLI worked only where `ansible-playbook` happened to be on `PATH`.
  `ansible-core` is now a declared dependency of the package and the CLI resolves the
  `ansible-playbook` installed alongside it, so `dxdfir process`/`ingest`/`deploy`/`detect`
  work on a clean install.
- `scripts/setup-environment.sh` now installs the `dxdfir` CLI (into a dedicated venv),
  not just Docker and the userland tools.
- `dxdfir list` now inventories the evidence staged under `data_store/raw` (per source,
  with file counts and whether it is staged) instead of just naming the source types.
- `-h` is accepted everywhere as an alias for `--help` (`dxdfir -h`, `dxdfir process -h`,
  …), each level showing its own options.

### Added
- Root `README.md` **Quick Start**: clone -> `setup-environment.sh` -> `dxdfir deploy`
  -> `process` / `ingest` / `detect`.


## [0.3.0] - 2026-08-26

### Added
- Hayabusa (Sigma detection) inside the evtx lane (`get_sybers_dxdfir.evtx --hayabusa`,
  `dxdfir_evtx_hayabusa`), scanning the same `.evtx` the lane collects — loose or
  disk-image-extracted.
- Disk-image EVTX extraction in the evtx lane (`--image-src`): WindowsEventLogs pulled
  from E01/raw/VMDK with log2timeline/plaso `image_export.py` (`get_sybers_dxdfir.imageexport`).
- Suricata tuning: `--home-net` / `--external-net` / `--suricata-set`, and
  `--auto-home-net` (HOME_NET derived per-pcap from the observed private subnets).
- DetectRaptor YARA provisioning (`get_sybers_dxdfir.signatures.detectraptor`): commit-pinned,
  sha256-verified fetch merged into the yara-rules ruleset.
- Pipeline smoke test (`tests/smoke-test.sh` + the `smoke` CI workflow): runs the real
  evtx -> EvtxECmd -> ingest pipeline over sha256-pinned Sysmon fixtures and asserts the
  CAR objects populate correctly.
- `docs/Signature-Rules.md`: adding your own YARA / Suricata rules (and tuning HOME_NET).
- **Detection orchestration** (`get_sybers_dxdfir.detect` + `dxdfir_detect_adx` role +
  `dxdfir detect`), modelled on DetectRaptor's StartHunts runner: a registry where
  each detection declares the processed data it targets (an ADX `db.Table` or a
  signature-lane JSONL output), a runner that surveys what is actually present and
  executes only the applicable detections (KQL detections run engine-side via
  `.set-or-append`; JSONL detections stream their lane files), and a unified
  `misc.Detections` output — every hit tagged with detection id, severity, ATT&CK
  techniques, source and a per-sweep `RunId` (`kusto/schema/50-detections.kql`,
  with `DetectionsLatest()`/`DetectionSummary()` views over the newest sweep).
  Seeded with 11 detections spanning EvtxECmd, Plaso prefetch, Zeek, Volatility,
  Velociraptor and the three signature lanes.

### Fixed
- `EvtxPayload()` parses EvtxECmd's JSON payload; it matched only the legacy XML shape
  before, silently emptying every Sysmon/Security-derived CAR field (command line, parent,
  service name/path, Sysmon network 5-tuple, driver/module/thread).
- `CarFlow` end_time preserves sub-second connection duration (was truncated to whole seconds).
- `ZeekSsl()` drops the always-null `Ja3` projection (base Zeek never emits it).

## [0.2.0] - 2026-08-21

### Changed
- Rebuilt the pipeline as three layers: the **`dxdfir` CLI** → the
  **`get_sybers.dxdfir` Ansible collection** (one role per source, one action per task)
  → the **`get_sybers_dxdfir` Python package**. Ten per-source roles/processors, each
  targeting ADX or SOF-ELK via `--pipeline adx|sofelk`. The legacy `process-*.sh`
  scripts remain as the legacy layer.
- Ran the Kusto backend end-to-end against the real `kustainer-linux` engine; all
  nine MITRE CAR objects return live rows (`CarCoverage()` 9/9).
- Made ADX ingest idempotent via an in-DB ledger, and tolerant of a processed file
  vanishing mid-read (concurrent processing).
- Collapsed the `ingest-kusto.sh` sources into a descriptor table and consolidated
  container lifecycle into `scripts/lib/docker-lifecycle.sh`.

### Added
- `dxdfir` CLI (Typer): `process` / `ingest` / `deploy` / `validate`, a man page, and
  80+ unit tests.
- From-source SOF-ELK image (`docker/sof-elk/`) and a bundled `dxdfir/evtxecmd` image
  (`docker/evtxecmd/`, DLL + `Maps/` baked in).
- Memory lane (Volatility 3) → `memory.VolatilityJson`, feeding the memory CAR
  objects (process/module/driver/service/thread/user_session/file/registry).
- Velociraptor loader → `host.VelociraptorJson`, re-sourcing `CarRegistry()`.
- Linux log processing with Plaso (syslog / auditd / utmp) and cross-platform
  `CarUserSession()` / `CarService()` / `CarProcess()`.
- Kusto schema: five databases, typed tables + ingestion mappings, and the MITRE CAR
  model as KQL functions pinned against MITRE's `car_data_model.json`.

### Fixed
- First live-emulator run: bracket-quote reserved database names (`network`),
  `0L` → `long(0)`, broadened the `CarFile` `modify` classifier, confirmed `tolong()`
  hex-pid conversion, and a dozen first-cut defects (query-vs-mgmt endpoint routing,
  per-host EvtxECmd staging collisions, empty-response handling, Zeek sentinel
  coercion, `ppid` source, header/`ignoreFirstRecord` handling).

### Removed
- The entire Splunk stack — deploy scripts, the eight Splunk apps, the in-container
  Ansible, and the ESCU lookups. The Kusto emulator is the analysis backend now.
- The KAPE automation (PowerShell, `KapeJson`); Velociraptor offline collectors
  (EZ Tools) take its place.
- Renamed the project `Splunk_DFIR` → `DX_DFIR`.

## [0.2.0-beta] - 2026-08-04

First versioned release, on the (since-retired) Splunk backend.

### Added
- Licensing: `LICENSE` (Apache-2.0), `NOTICE`, and `THIRD_PARTY_NOTICES.md`.
- The MITRE CAR data model + field mapping (Splunk `MITRE_CAR_App`), generated from
  the vendored `car_data_model.json`.
- Windows Event Log ingestion (`process-evtx-EvtxECmd.sh` + `EvtxECmd_App`), and this
  `CHANGELOG.md`.

### Changed
- `deploy-splunk.sh` gained `--purge` / `--persist`; redeploy became the default;
  first-party app versions demoted `1.0.0` → `0.2.0`.

### Security
- Network-isolated the Splunk container and closed an evidence-leak hole in
  `data_store/.gitignore`.

### Fixed
- Ten defects found by auditing the pre-versioned line — Splunk UI reachability,
  `--purge` safety, the `host` inputs-field literal, and the repository-root
  resolution across seven scripts, among others.

The pre-beta line is frozen on the
[`deprecated`](https://github.com/Get-Sybers/DX_DFIR/tree/deprecated) branch.
