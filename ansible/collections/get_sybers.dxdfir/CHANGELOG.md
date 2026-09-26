# Changelog — get_sybers.dxdfir collection

Collection-level changes only; the project-wide history lives in the repository
root [CHANGELOG.md](../../../CHANGELOG.md).

## [Unreleased]

### Changed

- **The Windows parser lane is the gowindowlicker sweep; the evtx lane rides its `goevtx` sub-tool.** GoDFIR-toolz ships the parser dozen as ONE multi-tool image now (the bumped gitlink's manifest stands at 8 images; the `.NET` per-tool lane is retired there), so `dxdfir_godfir_toolz` declares one `gowindowlicker lick` run over the export — `/output` is the lane root, so every sub-tool writes the same `<out_dir>/<subtool>/<item>/<subtool>.jsonl` tree the retired per-tool runs wrote, `gowxt` riding the sweep like the rest (`dxdfir_godfir_toolz_tools` is gone: content decides) — beside the unchanged `godaemonhunter hunt` run. `dxdfir_evtx` drives the same image's `goevtx` sub-tool under its canonical `GOEVTX_*` block; layout, record shapes and file names are unchanged everywhere. `dxdfir_lane`'s contract validation honours the multi-tool convention those contracts declare: a sub-run may set its selected sub-tool's own `<SUBTOOL>_*` variables, and a `multi-tool` contract always takes a sub-tool — the whole-matrix sweeps (`lick`, `hunt`) included.
- **`dxdfir_lane` gets its own molecule scenario, and every scenario runs offline.** The contract-validation matrix is a committed test: the `goevtx`/`lick` positives assert the built argv (sub-tool dispatch, env rendering, the `/work` tmpfs) against the real gowindowlicker contract at the submodule pin, and four negatives assert each refusal by name (undeclared variables under both contract kinds, a missing and an unknown sub-tool). Every scenario now resolves the build galaxy's role through the submodule on its roles path (the lane preflight includes it, so this was latent everywhere) and disables molecule's online prerun/galaxy dependency — the collection dep IS the git submodule. Proven with `molecule test` green, idempotence included, for `dxdfir_lane` (offline) and for `dxdfir_evtx` end to end: the really-built gowindowlicker image dispatching `goevtx` over a fixture log.
- **Only ansible interacts with the containers — enforced end to end (house strict rule, now in the standards table).** The molecule harness is a committed playbook (`playbooks/dxdfir-molecule.yml`) with `.github/tests/run-molecule.sh` reduced to its launcher and the runner image's Dockerfile a real file (`.github/tests/molecule-runner.Dockerfile`); the smoke test's direct docker preflights are gone — each lane's ansible preflight (daemon check → `ensure_built` → hardened `verify`) is the gate; `dev-scripts/purge-docker.sh` is retired (`dxdfir-cleanup.yml` is the wipe). Read-only daemon observation (the CLI health probe, the TUI containers panel) is the one documented exception.

- **The image inventory and the build logic are the BUILD galaxy's — GoDFIR-toolz supplies both, this collection consumes them.** The submodule's root `images.yml` (all 24 images: the pipeline five, the 12 Windows Go parsers, godaemonhunter, gomount, and the five `.NET` per-tool images as ordinary manifest entries) is the single source of truth; the repo-root copy is deleted, and `dxdfir_images` and CI read the submodule manifest at the gitlink pin (the runtime verify/audit gates below read the same file through the build galaxy). `dxdfir_images`' build path delegates to the build galaxy's `godfir_build` (resolved in place from the submodule via the repo-root `roles_path`, so the gitlink stays the only pin) run over the submodule tree; `tasks/build.yml` and `tasks/preflight.yml` moved there. The hardcoded shell/python image name-list is gone with them: every image self-declares its posture in `/etc/dfir-hardened` and the build gate holds each image to exactly what it declares.
- **The runtime image guard is ansible; `get_sybers_dxdfir.images` is retired.**
  The lane preflight gate and `dxdfir verify-images` run the build galaxy's
  `verify` / `audit` entries (through `dxdfir_images` `tasks_from: verify|audit`,
  which freeze the submodule root) instead of shelling out to
  `python3 -m get_sybers_dxdfir.images --require/--audit`. Same semantics —
  manifest membership on the digest/tag-normalized repo, USER + hardened-label
  contract on the host, the namespace audit with `non_tool_repos` exemptions —
  now from the same manifest and collection that build the images. The whole
  `*_python_path` plumbing (nine roles + the lane skeleton) existed only to
  find the python guard and is gone with it.
- **The build galaxy resolves in place — no installed copy, no tarball, no
  symlink.** `docker/GoDFIR-toolz/roles` is on the repo-root `roles_path`
  (the same mechanism this collection's own roles use), so `godfir_build`
  resolves straight from the submodule checkout at the gitlink pin. CI and
  setup no longer install it on the primary path; a checkout without the
  submodule has setup-environment.sh import the galaxy by `ansible-galaxy`
  from the `.gitmodules` source at the gitlink revision, into the shared
  path `roles_path` also covers as its degraded-only last entry, and
  run-checks asserts the roles_path wiring.
- **Smoke CI builds everything GoDFIR-toolz supplies.** A new `images` job builds the FULL manifest through the build galaxy (hardening asserted on every image, nightly included); the pipeline smoke job keeps its fast goevtx+byakugan path. The stale repo-root `images.yml` path filter is gone — a manifest change arrives as a gitlink bump.

- **Every tool lane runs its container from the GoDFIR-toolz contract, in ansible.** `dxdfir_lane` gained a data-driven builder (`tasks/argv.yml`): a lane declares runs as `{contract, subtool, env, mounts}` and the skeleton turns each into the confined `docker run` (`-e` per declared variable, `-v` per mount, tmpfs for `/tmp` and every unbound optional read-write contract mount, `--network none` unless the contract allows it, `--group-add` for the evidence group), asserting the spec against the contract first. The process step runs the built containers in order, honours the contract's exit table (0/1/3 judged by the summary line, 2 fails) and gates on "output on disk, or nothing to do". `dxdfir_lane_module` / `dxdfir_lane_argv` / `dxdfir_lane_input_checks` / `dxdfir_lane_preflight_extra` are gone; `dxdfir_lane_runs`, `dxdfir_lane_confinement`, `dxdfir_lane_tmpfs_opts` and `dxdfir_lane_exit_ok` are the interface.
- `dxdfir_zeek`, `dxdfir_evtx`, `dxdfir_plaso`, `dxdfir_godfir_toolz`, `dxdfir_signatures`, `dxdfir_memory` and `dxdfir_byakugan` declare their runs from `docker/GoDFIR-toolz/<tool>/contract.yml`; each gained a `dxdfir_<role>_contract` variable and its `_image` default is now empty (the contract's image; set it to pin a digest). Output layouts follow the contracts: `windows_logs/<log>/goevtx.jsonl`, `log2timeline/storage/<source>/<source>.plaso` + `log2timeline/jsonl/<source>/timeline.jsonl`, `godfir-toolz/<tool>/<item>/`, `detections/<subtool>/<item>/`.
- `dxdfir_evtx`: Hayabusa is no longer bolted onto the lane (it is the signatures image's `hayabusa` sub-tool); `dxdfir_evtx_hayabusa*` are gone, `dxdfir_evtx_image_src` is a directory of images.
- `dxdfir_plaso`: `dxdfir_plaso_module` (the mounted psort output module) is gone — psort renders `json_line` (`dxdfir_plaso_output_format`); `dxdfir_plaso_vss` / `_parsers` / `_storage_dir` / `_jsonl_dir` are new.
- `dxdfir_godfir_toolz`: the artefact set is the role's `files/image-export-filter.yaml`; `dxdfir_godfir_toolz_tools` lists the Go tools run over the export.
- `dxdfir_signatures`: `dxdfir_signatures_lanes` accepts `scan` (gomount→goyara over disk images, userspace); `dxdfir_signatures_yara_sources` is a list of `files`/`memory`; rulesets are the image's baked sets unless `dxdfir_signatures_yara_rules` / `_suricata_rules` / `_hayabusa_rules` mount an operator set; Suricata tuning is `dxdfir_signatures_suricata_set` (the per-pcap tuning file and `dxdfir_signatures_fetch` are gone).
- `dxdfir_byakugan`: `build` and `timeline` are contract-driven (`dxdfir_byakugan_derive` / `_stix` / `_timeline_out_dir` / `_timeline_force` new; the single-source `dxdfir_byakugan_in` / `_out` / `_host` / `_artefacts` and `dxdfir_byakugan_module` gone). `verify` runs the engine's `byakugan.verify` through the contracts' argv pass-through — the one declared deviation until the byakugan contract declares a `verify` sub-tool.

### Removed

- **The SOF-ELK path, entirely** — the `dxdfir_deploy_sofelk` and `dxdfir_ingest_sofelk` roles (with molecule scenarios), the `dxdfir-deploy-sofelk` / `dxdfir-ingest-sofelk` playbooks, and the whole `elastic|sofelk` pipeline axis: `dxdfir_<role>_pipeline`, `dxdfir_<role>_elastic_out_dir` and `dxdfir_<role>_sofelk_out_dir` collapse into the one `dxdfir_<role>_out_dir` default (`data_store/processed/<leaf>`), and `dxdfir_stack` drops `dxdfir_stack_name` (the Elastic backend is the only stack). The stack's Filebeat tails the processed tree directly, so no delivery role replaces the sofelk one.

### Changed

- **Every tool image now builds from the GoDFIR-toolz submodule**: the byakugan/plaso/signatures/zeek build items moved into the submodule (repo-root context, one dir per image), `dxdfir_images_context` defaults to `docker/GoDFIR-toolz`, the separate `dxdfir_images_eztools_context` is gone, and the preflight no longer syncs `hardening/harden.yml` into a `docker/hardening/` mirror — every Dockerfile COPYs the canonical copy straight from the shared context. The Elastic stack moved home to `docker/elastic/` (was `stacks/elastic/`).

### Fixed

- The lane preflight **supply-chain guard was a dead no-op**: its `when: item is match('^dxdfir/')` filter predated the `dxdfir/* → get-sybers/*` image rename, so it matched no image and `images.require()` never ran for any lane — the hardened-image gate silently passed everything. Corrected to `^get-sybers/` (require() already no-ops on non-get-sybers images) and refreshed the stale `dxdfir/*` wording in the guard's comments/specs. Also added the two images the `dxdfir_zimmerman` lane actually drives but had omitted from its guard list — `get-sybers/goese` (SRUM) and `get-sybers/goprefetch` (Prefetch) — so all eleven images the processor can run are now guarded (gowxt stays out, deferred #88).

### Removed

- The Kusto/ADX layer — the `dxdfir_deploy_adx`, `dxdfir_ingest_adx` and `dxdfir_detect_adx` roles (with their molecule scenarios) and the `dxdfir-deploy-adx` / `dxdfir-ingest-adx` / `dxdfir-detect-adx` playbooks. The Elastic-native path (`docker/elastic`, the ES|QL/EQL rules-as-code, the CAR->ECS projection) supersedes the emulator; detection is no longer a role.

### Changed

- The `dxdfir_zimmerman` lane and `dxdfir_images` build now run the all-Go Eric Zimmerman tool family: RECmd→`gore`, SBECmd→`gosbe`, LECmd→`gole`, JLECmd→`gojle`, WxTCmd→`gowxt` (joining the already-ported `goamcache`/`goappcompat`/`gomft`/`goevtx`/`gorb`/`goprefetch`/`goese`). `gore`/`gosbe` replay dirty-hive `.LOG1/.LOG2` logs into a writable `/work` tmpfs. Only SQLECmd remains .NET. The "no shell/python" image-hardening assertion was corrected to the Go images' real names.
- The processing roles' pipeline axis is `elastic|sofelk` (was `adx|sofelk`): `dxdfir_<role>_pipeline` defaults to `elastic`, and `dxdfir_<role>_adx_out_dir` is now `dxdfir_<role>_elastic_out_dir` — the same default path (`data_store/processed/<source>`, the tree the CAR lane builds from). `dxdfir_<role>_out_dir` still carries the resolved choice.

### Removed (earlier)

- The Velociraptor lane — `dxdfir_velociraptor` role, the `dxdfir-process-velociraptor` playbook, the ingest source and the `host.VelociraptorJson` table: Velociraptor is no longer part of this project (SRUM/RECmd evidence now comes from the hardened EZ-tool containers directly).

## 0.4.0

- New `dxdfir_images` role: builds the hardened dxdfir/* tool images from in-repo
  Dockerfiles (ansible-only execution, allow-listed run role, uid0 renamed and
  locked, no sudo/su, no package managers, non-root runtime) and verifies the
  contract per build, statically and in-container.
- Processor roles default to the dxdfir/* images; `dxdfir_volatility_symbols_online`
  gates the one legitimate network need.
- Process tasks pass runtime hardening through the shared
  `get_sybers_dxdfir.container` invocation layer.

## 0.3.1

- One pipeline-agnostic `tasks/process.yml` per processor role; the adx|sofelk
  decision is carried by the resolved `dxdfir_<role>_out_dir` default.
- Process tasks run as a guarded `block`; a `rescue` surfaces the processor's
  JSON summary and stderr as one diagnostic. Gates are check-mode-safe.
- Molecule scenarios repaired (local connection, roles path) and runnable via
  the containerised harness (`tests/run-molecule.sh`); idempotence enforced.
- New role vars: `dxdfir_signatures_{stage_dir,vss,yara_sources,suricata_tuning_file}`;
  `dxdfir_evtx_stage_dir` pinned to the canonical shared extraction stage.
- ansible-lint (production profile) adopted; collection metadata completed
  (repository/issues, requires_ansible >= 2.16.0).

## 0.2.0

- Initial collection: one role per evidence source (zeek, velociraptor, evtx,
  volatility, plaso, signatures), deploy/ingest/detect roles, adx and sofelk
  pipelines, argument specs and per-role molecule scenarios.
