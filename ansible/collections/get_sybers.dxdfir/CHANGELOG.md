# Changelog — get_sybers.dxdfir collection

Collection-level changes only; the project-wide history lives in the repository
root [CHANGELOG.md](../../../CHANGELOG.md).

## [Unreleased]

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
