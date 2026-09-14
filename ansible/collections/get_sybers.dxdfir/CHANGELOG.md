# Changelog — get_sybers.dxdfir collection

Collection-level changes only; the project-wide history lives in the repository
root [CHANGELOG.md](../../../CHANGELOG.md).

## [Unreleased]

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
