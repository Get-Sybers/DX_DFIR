# dxdfir_evtx

Parse **Windows Event Logs (`.evtx`)** with **goevtx** (the static-Go `.evtx`
parser on go-evtx, built `FROM scratch` from
[`docker/GoDFIR-toolz/goevtx`](https://github.com/Get-Sybers/GoDFIR-toolz/tree/main/goevtx))
into JSON Lines. The role is structure only — it asserts its inputs and declares
the runs, each driven purely by the tool's contract: the shared `dxdfir_lane`
skeleton builds the confined `docker run` from
`docker/GoDFIR-toolz/goevtx/contract.yml` (`-e GOEVTX_*`, `-v` for `/input` and
`/output`), and the image finds every event log under `/input` (by `.evtx`
extension or `ElfFile` signature) and writes one folder per log holding
`goevtx.jsonl` — one record per event (EventId, Level, Provider, Channel,
Computer, EventRecordId, TimeCreated, UserId, SourceFile, Payload). The folder
is the log's path relative to the input dir with separators folded to `_`, so
the source sub-dir (host) stays in the name. No host-side processor.

## Disk images
With `dxdfir_evtx_image_src` set to a directory of disk images, the plaso image's
`image_export` sub-tool runs first (`PLASO_IMAGE_EXPORT_ARTIFACT_FILTERS=WindowsEventLogs`)
and exports the event logs of every image into `dxdfir_evtx_stage_dir`, one
folder per image; goevtx then parses that stage alongside the loose logs. The
stage is the one canonical export the `dxdfir_signatures` hayabusa run reads
too, so an image is exported once for both.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_evtx_evtx_dir` | `<repo>/data_store/raw/logs/winevt` | `.evtx` tree to parse (recursed). |
| `dxdfir_evtx_image_src` | `""` | Optional directory of disk images to export event logs from. |
| `dxdfir_evtx_stage_dir` | `<repo>/data_store/processed/windows_logs/_extracted_evtx` | Where the image exports land. |
| `dxdfir_evtx_vss` | `false` | Export from every Volume Shadow Copy too. |
| `dxdfir_evtx_out_dir` | `<repo>/data_store/processed/windows_logs` | Output base, one folder per log (override to redirect). |
| `dxdfir_evtx_contract` | `<repo>/docker/GoDFIR-toolz/goevtx/contract.yml` | The contract the parse run is built from. |
| `dxdfir_evtx_plaso_contract` | `<repo>/docker/GoDFIR-toolz/plaso/contract.yml` | The contract the export run is built from. |
| `dxdfir_evtx_image` | `""` (the contract's `get-sybers/goevtx:latest`) | Image ref override, e.g. a digest pin. |
| `dxdfir_evtx_plaso_image` | `""` (the contract's `get-sybers/plaso:latest`) | Image ref override for the export step. |
| `dxdfir_evtx_python_path` | `<repo>/python` | PYTHONPATH for the image supply-chain guard (`get_sybers_dxdfir.images`). |
| `dxdfir_evtx_force` | `false` | Reparse logs (and re-export images) that already have output. |

## Idempotence
A log whose `goevtx.jsonl` already exists is skipped by the tool itself, never by
a task `when:`. A first run is `changed=true` (a summary line's `processed > 0`);
a second immediate run is `changed=false`.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-evtx.yml
```

## Testing
The **Molecule** scenario needs a sample `.evtx` (binary; not redistributable),
supplied as an extra-var:
```bash
molecule test -- -e molecule_sample_evtx=/path/Security.evtx
```
