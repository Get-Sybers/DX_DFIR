# dxdfir_plaso

Process **forensic disk images**, **VM exports** and (opt-in) **loose artefact
trees** with **Plaso** (log2timeline + psort) into JSON Lines. The role is
structure only — it asserts its inputs and declares the runs, each driven purely
by the plaso image's contract (`docker/GoDFIR-toolz/plaso/contract.yml`): the
shared `dxdfir_lane` skeleton builds the confined `docker run` from it
(`-e PLASO_<SUBTOOL>_*`, `-v` for `/input` and `/output`, a `/work` tmpfs) and
hands the multi-tool image its sub-tool name and nothing else. No host-side
processor, no mounted output module.

## Runs
1. `plaso-entry log2timeline` over `dxdfir_plaso_input_dir` — and over
   `dxdfir_plaso_vm_dir` / `dxdfir_plaso_loose_dir` when they exist — into
   `<out_dir>/`: one folder per source holding `<source>.plaso` +
   `log2timeline.log`. Every disk image under the tree and every immediate
   sub-directory (a staged tree) is an item.
2. `plaso-entry psort` over that same tree, into it: `timeline.jsonl` (the
   `json_line` output module) + `psort.log` rendered **beside** the storage
   file — one `<source>/` folder per image, nothing else.

Each sub-tool discovers, batches and skips its own items; `<source>` is the
input path relative to the input dir with separators folded to `_`.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_plaso_input_dir` | `<repo>/data_store/raw/disk_images` | Disk-image tree, recursed. |
| `dxdfir_plaso_vm_dir` | `<repo>/data_store/raw/VM_files` | VM export folders (one per VM); processed when present. |
| `dxdfir_plaso_loose_dir` | `""` | Loose-artefact trees (one folder per host); opt-in. |
| `dxdfir_plaso_collection` | `""` | The collection the run is scoped to (the CLI passes it); the output lands one level down. |
| `dxdfir_plaso_out_dir` | `<repo>/data_store/processed/log2timeline[/<collection>]` | Output base: one `<source>/` folder per image (`<source>.plaso`, `log2timeline.log`, `timeline.jsonl`, `psort.log`). |
| `dxdfir_plaso_contract` | `<repo>/docker/GoDFIR-toolz/plaso/contract.yml` | The contract the runs are built from. |
| `dxdfir_plaso_image` | `""` (the contract's `get-sybers/plaso:latest`) | Image ref override, e.g. a digest pin. |
| `dxdfir_plaso_vss` | `true` | log2timeline: process every VSS store (`PLASO_LOG2TIMELINE_VSS`). |
| `dxdfir_plaso_parsers` | `""` | log2timeline: parser preset/list (`PLASO_LOG2TIMELINE_PARSERS`). |
| `dxdfir_plaso_output_format` | `json_line` | psort: the output module (`PLASO_PSORT_OUTPUT_FORMAT`). |
| `dxdfir_plaso_force` | `false` | Rerun sources that already have a storage file / rendered timeline. |

## Idempotence
A source whose `.plaso` storage file (log2timeline) or `timeline.jsonl` (psort)
already exists is skipped by the sub-tool itself, never by a task `when:`.
Per-source failures are tolerated (a source yielding 0 events): the gate is "some
timeline was produced, or there were no sources".

## Example
```bash
ansible-playbook playbooks/dxdfir-process-plaso.yml
```

## Testing
The **Molecule** scenario needs a small parseable image (large/binary — not
shipped):
```bash
molecule test -- -e molecule_sample_image=/path/tiny.raw
```
