# dxdfir_godfir_toolz

Process **forensic disk images** (and **VM exports**) with the artefact set the
**GoDFIR-toolz** parsers handle — registry (`gore`), jump lists (`gojle`), `.lnk`
(`gole`), Amcache (`goamcache`), AppCompatCache (`goappcompat`), ShellBags
(`gosbe`), Recycle Bin (`gorb`), `$MFT` (`gomft`), SRUM (`goese`) and Prefetch
(`goprefetch`) — every one a Linux-native, static-Go `FROM scratch` image. The
role is structure only — it asserts its inputs and declares the runs, each
driven purely by a tool's contract (`docker/GoDFIR-toolz/<tool>/contract.yml`):
the shared `dxdfir_lane` skeleton builds each confined `docker run` from it. No
host-side processor.

## How it works

1. **Export.** The plaso image's `image_export` sub-tool runs over the image tree
   with the role's filter file (`files/image-export-filter.yaml`, mounted
   read-only and named by `PLASO_IMAGE_EXPORT_FILTER_FILE`) — the godfir-toolz
   artefact set has no named forensic-artifact-definitions entry, so it is
   declared as a plaso YAML collection filter: registry hives
   (SYSTEM/SOFTWARE/SAM/SECURITY + per-user NTUSER.DAT/UsrClass.dat) **with
   their .LOG1/.LOG2 transaction logs**, Amcache, jump lists/`.lnk`, Recycle Bin
   `$I` records, the Windows Timeline database, the SRUM database, Prefetch and a
   resident `$MFT`. One folder per image lands under `_extracted/`.
2. **Parse.** Each Go tool image runs over the whole export tree from its
   contract (`<TOOL>_FORCE`; `/input` ro, `/output` rw, a `/work` tmpfs for the
   dirty-hive replay): every tool content-detects its own artefacts anywhere
   under the tree — the tree holds only the filtered set, never the rest of the
   filesystem — and writes `<out_dir>/<tool>/<item>/<tool>.jsonl`, where
   `<item>` is the artefact's path relative to the export (image name included)
   with separators folded to `_`. The registry-family tools replay each hive's
   `.LOG1/.LOG2` into `/work`.

A tool that finds no artefact of its kind (a non-Windows image) exits 1
(nothing produced); a tool with a failed item exits 3 (partial). Both are
tolerated: the gate is "some tool produced output, or no artefacts were
exported".

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_godfir_toolz_input_dir` | `<repo>/data_store/raw/disk_images` | Disk-image tree, recursed. |
| `dxdfir_godfir_toolz_vm_dir` | `<repo>/data_store/raw/VM_files` | VM export folders; exported when present. |
| `dxdfir_godfir_toolz_out_dir` | `<repo>/data_store/processed/godfir-toolz` | Output base, one folder per tool (override to redirect). |
| `dxdfir_godfir_toolz_stage_dir` | `<out_dir>/_extracted` | The artefact export, one folder per image. |
| `dxdfir_godfir_toolz_toolz_dir` | `<repo>/docker/GoDFIR-toolz` | The submodule root holding every `<tool>/contract.yml`. |
| `dxdfir_godfir_toolz_plaso_contract` | `<toolz_dir>/plaso/contract.yml` | The contract the export runs are built from. |
| `dxdfir_godfir_toolz_filter_file` | `files/image-export-filter.yaml` | The artefact-set filter file. |
| `dxdfir_godfir_toolz_plaso_image` | `""` (the contract's `get-sybers/plaso:latest`) | Image ref override for the export. |
| `dxdfir_godfir_toolz_vss` | `false` | Also export from Volume Shadow Copies. |
| `dxdfir_godfir_toolz_tools` | the ten tools above | The Go tools to run, in order. |
| `dxdfir_godfir_toolz_python_path` | `<repo>/python` | PYTHONPATH for the image supply-chain guard (`get_sybers_dxdfir.images`). |
| `dxdfir_godfir_toolz_force` | `false` | Re-export images and reparse items that already have output. |

## Idempotence
Per item, in each tool: an item whose output already exists is skipped by the
tool itself, never by a task `when:`; an image already exported is not re-pulled.
`dxdfir_godfir_toolz_force` reruns both.

## Not yet run: gowxt
`get-sybers/gowxt` (Windows Timeline, `ActivitiesCache.db`) is built and has a
contract, but is not in `dxdfir_godfir_toolz_tools` until validated against a
real database (issue #88). Add it to the list to run it.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-godfir-toolz.yml
```

## Testing
The **Molecule** scenario needs a small parseable Windows image (large/binary —
not shipped):
```bash
molecule test -- -e molecule_sample_image=/path/tiny.raw
```
