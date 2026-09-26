# dxdfir_godfir_toolz

Process **forensic disk images** (and **VM exports**) with the two
**GoDFIR-toolz** artefact matrices — **`gowindowlicker`**, the Windows parser
dozen (registry `gore`, jump lists `gojle`, `.lnk` `gole`, Amcache
`goamcache`, AppCompatCache `goappcompat`, ShellBags `gosbe`, Recycle Bin
`gorb`, `$MFT` `gomft`, SRUM `goese`, Prefetch `goprefetch`, Windows Timeline
`gowxt`, event logs `goevtx`) as sub-tools of **one** static-Go `FROM scratch`
image, run as its `lick` sweep — plus **`godaemonhunter`**, the Linux
daemon-parser matrix (journal, auditd, logins, syslog, units, cron, shells,
trash, sysctl) in **one** image, run as its `hunt` sub-tool: every stream, the
default. The role is structure only — it asserts its inputs and declares the
runs, each driven purely by a tool's contract
(`docker/GoDFIR-toolz/<tool>/contract.yml`): the shared `dxdfir_lane` skeleton
builds each confined `docker run` from it. No host-side processor.

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
2. **The Windows matrix.** `gowindowlicker lick` runs **once** over the whole
   export tree from its contract (`GOWINDOWLICKER_FORCE`; `/input` ro,
   `/output` rw — the lane root — and a `/work` tmpfs for the dirty-hive
   replay): every parser sub-tool content-detects its own artefacts anywhere
   under the tree — the tree holds only the filtered set, never the rest of
   the filesystem — and writes `<out_dir>/<subtool>/<item>/<subtool>.jsonl`,
   where `<item>` is the artefact's path relative to the export (image name
   included) with separators folded to `_`: the same tree the retired
   per-tool images wrote. The registry-family sub-tools replay each hive's
   `.LOG1/.LOG2` into `/work`; the Windows Timeline database rides the sweep
   like the rest (#88). Event logs are not in this lane's filter — `.evtx`
   has the `dxdfir_evtx` lane's own export — so `goevtx` simply finds
   nothing here.
3. **The Linux matrix.** `godaemonhunter hunt` runs once over the same tree:
   Layer 1 (gohost, gousers, gonetwork) builds the image's knowledge store
   under `<out_dir>/godaemonhunter/knowledge/`, then every daemon parser runs
   enriched by it (resolved names beside native ids, the `Host` block, the
   host's timezone applied) — the layering is internal, one aggregate summary
   line. Over a Windows-only export it finds nothing and exits 1, tolerated
   like any other tool; it lights up when Linux content reaches the tree (the
   native `linux-core` export is the GoDFIR-toolz plan's P2).

A matrix that finds no artefact of its kind (gowindowlicker over a non-Windows
image — or godaemonhunter over a non-Linux export) exits 1
(nothing produced); one with a failed item exits 3 (partial). Both are
tolerated: the gate is "some tool produced output, or no artefacts were
exported".

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_godfir_toolz_input_dir` | `<repo>/data_store/raw/disk_images` | Disk-image tree, recursed. |
| `dxdfir_godfir_toolz_vm_dir` | `<repo>/data_store/raw/VM_files` | VM export folders; exported when present. |
| `dxdfir_godfir_toolz_out_dir` | `<repo>/data_store/processed/godfir-toolz` | Output base, one folder per sub-tool (override to redirect). |
| `dxdfir_godfir_toolz_stage_dir` | `<out_dir>/_extracted` | The artefact export, one folder per image. |
| `dxdfir_godfir_toolz_toolz_dir` | `<repo>/docker/GoDFIR-toolz` | The submodule root holding every `<tool>/contract.yml`. |
| `dxdfir_godfir_toolz_plaso_contract` | `<toolz_dir>/plaso/contract.yml` | The contract the export runs are built from. |
| `dxdfir_godfir_toolz_filter_file` | `files/image-export-filter.yaml` | The artefact-set filter file. |
| `dxdfir_godfir_toolz_plaso_image` | `""` (the contract's `get-sybers/plaso:latest`) | Image ref override for the export. |
| `dxdfir_godfir_toolz_vss` | `false` | Also export from Volume Shadow Copies. |
| `dxdfir_godfir_toolz_force` | `false` | Re-export images and reparse items that already have output. |

There is no tool list to configure: which parsers fire is decided by content —
each matrix run fans out to every sub-tool internally, and a sub-tool with no
artefact of its kind contributes nothing.

## Idempotence
Per item, in each sub-tool: an item whose output already exists is skipped by
the tool itself, never by a task `when:`; an image already exported is not
re-pulled. `dxdfir_godfir_toolz_force` reruns both.

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
