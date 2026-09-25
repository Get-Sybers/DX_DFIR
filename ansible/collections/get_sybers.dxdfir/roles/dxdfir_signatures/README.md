# dxdfir_signatures

Run the **YARA**, **Suricata**, **Hayabusa** and **disk-scan** detection sub-tools
over the evidence and land their native events as JSON Lines. The role is
structure only — it asserts its inputs and declares the runs, each driven purely
by the signatures image's contract (`docker/GoDFIR-toolz/signatures/contract.yml`):
the shared `dxdfir_lane` skeleton builds the confined `docker run` from it
(`-e SIGNATURES_<SUBTOOL>_*`, `-v` for `/input` and `/output`, tmpfs for `/work`
and suricata's `/var/run` + `/var/log`) and hands the multi-tool image its
sub-tool name and nothing else. No host-side processor.

## Sub-tools
| Sub-tool | Input (a run per tree that exists) | Output under `detections/` |
|---|---|---|
| `yara` | loose files under `raw/other_raw_data/` (every immediate child is a target); memory images under `raw/memory/` (scanned directly) | `yara/files/<item>/yara.jsonl`, `yara/memory/<item>/yara.jsonl` |
| `suricata` | every `*.pcap`/`*.pcapng`/`*.cap` under `raw/pcaps/` | `suricata/<item>/eve.json` (+ suricata's logs, `suricata.jsonl` index) |
| `hayabusa` | every `.evtx` tree: `raw/logs/winevt/` and the evtx lane's disk-image export (`processed/windows_logs/_extracted_evtx/`) | `hayabusa/<item>/timeline.jsonl` (+ `hayabusa.jsonl` index) |
| `scan` | every disk image under `raw/disk_images/`, streamed by gomount through goyara in userspace — no `/dev/fuse`, nothing mounted on the host | `scan/<item>/scan.jsonl` |

> **Standalone and reuse-aware.** No processor run is needed first: each
> sub-tool reads raw evidence directly. Disk-image event logs reach hayabusa
> through the evtx lane's one canonical export, so an image is exported once for
> both lanes. `<item>` is the input path relative to the tree with separators
> folded to `_`.

## Rules
The image bakes its rulesets: the DetectRaptor YARA merge (yara + scan), the ET
Open Suricata merge, hayabusa's default Sigma set. An operator ruleset is
mounted read-only and named to the sub-tool by its `*_RULES` variable
(`dxdfir_signatures_yara_rules` / `_suricata_rules` / `_hayabusa_rules`) — see
[Signature-Rules](../../../../../docs/Signature-Rules.md).

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_signatures_out_dir` | `<repo>/data_store/processed/detections` | Output base, one folder per sub-tool. |
| `dxdfir_signatures_lanes` | `[]` (all) | Sub-tools to run — any of `yara`, `suricata`, `hayabusa`, `scan`. |
| `dxdfir_signatures_yara_sources` | `[files, memory]` | The yara sub-tool's sources. |
| `dxdfir_signatures_files_dir` | `<repo>/data_store/raw/other_raw_data` | Loose files for yara. |
| `dxdfir_signatures_memory_dir` | `<repo>/data_store/raw/memory` | Memory images for yara. |
| `dxdfir_signatures_pcap_dir` | `<repo>/data_store/raw/pcaps` | Captures for suricata. |
| `dxdfir_signatures_evtx_dir` | `<repo>/data_store/raw/logs/winevt` | Loose `.evtx` for hayabusa. |
| `dxdfir_signatures_evtx_stage_dir` | `<repo>/data_store/processed/windows_logs/_extracted_evtx` | The evtx lane's image export, for hayabusa. |
| `dxdfir_signatures_disk_dir` | `<repo>/data_store/raw/disk_images` | Disk images for scan. |
| `dxdfir_signatures_yara_rules` | `""` (baked) | Operator YARA ruleset file (yara + scan). |
| `dxdfir_signatures_suricata_rules` | `""` (baked) | Operator `suricata.rules` file. |
| `dxdfir_signatures_hayabusa_rules` | `""` (baked) | Operator Sigma rules directory. |
| `dxdfir_signatures_suricata_set` | `""` | Suricata `--set` tuning entries (`SIGNATURES_SURICATA_SET`), e.g. `vars.address-groups.HOME_NET=[10.0.0.0/8]`. |
| `dxdfir_signatures_hayabusa_profile` | `""` (verbose) | hayabusa output profile. |
| `dxdfir_signatures_scan_filter` | `""` (every file) | gomount `--filter` glob for scan. |
| `dxdfir_signatures_contract` | `<repo>/docker/GoDFIR-toolz/signatures/contract.yml` | The contract the runs are built from. |
| `dxdfir_signatures_image` | `""` (the contract's `get-sybers/signatures:latest`) | Image ref override, e.g. a digest pin. |
| `dxdfir_signatures_force` | `false` | Rescan items that already have output. |

## Idempotence
An item whose output already exists is skipped by the sub-tool itself, never by a
task `when:`. A sub-tool with nothing to scan (exit 1) or a failed item (exit 3)
is tolerated; the gate is "some detection output landed, or there was nothing to
scan". An evidence tree that does not exist declares no run; with none present
for the selected sub-tools the role notes it and does nothing.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-signatures.yml
# one sub-tool:
ansible-playbook playbooks/dxdfir-process-signatures.yml -e '{"dxdfir_signatures_lanes":["yara"]}'
```

## Testing
The **Molecule** scenario runs the **yara sub-tool live** over a fixture rule +
matching sample (needs the hardened `get-sybers/signatures` image —
`playbooks/dxdfir-build-images.yml`): converge → idempotence → verify the recorded
match.
