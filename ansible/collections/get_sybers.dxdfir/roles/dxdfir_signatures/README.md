# dxdfir_signatures

Run the **YARA**, **Suricata** and **Hayabusa** detection lanes over the evidence and
land their native events as JSON Lines for the Elastic-native or SOF-ELK pipeline. The role is
structure only — it asserts inputs, runs a preflight (docker, the `data_store`
anchor, the module), then invokes the `get_sybers_dxdfir.signatures` Python processor
as a **single action**. One `<lane>/` folder of detections under the output base.

## Lanes
| Lane | Input | Output |
|---|---|---|
| `yara` | loose files under `raw/other_raw_data/`; disk images under `raw/disk_images/` (mounted read-only in place — needs `/dev/fuse` + `ewfmount`/`ntfs-3g` on the host, nothing extracted); memory images under `raw/memory/` (Volatility 3 `windows.vadyarascan`) | `yara/matches.jsonl`, `yara/disk.jsonl`, `yara/memory.jsonl` |
| `suricata` | every capture the zeek processor discovers (magic-first, odd extensions included) | `suricata/<name>.eve.jsonl` (alert + context event types) |
| `hayabusa` | loose Windows Event Logs (`.evtx`) under `raw/` **and** disk images (staged `image_export` extraction shared with the evtx processor) | `hayabusa/timeline.jsonl` |

> **Standalone and reuse-aware.** No processor run is needed first: each lane reads
> raw evidence directly. Disk-image EVTX for Hayabusa are staged once (default:
> the evtx processor's own stage under `processed/windows_logs/_extracted_evtx`)
> and reused by both the detection lane and the processor — an image is never
> extracted twice.

> **Mounting.** The YARA `disk` source needs `/dev/fuse` on the host (an LXC
> blocks it by default); without it the source records a note and produces
> nothing — it never extracts files out of an image. The `memory` source needs
> the Volatility 3 container image and pre-seeded symbols.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_signatures_pipeline` | `elastic` | `elastic` or `sofelk` — selects the output destination (the **playbook** decides this). |
| `dxdfir_signatures_elastic_out_dir` | `<repo>/data_store/processed/signatures` | Elastic-path output base. |
| `dxdfir_signatures_sofelk_out_dir` | `<repo>/data_store/processed/sofelk/signatures` | SOF-ELK-path output base. |
| `dxdfir_signatures_lanes` | `[]` (all) | Lanes to run — any of `yara`, `suricata`, `hayabusa`. |
| `dxdfir_signatures_stage_dir` | `""` (evtx processor's stage) | Where the hayabusa lane stages disk-image EVTX extractions; already-staged images are reused, never re-extracted. |
| `dxdfir_signatures_vss` | `false` | Include Volume Shadow Copies when staging disk images. |
| `dxdfir_signatures_yara_sources` | `""` (all) | YARA sources to run — comma list of `files,disk,memory`. |
| `dxdfir_signatures_suricata_tuning_file` | `""` (`<repo>/data_store/dependencies/suricata-tuning.conf`) | Per-pcap Suricata tuning template — see below. |

## Suricata tuning (per-pcap template)

Every `vars.*` variable the stock suricata.yaml defines is **consolidated** in
one registry (`suricata.SURICATA_VARS`) — kind, stock default, and how the lane
automates it — and the template file is generated from it, so the operator sees
the full set in one place. The lane manages tuning through that
**operator-editable INI template**
(`data_store/dependencies/suricata-tuning.conf` by default):

- **First run** writes the template (comments only — including the consolidated
  variable table) and, because it holds no real sections, **auto-detects** the
  vars from each capture's own traffic (a cheap default-vars pass first) and
  **records** the derived values as a section per capture.
  **Every var automates**, from the traffic each host sends and receives:
  `HOME_NET`/`EXTERNAL_NET` from the observed private supernets and their
  complement; the address vars from the flow endpoint playing that role —
  receiver for `*_SERVERS`/`*_SERVER` (HTTP/SMTP/DNS/SQL/TELNET/AIM/DC and the
  SCADA server groups), initiator for the SCADA `*_CLIENT` groups — where the
  flow shows parser evidence (its app-layer protocol) or well-known-port
  evidence (e.g. 1433/3306/5432/1521 for SQL, 88 for a DC, 23 telnet, 5190
  AIM), scoped home/external to match each var's stock default; the port vars
  from the ports a parsed protocol was actually spoken on (flow `app_proto`
  included, so non-standard ports are caught) or — where no parser exists
  (ORACLE/GENEVE/VXLAN/TEREDO) — the well-known ports that actually carried
  traffic. `SHELLCODE_PORTS` becomes `!$HTTP_PORTS`; `FILE_DATA_PORTS` follows
  the derived `HTTP_PORTS` by reference. A var with nothing observed keeps its
  stock default.
- **Edit the recorded sections** (or add `[global]`) and re-run with
  `dxdfir_signatures_force=true` to apply your values. A capture without a section
  still auto-detects and gets recorded.
- **An invalid file** (bad INI, a key that isn't a consolidated var, whitespace
  inside an address group) falls back to auto-detect; the broken file is
  preserved beside the fresh one as `*.invalid`.
- Tuning is **reset for every pcap** — a value derived from or configured for one
  capture never leaks into the next. The per-capture decision (values, source:
  cli/file/auto) is echoed in the run summary under `tuning`.
| `dxdfir_signatures_fetch` | `false` | Provision rules when online: the YARA lane fetches the pinned DetectRaptor ruleset into `yara-rules/detectraptor/` (sha256-verified, merged, idempotent) when it has no rules yet. The other lanes still record a note when their deps are missing — supply those rules/binaries yourself. |
| `dxdfir_signatures_python_path` | `<repo>/python` | PYTHONPATH to `get_sybers_dxdfir` (in-repo runs). |
| `dxdfir_signatures_force` | `false` | Regenerate lane outputs that already exist. |

## Rules / binaries
Operator-supplied: YARA rules under `data_store/dependencies/yara-rules`, ET Open
under `.../suricata-rules`, the Hayabusa binary under `.../hayabusa`.
`dxdfir_signatures_fetch` / `--fetch` provisions the DetectRaptor YARA ruleset when
the tree has no rules yet (see `docs/Signature-Rules.md` → *DetectRaptor
content*); Suricata rules and the Hayabusa binary are provisioned by the operator
(`suricata-update` / the pinned Hayabusa release). A lane with no rules/inputs
notes it and produces nothing (not a failure).

## Idempotence
A lane whose output already exists is skipped — the skip lives in the Python
processor, never in a task `when:`. The verify gate tolerates a zero-detection run
(no rules/inputs) but surfaces real Suricata failures.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-signatures.yml -e dxdfir_signatures_pipeline=elastic
# one lane:
ansible-playbook playbooks/dxdfir-process-signatures.yml -e '{"dxdfir_signatures_lanes":["yara"]}'
```

## Testing
Python unit tests cover the pure parsing logic (YARA text → match JSONL incl.
strings/offsets, `vadyarascan` → match JSONL, disk-mount/vadyarascan argv
construction and `mmls` offset parsing, Suricata EVE filtering/annotation,
Hayabusa tagging, binary discovery). The **Molecule** scenario runs the **yara lane
live** against a fixture rule + matching sample (needs the hardened `dxdfir/yara`
image — `playbooks/dxdfir-build-images.yml`):
converge → idempotence → verify the recorded match.
