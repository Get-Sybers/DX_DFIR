# Processing lanes

A **lane** processes one family of evidence with one specialist tool. There are six.
Each is an Ansible role that delegates the run to a shared skeleton and calls a Python
processor, which runs a hardened container and writes deterministic output.

`dxdfir process [COLLECTION] [LANE]` picks the lane; `all` runs every lane that has
evidence. See the [command reference](../getting-started/commands.md#processing).

## The six lanes

| Lane | Evidence in | Tool | Container | Output under `data_store/processed/` |
|---|---|---|---|---|
| **zeek** | Packet captures (`data_store/raw/pcaps`) | Zeek → JSON logs | `get-sybers/zeek` | `zeek/<capture>/*.json` |
| **evtx** | Windows event logs (`raw/logs/winevt`, or pulled from disk images) | [goevtx](https://github.com/Get-Sybers/GoDFIR-toolz) (static-Go `.evtx` parser) + Hayabusa Sigma | `get-sybers/goevtx` | `windows_logs/<host>/*_EvtxECmd_Output.json` |
| **volatility** | Memory images (`raw/memory`) | [PIIAT-Mem](https://github.com/Get-Sybers/PIIAT-Mem) (Volatility 3) | `get-sybers/piiat-mem` | `volatility/<image>/plugins/*.jsonl` |
| **plaso** | Disk images + VM exports (`raw/disk_images`, `raw/VM_files`) | Plaso (`log2timeline` → `psort`) | `get-sybers/plaso` | `log2timeline/<host>.jsonl` |
| **godfir-toolz** | Same disk-image family | [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) parsers (gore, gomft, goese, goprefetch…) | `get-sybers/<tool>` + `get-sybers/plaso` for extraction | `godfir-toolz/<host>/` |
| **signatures** | PCAPs · disk · memory · `.evtx` | YARA · Suricata replay · Hayabusa Sigma (three sub-lanes) | `get-sybers/yara`, `get-sybers/suricata` | `signatures/<sub-lane>/` |

Evidence is discovered by **magic bytes first**, extension as a fallback — so a
mislabelled `.pcap` is still recognised. Every tool runs in a
[hardened container](../Containers.md): fixed non-root user, no network, read-only
rootfs.

## The shared lane skeleton

Each lane role (`dxdfir_zeek`, `dxdfir_evtx`, …) carries only its own per-lane piece —
asserting its inputs and building the processor argv — then delegates the run to the
shared **`dxdfir_lane`** role. That skeleton is the same for every lane:

```
preflight ──▶ process ──▶ verify/gate
    │            │              │
 docker up?   run the       assert failed == 0,
 inputs?      processor,     find output on disk,
 image ok?    changed_when   surface the JSON summary
             from summary    on failure (rescue)
```

This is the house rule in action: **the role groups, the playbook decides, and
idempotence lives in the Python processor** — a source whose output already exists is
skipped in the processor, not in an Ansible `when:`. See
[Ansible standards](../reference/ansible-standards.md).

## Output

Every lane writes the processed tree the [CAR pipeline](car-pipeline.md)
builds from and [Filebeat](the-stack.md) ships.

## Collections

A **collection** groups raw evidence into one named, registered set so the whole
pipeline can be scoped to it. Physically it's a folder under
`data_store/raw/collections/<NAME>/` with the lane subdirs, plus control files: a SQLite
registry (`.registry.db`), a `.collection` marker, a log, and a `.collection.hashes`
SHA-1 manifest.

The **dropzone** is `data_store/raw/sort/`. Drop a mixed pile there and:

```bash
dxdfir register case-a          # promote data_store/raw/sort/case-a/ → a tracked collection + hash it
dxdfir collection sort case-a   # magic-byte-sort loose files into the lane subdirs
dxdfir collection select case-a # make it the active target
```

The registry read path (`collection list`/`lanes`/`state`) is native Go — no subprocess
— and shares the SQLite schema as its contract with the Python writers. Full command
list: [commands → evidence and collections](../getting-started/commands.md#evidence-and-collections).
