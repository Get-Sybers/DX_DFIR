# Processing lanes

A **lane** processes one family of evidence with one specialist tool. There are six.
Each is an Ansible role that declares one or more runs of a
[GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) tool image and delegates
them to a shared skeleton, which builds each confined `docker run` purely from the
tool's `contract.yml` — `-e` for its environment variables, `-v` for its mounts —
and gates on the single JSON summary line the container prints. The container
discovers its inputs, batches over them, skips items that already have valid output
and writes deterministic output; no host-side processor exists.

`dxdfir process [COLLECTION] [LANE]` picks the lane; `all` runs every lane that has
evidence. See the [command reference](../getting-started/commands.md#processing).

## The six lanes

| Lane | Evidence in | Tool | Container(s) | Output under `data_store/processed/` |
|---|---|---|---|---|
| **zeek** | Packet captures (`data_store/raw/pcaps`) | Zeek → JSON logs | `get-sybers/zeek` | `zeek/<capture>/*.json` + `zeek.jsonl` |
| **evtx** | Windows event logs (`raw/logs/winevt`, or exported from disk images by the plaso image) | [goevtx](https://github.com/Get-Sybers/GoDFIR-toolz) (static-Go `.evtx` parser) | `get-sybers/goevtx` (+ `get-sybers/plaso` for the export) | `windows_logs/<log>/goevtx.jsonl` |
| **memory** | Memory images (`raw/memory`) | [anamnesis](https://github.com/Get-Sybers/Anamnesis) (MemProcFS) | `get-sybers/anamnesis` | `memory/<image>/plugins/*.jsonl` + `car.db` |
| **plaso** | Disk images + VM exports (`raw/disk_images`, `raw/VM_files`) | Plaso (`log2timeline` → `psort` sub-tools) | `get-sybers/plaso` | `log2timeline/storage/<source>/<source>.plaso`, `log2timeline/jsonl/<source>/timeline.jsonl` |
| **godfir-toolz** | Same disk-image family | [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) parsers (gore, gomft, goese, goprefetch…) over the plaso image's artefact export, plus **godaemonhunter** — the Linux daemon-parser matrix in one image, run as `hunt` (Layer-1 knowledge store → enriched daemon parsers) over the same tree | `get-sybers/<tool>` + `get-sybers/godaemonhunter` + `get-sybers/plaso` for the export | `godfir-toolz/<tool>/<item>/<tool>.jsonl`; the Linux tree under `godfir-toolz/godaemonhunter/` (`knowledge/` + one dir per daemon parser) |
| **signatures** | loose files · memory · PCAPs · `.evtx` · disk images | YARA · Suricata replay · Hayabusa Sigma · gomount→goyara disk scan (four sub-tools of one image) | `get-sybers/signatures` | `detections/<sub-tool>/<item>/` |

Each tool discovers its items by **content first** (magic bytes / signatures),
extension as a fallback — so a mislabelled `.pcap` is still recognised. Every tool
runs in a [hardened container](../Containers.md): fixed non-root user, no network,
read-only rootfs.

## The shared lane skeleton

Each lane role (`dxdfir_zeek`, `dxdfir_evtx`, …) carries only its own per-lane piece —
asserting its inputs and declaring its runs (`{contract, subtool, env, mounts}`) —
then delegates to the shared **`dxdfir_lane`** role. That skeleton is the same for
every lane:

```
build ──────────▶ preflight ──────▶ process ──────▶ verify/gate
  │                  │                 │                │
 read the         docker up?      run each          assert failed == 0,
 contract,        image built +   container in      find output on disk,
 assert the       hardened?       order; changed    surface every summary
 spec fits it,                    when its summary  + stderr on failure
 build the                        says processed>0  (rescue)
 confined argv
```

The confinement every run gets: `--cap-drop ALL --security-opt no-new-privileges
--pids-limit 512 --read-only`, a tmpfs for `/tmp` and every optional read-write
mount the contract declares (the tool's `/work` scratch), `--network none` unless
the contract allows it and the lane asks, and `--group-add` for the group owning
each read-only evidence mount. The contract's exit table is honoured: 0 success,
1 nothing to do, 3 partial (judged by the summary line and the lane's gate), 2
config error (fails).

This is the house rule in action: **the role groups, the playbook decides, and
idempotence lives in the tool container** — an item whose output already exists is
skipped by the tool, not in an Ansible `when:`. See
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
dxdfir sort case-a              # magic-byte-sort loose files into the lane subdirs
dxdfir select case-a            # make it the active target
```

The registry read path (`list collections`, the lane and state reads) is native Go — no subprocess
— and shares the SQLite schema as its contract with the Python writers. Full command
list: [commands → evidence and collections](../getting-started/commands.md#evidence-and-collections).
