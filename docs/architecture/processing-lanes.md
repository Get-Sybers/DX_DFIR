# Processing lanes

A **lane** processes one family of evidence with one specialist tool, and is named
after it. There are six.
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

Every lane writes `data_store/processed/<tool>/[<collection>/]<host>/…`: one leaf
per tool, a collection-scoped run one level below it, one folder per **host** — the
evidence item: a disk image, a capture, a memory image, a folder of loose logs
staged as `logs/<os>/<host>/` — and the tool's own items under that.

| Lane (aliases) | Evidence in | Tool | Container(s) | Output under `data_store/processed/` |
|---|---|---|---|---|
| **zeek** | Packet captures (`data_store/raw/pcaps`) | Zeek → JSON logs | `get-sybers/zeek` | `zeek/[<collection>/]<capture>/*.json` + `zeek.jsonl` |
| **gowindowlicker** (`windowlicker`, `lick`, `evtx`) | Windows hosts: loose event logs (`raw/logs/winevt/<host>/`) and disk images + VM exports (`raw/disk_images`, `raw/VM_files`), exported once by the shared [`dxdfir_export`](../../ansible/collections/get_sybers.dxdfir/roles/dxdfir_export/README.md) step | The [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) Windows parsers — every one a sub-tool of one static-Go image: goevtx, gore, gosbe, gomft, goprefetch, goese, goamcache, goappcompat, gorb, gole, gojle, gowxt — one run per (parser, host) | `get-sybers/gowindowlicker` (+ `get-sybers/plaso` for the export) | `windowlicker/[<collection>/]<subtool>/<host>/<item>/<subtool>.jsonl` |
| **godaemonhunter** (`daemonhunter`, `hunt`) | Linux hosts: loose logs / root trees (`raw/logs/linux/<host>/`) and the same disk-image family through the shared export | The GoDFIR-toolz Linux matrix: Layer 1 (gohost, gousers, gonetwork) into a per-host knowledge store, then the daemon parsers (gojournal, goauditd, gowtmp, gosyslog, gounit, gocron, goshell, gotrash, goctl) enriched by it — one run per (parser, host) | `get-sybers/godaemonhunter` (+ `get-sybers/plaso` for the export) | `daemonhunter/[<collection>/]<subtool>/<host>/<item>/<subtool>.jsonl` + `knowledge/<host>/` |
| **anamnesis** (`memory`) | Memory images (`raw/memory`) | [anamnesis](https://github.com/Get-Sybers/Anamnesis) (MemProcFS) | `get-sybers/anamnesis` | `anamnesis/[<collection>/]<image>/plugins/*.jsonl` + `car.db` |
| **plaso** (`log2timeline`, `psort`) | Disk images + VM exports | Plaso (`log2timeline` → `psort` sub-tools) | `get-sybers/plaso` | `log2timeline/[<collection>/]<host>/<host>.plaso` + `timeline.jsonl`, side by side |
| **signatures** | loose files · memory · PCAPs · event-log hosts · disk images (+ their export) | YARA · Suricata replay · Hayabusa Sigma · gomount→goyara disk scan (four sub-tools of one image) | `get-sybers/signatures` | `detections/{yara,suricata,hayabusa}/[<collection>/]<host>/` |

`godfir-toolz`, the retired lane that ran both matrices, is a group: it runs
`gowindowlicker` + `godaemonhunter`. Disk images are exported once into the shared
stage `processed/_extracted/[<collection>/]<image>/export/` — the artefact set
(registry hives + transaction logs, Amcache, jump lists, `$MFT`, Prefetch, SRUM,
the event logs, the Linux core) in one filter — by whichever consuming lane runs
first; the others find every image done and skip. The stage is `_`-prefixed:
never a CAR source, never shipped.

Each tool discovers its items by **content first** (magic bytes / signatures),
extension as a fallback — so a mislabelled `.pcap` is still recognised. Every tool
runs in a [hardened container](../Containers.md): fixed non-root user, no network,
read-only rootfs.

## The shared lane skeleton

Each lane role (`dxdfir_zeek`, `dxdfir_gowindowlicker`, …) carries only its own per-lane piece —
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
SHA-1 manifest. `dxdfir process <NAME> <lane>` passes the role its collection subdirs
as inputs and `dxdfir_<lane>_collection=<NAME>` for the output, so everything the
run writes lands one level below the tool's leaf (`processed/<tool>/<NAME>/…`) and
the CAR engine names every store after that path — two cases never share one.

The **dropzone** is `data_store/raw/sort/`. Drop a mixed pile there and:

```bash
dxdfir register case-a          # promote data_store/raw/sort/case-a/ → a tracked collection + hash it
dxdfir sort case-a              # magic-byte-sort loose files into the lane subdirs
dxdfir select case-a            # make it the active target
```

The registry read path (`list collections`, the lane and state reads) is native Go — no subprocess
— and shares the SQLite schema as its contract with the Python writers. Full command
list: [commands → evidence and collections](../getting-started/commands.md#evidence-and-collections).
