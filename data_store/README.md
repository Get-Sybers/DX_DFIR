# 📂 `data_store`

All raw and processed forensic data for the **DX_DFIR pipeline** lives here.
Everything under `data_store/` is gitignored deny-by-default — read
[Before You Run Anything](/README.md#before-you-run-anything) before you commit.

---

## 📁 Directory Structure

The full annotated tree (including the analysis backend) is in
[Dir-Structure.md](/docs/Dir-Structure.md); this is the evidence-side view.

```bash
data_store/
   ├── raw/                        # Unprocessed evidence — the lanes defined in evidence-taxonomy/
   │   ├── pcaps/                  # Packet captures (.pcap, .pcapng)
   │   ├── logs/winevt/<host>/     # Windows event logs, one folder per host
   │   ├── logs/linux/<host>/      # Linux logs / staged root trees, one folder per host
   │   ├── logs/macOS/<host>/      # macOS logs (staged; no lane reads them yet)
   │   ├── disk_images/            # Disk images (.E01, .raw/.dd, .vmdk, …)
   │   ├── VM_files/               # VMware VM exports (one folder per VM)
   │   ├── memory/                 # Memory captures
   │   ├── filesystem/documents/   # Documents and loose filesystem artefacts
   │   ├── mobile/                 # Mobile-device extractions
   │   ├── other_raw_data/         # Catch-all; other_raw_data/sql holds SQLite/SQL databases
   │   ├── sort/                   # Dropzone for `dxdfir sort`
   │   └── collections/<name>/     # Registered collections — the same lane subdirs, per case
   │
   ├── dependencies/               # Operator-supplied rulesets/symbols
   │
   └── processed/                  # processed/<tool>/[<collection>/]<host>/… — what `dxdfir build-car` reads
       ├── zeek/[<collection>/]<capture>/                        # Zeek JSON (conn.json, dns.json, …) + zeek.jsonl
       ├── windowlicker/[<collection>/]<subtool>/<host>/<item>/  # the Windows parsers: goevtx, gore, gomft, goprefetch, goese, …
       ├── daemonhunter/[<collection>/]<subtool>/<host>/<item>/  # the Linux daemon parsers; knowledge/<host>/ is Layer 1
       ├── anamnesis/[<collection>/]<image>/                     # anamnesis (MemProcFS) JSONL per plugin + car.db
       ├── log2timeline/[<collection>/]<host>/                   # <host>.plaso (reusable by Timesketch) + timeline.jsonl, side by side
       ├── detections/{yara,suricata,hayabusa}/[<collection>/]<host>/  # detection JSONL (the disk scan lands under yara/)
       ├── detections/byakugan/                                  # reserved for the engine's own detections
       ├── _extracted/[<collection>/]<image>/export/             # the shared disk-image artefact export (staging, never shipped)
       ├── byakugan/<source>/                                    # the materialised CAR: car_<object>.jsonl (+ car_relationships.jsonl)
       ├── byakugan-load/                                        # `load-car` state
       └── exchange/                                             # the STIX/CTI exchange's bundles
```

A **collection** (`dxdfir process <collection> …`) reads
`raw/collections/<collection>/<lane subdir>/` and writes one level below each
tool's leaf, so two cases never share an output folder or a CAR store. A
**host** is the evidence item — a disk image, a capture, a memory image, or a
folder of loose logs staged as `logs/<os>/<host>/`.

---

## 🛠️ Usage & Workflow

**1. Place raw evidence** in the matching `raw/` subdirectory above.

*Or auto-sort a mixed drop.* Create a collection and let `dxdfir` file a pile of
mixed evidence into its lane subdirs by **magic bytes** (content, not extension —
a mislabelled `.raw` E01 still lands in `disk_images/`; a header-less `.raw` with
no signature is left in the dropzone for you to place by hand):

```bash
dxdfir register case-a                   # -> data_store/raw/collections/case-a/ (+ SHA-1 hash)
#   ...drop mixed files into data_store/raw/sort/...
dxdfir sort case-a                       # magic-first sort into the lane subdirs
dxdfir process all case-a                # run every lane over just this collection
```

**2. Process it.** The `dxdfir` CLI is the front-end (see
[How It Runs](/README.md#how-it-runs)):

```bash
dxdfir process zeek            # pcaps
dxdfir process gowindowlicker  # Windows hosts: event logs + the disk-image artefacts (aliases: evtx, windowlicker)
dxdfir process godaemonhunter  # Linux hosts: logs + the disk-image artefacts (alias: daemonhunter)
dxdfir process anamnesis       # memory (alias: memory)
dxdfir process plaso           # disk images / VM exports
dxdfir process signatures      # yara / suricata / hayabusa
```

**3. Build and verify the CAR:**

```bash
dxdfir build-car            # every source -> processed/byakugan/<source>/car_<object>.jsonl
dxdfir verify-car           # the correctness gate over what was written
```

**4. Bring up the analysis backend** — the Elastic-native stack under
[the stack](/docs/architecture/the-stack.md) (the `dxdfir_stack` role, localhost-only,
security on). Filebeat tails the processed tree into `logs-dxdfir.<type>-*`
data streams; see [Get-Started](/docs/Get-Started.md) steps 7–9.

---

## ⚠️ Notes

- **Verify hashes** when moving forensic images (`.E01`).
- **Never commit evidence.** `data_store/` is gitignored deny-by-default, but it
  is a safety net, not a guarantee — check `git status` before every commit.
- Follow the layout above so the CAR lane and the shipper find each source.

🚀 **Stay organized, process efficiently, and hunt smart!**
