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
   ├── raw/                        # Unprocessed evidence — you place it here
   │   ├── disk_images/            # Disk images (.E01, .raw/.dd, .vmdk, …)
   │   ├── pcaps/                  # Packet captures (.pcap, .pcapng)
   │   ├── VM_files/               # VMware VM exports (one folder per VM)
   │   ├── memory/                 # Memory captures
   │   └── other_raw_data/         # e.g. WinEvt/<host>/*.evtx for the EVTX path
   │
   ├── dependencies/               # Operator-supplied rulesets/symbols
   │
   └── processed/                  # One subtree per source — what `dxdfir build-car` reads
       ├── log2timeline/
       │   ├── storage/<source>/   # <source>.plaso (reusable by Timesketch) + log2timeline.log
       │   └── jsonl/<source>/     # Plaso json_line timeline.jsonl + psort.log
       ├── windows_logs/<log>/     # goevtx.jsonl, one folder per event log
       ├── zeek/<capture>/         # Zeek JSON (conn.json, dns.json, …)
       ├── memory/<image>/         # anamnesis (MemProcFS) JSONL per plugin + car.db
       ├── godfir-toolz/<tool>/    # GoDFIR-toolz artefacts, one folder per item (registry, SRUM, MFT, …)
       ├── detections/             # yara/ suricata/ hayabusa/ scan/ detection JSONL
       ├── linux_logs/             # syslog/auth/utmp/… (not yet wired into the backend)
       └── car/<source>/           # the materialised CAR: car.db + car_<object>.jsonl (+ car_relationships.jsonl)
```

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
dxdfir process plaso        # disk images / VM exports
dxdfir process zeek         # pcaps
dxdfir process evtx         # Windows event logs
dxdfir process memory       # memory
dxdfir process godfir-toolz    # GoDFIR-toolz artefacts from disk images
dxdfir process signatures   # yara / suricata / hayabusa
```

**3. Build and verify the CAR:**

```bash
dxdfir build-car            # every source -> processed/car/<source>/car_<object>.jsonl
dxdfir verify-car           # the correctness gate over what was written
```

**4. Bring up the analysis backend** — the Elastic-native stack under
[`docker/elastic/`](/docker/elastic/README.md) (docker compose, localhost-only,
security on). Filebeat tails the processed tree into `logs-dxdfir.<type>-*`
data streams; see [Get-Started](/docs/Get-Started.md) steps 7–9.

---

## ⚠️ Notes

- **Verify hashes** when moving forensic images (`.E01`).
- **Never commit evidence.** `data_store/` is gitignored deny-by-default, but it
  is a safety net, not a guarantee — check `git status` before every commit.
- Follow the layout above so the CAR lane and the shipper find each source.

🚀 **Stay organized, process efficiently, and hunt smart!**
