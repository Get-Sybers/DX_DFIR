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
   ├── dependencies/               # Operator-supplied tools (e.g. EvtxECmd)
   │
   └── processed/                  # Ingest-ready output, one subtree per source
       ├── log2timeline/
       │   ├── plaso/              # .plaso databases (reusable by Timesketch / SOF-ELK)
       │   ├── jsonl/              # Plaso json_line  -> host.L2t<Parser> (one table per parser)
       │   └── logs/               # Job logs
       ├── windows_logs/           # EvtxECmd JSON     -> host.EvtxEcmdJson
       ├── zeek/<capture>/         # Zeek JSON (conn.json, dns.json, …) -> network.ZeekConn + network.Zeek
       ├── volatility/<image>/     # Volatility 3 JSONL per plugin      -> memory.VolatilityJson
       ├── velociraptor/           # Velociraptor collector JSON        -> host.VelociraptorJson
       ├── signatures/             # yara/ suricata/ hayabusa/ detection JSONL
       ├── linux_logs/             # syslog/auth/utmp/… (not yet wired into the backend)
       └── sofelk/<tool>/          # --pipeline sofelk output, delivered into SOF-ELK
```

---

## 🛠️ Usage & Workflow

**1. Place raw evidence** in the matching `raw/` subdirectory above.

**2. Process it.** The `dxdfir` CLI is the front-end (see
[How It Runs](/README.md#how-it-runs)); each source also has a legacy
`process-*.sh` script:

```bash
dxdfir process plaso        # disk images / VM exports   (or ./scripts/process-log2timeline-Dynamic.sh)
dxdfir process zeek         # pcaps                       (or ./scripts/process-zeek-ALL.sh)
dxdfir process evtx         # Windows event logs          (or ./scripts/process-evtx-EvtxECmd.sh)
dxdfir process volatility   # memory                      (or ./scripts/process-volatility.sh)
dxdfir process velociraptor # Velociraptor collections    (or ./scripts/process-velociraptor.sh)
dxdfir process signatures   # yara / suricata / hayabusa  (or ./scripts/process-signatures.sh)
```

Add `--pipeline sofelk` to target the SOF-ELK backend instead of ADX (output
lands under `processed/sofelk/<tool>/`).

**3. Load into the analysis backend** (ADX / Kusto emulator):

```bash
dxdfir deploy               # stand up the emulator + apply schema
dxdfir ingest               # load data_store/processed into it
```

The equivalent scripts are `./scripts/deploy-kusto.sh`,
`./scripts/apply-kusto-schema.sh` and `./scripts/ingest-kusto.sh`.

---

## ⚠️ Notes

- **Verify hashes** when moving forensic images (`.E01`).
- **Never commit evidence.** `data_store/` is gitignored deny-by-default, but it
  is a safety net, not a guarantee — check `git status` before every commit.
- Follow the layout above so ingest finds each source.

🚀 **Stay organized, process efficiently, and hunt smart!**
