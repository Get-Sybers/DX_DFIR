# DX_DFIR Pipeline Task Board

Tracks tasks for the DFIR automation project — from forensic data processing to
the Elastic-native analysis backend.

Current release and its maturity: see the badge in
[README.md](/README.md) — it reads the latest
[Release](https://github.com/Get-Sybers/DX_DFIR/releases) directly. The
pre-release code is frozen on the
[`deprecated`](https://github.com/Get-Sybers/DX_DFIR/tree/deprecated)
branch.

## Architecture (epics #45 / #46)

The pipeline has been rebuilt as a three-layer stack: the **`dxdfir` CLI** →
the **`get_sybers.dxdfir` Ansible collection** (one role per source) → the
**`get_sybers_dxdfir` Python package**, writing the processed tree the CAR lane
builds from (`--pipeline elastic`, the default) or the retiring SOF-ELK delivery
tree (`--pipeline sofelk`). The analysis backend is the Elastic-native stack
(`docker/elastic`); the Kusto/ADX emulator it replaced has been retired. The
processing roles, the CLI, the CAR lane and both stacks exist on `dev`; the
per-source `process-*.sh` scripts have been retired (removed) — their behaviour
lives in the `get_sybers_dxdfir` processors. The tables below track the processing
/ CAR layer by source — see [How It Runs](/README.md#how-it-runs).

A note on what the ticks mean, because the previous version of this board was
generous with them:

| Mark | Meaning |
|:---:|:---|
| ✅ | Ran end-to-end by hand and produced correct output |
| ⚠️ | Runs, but incomplete, fragile, or unverified |
| ◑ | Built and internally consistent, never run against a live backend |
| ❌ | Not working, or not started |

Nothing on this board is covered by pipeline tests. "✅" is the author's
word, not a test result.

---

# Data Pipeline Progress

Processing = the evidence-side lanes. CAR = the materialised CAR the engine
writes from each lane's output (`dxdfir build-car`) — the contract the
Elastic-native backend reads.

| Processing Tool / Artefact                                    | Automate Data | File Type      | Processed output (`data_store/processed/`) | CAR objects |
|:--------------------------------------------------------------|:-------------:|:---------------|:------------:|:-------------:|
| [Log2timeline](https://github.com/log2timeline/plaso)         | ✅            | json_line       | ✅ `log2timeline/jsonl/`           |     ✅ (`file`) |
| [Zeek](https://zeek.org/)                                     | ✅            | json            | ✅ `zeek/<capture>/` (`conn` + all other logs) | ✅ (`flow`) |
| [WinEvent Logs](https://www.sans.org/white-papers/32949/) (EvtxECmd) | ✅ (bundled `dxdfir/evtxecmd` image; 103 real LoneWolf logs) | evtx → json     | ✅ `windows_logs/<host>/` (55,638 rows)           |     ✅ (`process`/`user_session`/`service`) |
| [EZ-Tools](https://ericzimmerman.github.io/) (Zimmerman) artefacts | ✅ the zimmerman lane (`dxdfir process zimmerman`) | json / csv | ✅ `zimmerman/` | ✅ (`registry`/`flow`/`process`) |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | ✅ the volatility lane | json (per plugin) | ✅ `volatility/<image>/` | n/a (memory ≠ CAR dead-box object) |
| [Log2timeline/Plaso](https://github.com/log2timeline/plaso) (disk images, all formats + VM) | ✅ the plaso lane | json_line (+ `.plaso` db) | ✅ `log2timeline/jsonl/`, one file per host | ✅ (`file`, `process` prefetch/amcache/cron, `user_session` utmp/ssh) |
| Linux Logs (syslog / utmp / ssh, via Plaso)                   | ✅            | json_line       | ✅ via the plaso lane | ✅ (`user_session` utmp+ssh, `process` cron) |
| [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | ✅ (via EvtxECmd) | evtx → json | ✅ `windows_logs/<host>/` | ✅ (`driver`/`module`/`thread`, + `process`/`flow`/`registry`/`file`) |
| [YARA](https://github.com/VirusTotal/yara) (files / mounted disk / memory) | ✅ `get_sybers_dxdfir.signatures` (yara lane) | json (matches) | ✅ `signatures/yara/` | ⏳ detection enrichment (follow-up) |
| [Suricata](https://suricata.io/) (pcaps → EVE)                | ✅ `get_sybers_dxdfir.signatures` (suricata lane) | json (EVE) | ✅ `signatures/suricata/` | ⏳ |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) (EVTX → Sigma) | ✅ `get_sybers_dxdfir.signatures` (hayabusa lane; also in the evtx lane) — validated 792 detections | json (Sigma) | ✅ `signatures/hayabusa/` | ⏳ |
| [Syslog](https://syslog-ng.github.io)                         | ✅ (via Plaso) |                 |              |               |

**CAR is materialized.** The engine ([byakugan](https://github.com/Get-Sybers/byakugan), formerly PIIAT-MitreCar) normalises each evidence
source into finished CAR events and writes one `car_<object>.jsonl` per object
(13 objects) plus `car_relationships.jsonl` (the superset relationship edges)
under `processed/car/<source>/` — the materialised CAR every sink reads; the
Elastic-native path projects it to ECS (`logs-car.*`, the
[risk gate](/docs/riskgate.md)). Extraction happens once, in the engine, so the
JSON cannot drift from the model. `dxdfir build-car` produces the stores,
`dxdfir verify-car` gates them, `dxdfir car-timeline` unions them into one
timeline. See [docs/CAR-Pipeline.md](/docs/CAR-Pipeline.md) and
[docs/CAR-Extraction-Rules.md](/docs/CAR-Extraction-Rules.md).

---

# Known Limitations

Things that are broken or unsafe right now.

- **`chmod -R 777` on data directories.** Processing scripts widen permissions
  on `data_store/` to work around Docker UID mismatches. Don't run on a shared
  host.
- **The retiring SOF-ELK stack has no security at all** (dead-box posture); the
  Elastic-native stack runs with security on, but Kibana is plain HTTP on the
  loopback interface and Filebeat writes as the superuser for now. The
  `127.0.0.1` bindings are the control; see [SECURITY.md](/SECURITY.md).
- ~~**Raw EVTX processing is built but unverified.**~~ **Resolved.** The `dxdfir_evtx`
  role ran on **103 real event logs** carved from the LoneWolf image (bundled
  `dxdfir/evtxecmd` image), 55,638 EvtxECmd rows, feeding the
  `user_session`/`process`/`service` CAR objects from real 4624/4688/7045.

---

# Update log

## To Do

### Run the backend to ground — *the blocker for everything*
- ⬜ **Run the Elastic-native backend to ground.** The Phase-0
  [risk gate](/docs/riskgate.md) was authored without a cluster; its first live
  run on `docker/elastic` gates everything built on top (the CAR→ECS load into
  `logs-car.*`, the detection rules, the CTI exchange) and is worth more than
  any further code.

### Data Models & MITRE CAR Mapping
- Validate the CAR field mappings against real Windows event logs, Zeek logs,
  and forensic artifacts beyond the author's corpus (`dxdfir verify-car` is the
  gate; the smoke test covers the Sysmon lane) —
  [issue #14](https://github.com/Get-Sybers/DX_DFIR/issues/14) is the ranked
  checklist.
- Extend lookups for event IDs, log sources, and mapped MITRE techniques —
  potentially from CTI STIX data and
  https://github.com/ForensicArtifacts/artifacts.
- A visualisation story for CAR-mapped events — Kibana over the `logs-car.*`
  data streams once the CAR→ECS load lands.

### Testing — *partly done*
- ✅ Syntax/lint gating — `tests/run-checks.sh` (`bash -n`, shellcheck, the
  pinned collection requirements, ansible-lint, path resolution, the Python
  unit tests, gitignore, secrets, doc links). The count is whatever the harness
  prints; it is deliberately not restated here.
- ✅ A smoke test (`tests/smoke-test.sh`, the `smoke` workflow) runs the real
  evtx lane over sha256-pinned public Sysmon fixtures, normalises to CAR and
  asserts the extracted field values, then runs the `verify-car` gate.
- ⬜ The same for a small public disk image (the plaso / zimmerman lanes).

### Environment & Dependencies
- Create a guide for **setting up the development environment**.

---

## In Progress

### Documentation
- Align the docs with the #45/#46 rewrite — present the `dxdfir` CLI + collection
  as the front-end; the retired `process-*.sh` scripts have been removed (done).

---

## Done

### Kusto/ADX retired — the Elastic-native path is the backend
✅ Removed the whole Azure Data Explorer emulator layer: `kusto/schema/`, the
`dxdfir_deploy_adx` / `dxdfir_ingest_adx` / `dxdfir_detect_adx` roles and playbooks,
`get_sybers_dxdfir.deploy`, the `get_sybers_dxdfir.ingest` package, the Kusto
detection runner and registry, the `dxdfir deploy` / `ingest` / `detect` verbs,
`docs/Kusto-Port.md` and the emulator's licensing notices. `--pipeline adx` is
now `--pipeline elastic`. `dxdfir verify-car` and the smoke test assert the
materialised `car_<object>.jsonl` directly instead of querying an emulator.
The Done entries below that mention Kusto/KQL are history — they describe the
backend as it was when that work landed.

### Plaso pipeline migrated CSV → JSON (json_line), with a Plaso output module
✅ **Plaso now outputs `json_line`, not the flat 23-column CSV** — the CSV forced
every parser's event into a lowest-common-denominator schema and dropped the rest
(imphash, sha256, pe_type, pathspec, the typed utmp/cron/ssh fields…). New
`host.L2tJson` table: a `dynamic Record` per event (same shape as
`VolatilityJson`), Timestamp lifted from Plaso's microsecond
`timestamp` in the ingest prepare hook. The 4 Plaso-fed CAR functions
(`CarFile`/`CarProcess`/`CarUserSession`/`CarService`) were rewritten to read
`Record.data_type` + typed fields instead of the CSV's `SourceLong`/message
regexes — cleaner and validated on **real** json output (dfrws Raspberry Pi,
host `octopi`): `CarFile` 265k fs events, `CarProcess` cron (typed
command/pid/user), `CarUserSession` utmp login/logout/boot **+ real SSH logins**.
✅ **`dev-scripts/plaso/l2t_json_dxdfir.py` — a Plaso output module** that adds, from
the `.plaso` db, on every event: `image_hostname` (the box's own name from
system_configuration — consistent, unlike per-event GetHostname), `username`,
`disk_id`, `volume_id`, `volume_offset`. The processor runs the two-step
(`log2timeline.py` → `.plaso` → `psort.py -o l2t_json_dxdfir`), naming output by
hostname. The hostname/username half is upstreamed as
[log2timeline/plaso#5194](https://github.com/log2timeline/plaso/pull/5194) (#41).
✅ Fixed a critical regression first: the processor had been left emitting
`json_line` at a path/format the CSV ingest couldn't read (#38).

### CAR to 9/9 objects (Sysmon) + Zeek all-log JSON pipeline
✅ **All nine CAR objects sourced and validated live.** Added `CarDriver()`
(Sysmon 6), `CarModule()` (Sysmon 7) and `CarThread()` (Sysmon 8) — the three
that had no dead-box source — and strengthened `CarProcess` (1/5), `CarFlow`
(3), `CarRegistry` (12/13/14) and `CarFile` (11/23) with Sysmon branches. Sysmon
rides the existing EvtxECmd path into `host.EvtxEcmdJson`, told apart by
`Provider`. `CarCoverage()` returned real rows for all nine on the live engine.
✅ A defect the live run surfaced: KQL `has` is whole-term, so the Sysmon
registry `action` (`case(EventType has "Create"...)`) fell through to "modify"
for every event — `CreateKey`/`RenameKey` now classify correctly via `contains`.
✅ Confirmed the two Windows PID encodings decode correctly side by side —
Security 4688 hex (`0x11b8`→4536) and Sysmon decimal (`4536`→4536).
✅ **Zeek pipeline reconciled to JSON, all ~69 log types ingested.** The
processor already emitted JSON (`LogAscii::use_json=T`) but the loader still
expected TSV — they had drifted and could not run end-to-end. `conn.json` is now
typed into `ZeekConn` by **JSON path** mapping (immune to Zeek field reordering,
so the old ordinal column-order guard is gone), native numeric/boolean types,
and every other log lands in the generic `Zeek` dynamic table via a
`{LogType, SourceFile, Record}` wrapper — `dns`/`http`/`ssl`/… all queryable,
with `ZeekLog()`/`ZeekDns()`/`ZeekHttp()`/`ZeekSsl()` views. Validated live.

### First run against a live Kusto emulator — *the blocker, broken*
✅ Deploy → apply → ingest → `CarCoverage()` executed end-to-end on the real
`kustainer-linux` engine, with data processed from the Digital Corpora sample
URLs. Five of nine CAR objects returned real rows.
✅ Processed three real `.E01` images with Plaso (`psteal --output-format
dynamic`) — 1240 filesystem events. Confirmed the 23-field CSV header order
matches the `L2tCsvMapping` ordinals, the `datetime` field parses with zero
nulls, and `ignoreFirstRecord` drops the header cleanly.
✅ Fixed four defects the live run surfaced, each invisible until first contact:
`network` is a **reserved database name** (bracket-quoted now); the `0L` long
literal in `CarCoverage()` is rejected by this build (`long(0)` now); the two
database-name parsers updated to match; and `CarFile()` left 260/1240 real rows
with an empty `action` because its `modify` regex missed `Metadata`/`File Last`
modification times (broadened now — all rows classify).
✅ Resolved [issue #14](https://github.com/Get-Sybers/DX_DFIR/issues/14) item 6:
`tolong()` **does** parse a `0x` hex string at run time, so `CarProcess.pid` is
populated (`0x1a4` → 420).
✅ Validated the Zeek `conn` and EvtxECmd ingest/mapping/CAR paths (including
`CarProcess`/`CarUserSession`/`CarService` and the Payload-XML extraction)
against the live engine with format-accurate fixtures — the tool engines
themselves are blocked by egress policy here.
✅ **Memory** processed with Volatility 3 → `memory.VolatilityJson`,
proving the constant-column injection the JSON loaders need
([#16](https://github.com/Get-Sybers/DX_DFIR/issues/16)).
✅ **Android and macOS** artefacts processed with real Plaso parsers into
`host.L2tCsv`: Android `LOG`/"Android SMS messages"·"Android Call History"
([#17](https://github.com/Get-Sybers/DX_DFIR/issues/17)), macOS `WEBHIST`/"Safari
History Database" and the real `fseventsd` `MacOS File System Events`
([#18](https://github.com/Get-Sybers/DX_DFIR/issues/18)). These mobile/browser
source types correctly do **not** map to a CAR object (CAR's objects are
host dead-box: file/process/flow/…); they're queried directly by `SourceLong`.
Full Android/macOS *disk images* (5–48 GB) exceed the working disk here; the
real artefact formats were parsed instead.

### The pivot: Splunk → Data Explorer emulator
✅ Ported the SIEM layer to the Kusto emulator — 5 databases, typed tables and
ingestion mappings for Plaso/EvtxECmd/Zeek `conn`, MITRE CAR as KQL functions,
deploy/apply/ingest scripts with the container lessons the Splunk path paid
for (isolation verified both directions, honest purges, real readiness
checks).
✅ Retired the Splunk stack in one cut — scripts, eight apps, in-container
Ansible, vendored ESCU lookups. History and the `deprecated` branch keep it.
✅ Consolidated the container lifecycle into a shared library and the ingest
sources into a descriptor table (both since retired with the shell pipeline —
the roles and `get_sybers_dxdfir` carry the behaviour).

### Field Extractions

✅ **Log2timeline field mappings**
  - log2timeline output was changed from json to "dynamic" which outputs a "comma delimited" output. The reason for this is l2t captures more timestamp formats than I knew existed and won't convert them into epoch unless --dynamic output is made.
  - the end result is surprisingly a looot better than I expected csv.
  - huge benefit is I was able to pass the "datetime" field l2t outputs in as the timeline `_time` value — the same field now drives `Timestamp` in `host.L2tCsv`.

### Dynamic Scripts Testing
✅ Test the plaso lane for processing **single and all E01 images**.
✅ Test the zeek lane.
✅ VMware VM export support added to log2timeline processing — lightly tested.

### log2timeline Processing
- Functional pipeline for **E01 images → Plaso → CSV**.
  *(output was originally JSON, later changed to csv)*

### Zeek Processing
- PCAPs successfully converted into Zeek logs.

### Repository Setup & Documentation
- Created base directory structure (`data_store`, `scripts`).
- Wrote **README files** for root, `data_store`, and `scripts` directories.

### Release hygiene *(v0.2.0-beta)*
- Audited every vendored dependency and settled the project licence — Apache-2.0.
- Added `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `CHANGELOG.md`.

✅ **Closed an evidence-leak hole in `data_store/.gitignore`.**
  The old file was an extension blocklist, and it had already failed: VMware
  exports (`.vmdk`, `-flat.vmdk`, `.vmx`, `.ovf`, `.ova`, `.vmsd`, `.vmxf`) were
  fully committable, because VM support was added to the pipeline without
  updating the list — and `data_store/raw/VM_files/` is where the docs tell you
  to put them. Replaced with deny-by-default, which also covers extensionless
  files and any future format. Verified all 23 tracked skeleton files survive.
