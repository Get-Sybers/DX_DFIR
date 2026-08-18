# 🗂️ DX_DFIR Pipeline Task Board

Tracks tasks for the DFIR automation project — from forensic data processing to
the Kusto-emulator analysis backend.

Current release and its maturity: see the badge in
[README.md](/README.md) — it reads the latest
[Release](https://github.com/Get-Sybers/DX_DFIR/releases) directly. The
pre-release code is frozen on the
[`deprecated`](https://github.com/Get-Sybers/DX_DFIR/tree/deprecated)
branch.

## 🧱 Architecture (epics #45 / #46)

The pipeline has been rebuilt as a three-layer stack: the **`dxdfir` CLI** →
the **`get_sybers.dfir` Ansible collection** (one role per source) → the
**`get_sybers_dfir` Python package**, driving two backends via
`--pipeline adx|sofelk` (ADX / Kusto emulator + SOF-ELK). All ten roles, the CLI
and the from-source SOF-ELK stack exist on `dev`; the one open box is **per-source
retirement of the `process-*.sh` scripts**. The tables below track the
processing / ingest layer (still named by the `process-*.sh` scripts the roles
wrap) — see [How It Runs](/README.md#how-it-runs) and #46.

A note on what the ticks mean, because the previous version of this board was
generous with them:

| Mark | Meaning |
|:---:|:---|
| ✅ | Ran end-to-end by hand and produced correct output |
| ⚠️ | Runs, but incomplete, fragile, or unverified |
| ◑ | Built and internally consistent, never run against a live emulator |
| ❌ | Not working, or not started |

Nothing on this board is covered by pipeline tests. "✅" is the author's
word, not a test result.

---

# Data Pipeline Progress

Processing = the evidence-side scripts. Ingest / CAR = the Kusto backend.

| Processing Tool / Artefact                                    | Automate Data | File Type      | Kusto Ingest | CAR Functions |
|:--------------------------------------------------------------|:-------------:|:---------------|:------------:|:-------------:|
| [Log2timeline](https://github.com/log2timeline/plaso)         | ✅            | json_line       | ✅           |     ✅ (`file`) |
| [Zeek](https://zeek.org/)                                     | ✅            | json            | ✅ (`conn` typed + all other logs generic) | ✅ (`flow`) |
| [WinEvent Logs](https://www.sans.org/white-papers/32949/) (EvtxECmd) | ⚠️     | evtx → json     | ✅           |     ✅ (`process`/`user_session`/`service`) |
| Velociraptor offline collectors ([EZ Tools](https://ericzimmerman.github.io/)) | ✅ `process-velociraptor.sh` (unpack collection) | json | ✅ `host.VelociraptorJson` | ✅ (`registry`) |
| [Velociraptor](https://github.com/Velocidex/velociraptor)     | ⚠️            | json            | ✅ `host.VelociraptorJson` | ✅ (`registry`) |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | ✅ `process-volatility.sh` | json (per plugin) | ✅ `memory.VolatilityJson` | n/a (memory ≠ CAR dead-box object) |
| [Log2timeline/Plaso](https://github.com/log2timeline/plaso) (disk images, all formats + VM) | ✅ `process-log2timeline-Dynamic.sh` | json_line (+ `.plaso` db) | ✅ per-parser `host.L2t<Parser>` | ✅ (`file`, `process` prefetch/amcache/cron, `user_session` utmp/ssh) |
| Linux Logs (syslog / utmp / ssh, via Plaso)                   | ✅            | json_line       | ✅ `host.L2tText`/`L2tUtmp` | ✅ (`user_session` utmp+ssh, `process` cron) |
| [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | ✅ (via EvtxECmd) | evtx → json | ✅ `host.EvtxEcmdJson` | ✅ (`driver`/`module`/`thread`, + `process`/`flow`/`registry`/`file`) |
| [YARA](https://github.com/VirusTotal/yara) (files / mounted disk / memory) | ✅ `process-signatures.sh` (yara.sh) | json (matches) | ⏳ `processed/signatures/yara` | ⏳ detection enrichment (follow-up) |
| [Suricata](https://suricata.io/) (pcaps → EVE)                | ✅ `process-signatures.sh` (suricata.sh) | json (EVE) | ⏳ `processed/signatures/suricata` | ⏳ |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) (EVTX → Sigma) | ✅ `process-signatures.sh` (hayabusa.sh) — validated 792 detections | json (Sigma) | ⏳ `processed/signatures/hayabusa` | ⏳ |
| [Chainsaw](https://github.com/countercept/chainsaw)           | ❌            |                 |              |               |
| [Syslog](https://syslog-ng.github.io)                         | ✅ (via Plaso) |                 |              |               |
| [Zimmerman](https://github.com/EricZimmerman)                 | (via Velociraptor) |            |              |               |

**All nine CAR objects now run against a live emulator.** The MITRE CAR data
model is expressed as KQL functions in the `mitre` database — `CarFlow()`,
`CarUserSession()`, `CarProcess()`, `CarService()`, `CarFile()`, `CarRegistry()`,
`CarDriver()`, `CarModule()`, `CarThread()`, with `CarCoverage()` reporting what
has data. The three that were empty for so long — `driver`, `module`, `thread` —
are now sourced from **Sysmon** (Microsoft-Windows-Sysmon/Operational events
6/7/8), which lands in `host.EvtxEcmdJson` through the same EvtxECmd path as the
Security log. Sysmon also strengthens `process` (event 1/5, full pid/ppid/command
line), `flow` (3), `registry` (12/13/14) and `file` (11/23). On the live engine
`CarCoverage()` returned real rows for **all nine** objects — see
[docs/Runtime-Validation.md](/docs/Runtime-Validation.md).

**The CAR layer has since been refactored into per-artefact views.** Each object
is now built as one view per artefact — `Car<Object>_<Artefact>()` (e.g.
`CarProcess_Sysmon`, `CarProcess_Memory`, `CarRegistry_Recmd`) — that keeps the
source table's native fields and *adds* the canonical CAR fields; the public
`CarX()` is a `union isfuzzy` roll-up. Every artefact fills every canonical field
it can supply, strict to `car_data_model.json`. See
[docs/CAR-Extraction-Rules.md](/docs/CAR-Extraction-Rules.md) and #43.

**What the live run still does not cover.** Plaso was run for real, but only on
filesystem test images — a Windows image (for `CarProcess`-from-Plaso via
Prefetch/Amcache) has not been run. The Zeek, EvtxECmd and Sysmon **engines**
could not run here (egress policy blocks the `zeek/zeek` image and there is no
standalone `.evtx`/Sysmon log in the corpus), so their ingest/mapping/CAR paths
were proven with format-accurate fixtures against the live engine rather than
live tool output. The remaining runtime checklist is
[issue #14](https://github.com/Get-Sybers/DX_DFIR/issues/14).

---

# 🚨 Known Limitations

Things that are broken or unsafe right now.

- **No pipeline tests.** `tests/run-checks.sh` runs the static and behavioural
  repo checks in CI, but nothing exercises the actual pipeline. Until
  something does, every ✅ on this board is still a claim rather than a
  result. Highest-value next step.
- **Nothing has touched a real emulator.** Deploy, schema, ingestion and the
  CAR functions are verified against fakes and fixtures only.
- **`chmod -R 777` on data directories.** Processing scripts widen permissions
  on `data_store/` to work around Docker UID mismatches. Don't run on a shared
  host.
- **The emulator has no security features at all** — no auth, no access
  control, plaintext HTTP, no encryption at rest. The `127.0.0.1` binding is
  the only control; see [SECURITY.md](/SECURITY.md).
- **Raw EVTX processing is built but unverified.** `process-evtx-EvtxECmd.sh`
  has never been run against a real event log.

---

# Update log

## 🔜 To Do

### 🔹 **Run the backend to ground** — *the blocker for everything*
- ⬜ **Run it.** Nothing has touched a real emulator. That gates everything
  below and is worth more than any further code —
  [issue #14](https://github.com/Get-Sybers/DX_DFIR/issues/14) is the ranked
  checklist.
- ⬜ Velociraptor: the ingest loader is wired (`host.VelociraptorJson` via
  `velociraptor_prepare`), but the upstream offline-collector path that feeds it
  isn't built, and nothing has run against a real emulator.

### 🔹 **Data Models & MITRE CAR Mapping**
- Validate the CAR field mappings against real Windows event logs, Zeek logs,
  and forensic artifacts (KQL functions exist; values unverified).
- Extend lookups for event IDs, log sources, and mapped MITRE techniques —
  potentially from CTI STIX data and
  https://github.com/ForensicArtifacts/artifacts.
- A visualisation story for CAR-mapped events (the emulator has no dashboard
  layer; Kusto.Explorer or a thin web UI are the candidates).

### 🔹 **Testing** — *partly done*
- ✅ Syntax/lint gating — `tests/run-checks.sh` (`bash -n`, shellcheck, path
  resolution, the container-lifecycle library's behavioural tests, Kusto
  schema consistency, gitignore, secrets, doc links). The count is whatever
  the harness prints; it is deliberately not restated here.
- ⬜ A smoke test that runs the pipeline against a small public sample image.

### 🔹 **Velociraptor offline collectors (EZ Tools) & Raw EVTX**
- Build the offline-collector path: Velociraptor collectors running the EZ
  Tools for artefact collection and parsing — the replacement for the removed
  KAPE automation. Same Zimmerman parsers and field names, so the retired
  `KapeJson` mapping in git history is the starting point; re-sources the
  `registry` CAR object when it lands. If the collectors emit EZ-tool CSV,
  the answer is typed per-artefact tables or JSON conversion — a CSV mapping
  cannot populate a `dynamic` column.
- Verify `process-evtx-EvtxECmd.sh` against a real event log.

### 🔹 **Environment & Dependencies**
- Create a guide for **setting up the development environment**.

---

## 🔄 In Progress

### 🔹 **Documentation**
- Align the docs with the #45/#46 rewrite — present the `dxdfir` CLI + collection
  as the front-end and frame the `process-*.sh` scripts as the legacy layer being
  retired (in progress).

---

## ✅ Done

### 🔹 **Plaso pipeline migrated CSV → JSON (json_line), with a Plaso output module**
✅ **Plaso now outputs `json_line`, not the flat 23-column CSV** — the CSV forced
every parser's event into a lowest-common-denominator schema and dropped the rest
(imphash, sha256, pe_type, pathspec, the typed utmp/cron/ssh fields…). New
`host.L2tJson` table: a `dynamic Record` per event (same shape as
`VolatilityJson`/`VelociraptorJson`), Timestamp lifted from Plaso's microsecond
`timestamp` in the ingest prepare hook. The 4 Plaso-fed CAR functions
(`CarFile`/`CarProcess`/`CarUserSession`/`CarService`) were rewritten to read
`Record.data_type` + typed fields instead of the CSV's `SourceLong`/message
regexes — cleaner and validated on **real** json output (dfrws Raspberry Pi,
host `octopi`): `CarFile` 265k fs events, `CarProcess` cron (typed
command/pid/user), `CarUserSession` utmp login/logout/boot **+ real SSH logins**.
✅ **`dev-scripts/plaso/l2t_json_dfir.py` — a Plaso output module** that adds, from
the `.plaso` db, on every event: `image_hostname` (the box's own name from
system_configuration — consistent, unlike per-event GetHostname), `username`,
`disk_id`, `volume_id`, `volume_offset`. The processor runs the two-step
(`log2timeline.py` → `.plaso` → `psort.py -o l2t_json_dfir`), naming output by
hostname. The hostname/username half is upstreamed as
[log2timeline/plaso#5194](https://github.com/log2timeline/plaso/pull/5194) (#41).
✅ Fixed a critical regression first: the processor had been left emitting
`json_line` at a path/format the CSV ingest couldn't read (#38).

### 🔹 **CAR to 9/9 objects (Sysmon) + Zeek all-log JSON pipeline**
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

### 🔹 **First run against a live Kusto emulator** — *the blocker, broken*
✅ Deploy → apply → ingest → `CarCoverage()` executed end-to-end on the real
`kustainer-linux` engine, with data processed from the Digital Corpora sample
URLs. Five of nine CAR objects returned real rows. Full write-up, including the
field/source-type breakdown, in
[docs/Runtime-Validation.md](/docs/Runtime-Validation.md).
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
proving the constant-column injection the Velociraptor loader needs
([#16](https://github.com/Get-Sybers/DX_DFIR/issues/16)).
✅ **Android and macOS** artefacts processed with real Plaso parsers into
`host.L2tCsv`: Android `LOG`/"Android SMS messages"·"Android Call History"
([#17](https://github.com/Get-Sybers/DX_DFIR/issues/17)), macOS `WEBHIST`/"Safari
History Database" and the real `fseventsd` `MacOS File System Events`
([#18](https://github.com/Get-Sybers/DX_DFIR/issues/18)). These mobile/browser
source types correctly do **not** map to a CAR object (CAR's objects are
host dead-box: file/process/flow/…); they're queried directly by `SourceLong`.
Full Android/macOS *disk images* (5–48 GB) exceed the working disk here; the
real artefact formats were parsed instead. See
[docs/Runtime-Validation.md](/docs/Runtime-Validation.md).

### 🔹 **The pivot: Splunk → Data Explorer emulator**
✅ Ported the SIEM layer to the Kusto emulator — 5 databases, typed tables and
ingestion mappings for Plaso/EvtxECmd/Zeek `conn`, MITRE CAR as KQL functions,
deploy/apply/ingest scripts with the container lessons the Splunk path paid
for (isolation verified both directions, honest purges, real readiness
checks).
✅ Retired the Splunk stack in one cut — scripts, eight apps, in-container
Ansible, vendored ESCU lookups. History and the `deprecated` branch keep it.
✅ Consolidated the container lifecycle into `scripts/lib/docker-lifecycle.sh`
and the ingest sources into a descriptor table.

### 🔹 **Field Extractions**

✅ **Log2timeline field mappings**
  - log2timeline output was changed from json to "dynamic" which outputs a "comma delimited" output. The reason for this is l2t captures more timestamp formats than I knew existed and won't convert them into epoch unless --dynamic output is made.
  - the end result is surprisingly a looot better than I expected csv.
  - huge benefit is I was able to pass the "datetime" field l2t outputs in as the timeline `_time` value — the same field now drives `Timestamp` in `host.L2tCsv`.

### 🔹 **Dynamic Scripts Testing**
✅ Test `process-log2timeline-Dynamic.sh` for processing **single and all E01 images**.
✅ Test `process-zeek-ALL.sh`.
✅ VMware VM export support added to log2timeline processing — lightly tested.

### ✅ **log2timeline Processing**
- Functional pipeline for **E01 images → Plaso → CSV**.
  *(output was originally JSON, later changed to csv)*

### ✅ **Zeek Processing**
- PCAPs successfully converted into Zeek logs.

### ✅ **Repository Setup & Documentation**
- Created base directory structure (`data_store`, `scripts`).
- Wrote **README files** for root, `data_store`, and `scripts` directories.

### ✅ **Release hygiene** *(v0.2.0-beta)*
- Audited every vendored dependency and settled the project licence — Apache-2.0.
- Added `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `CHANGELOG.md`.

✅ **Closed an evidence-leak hole in `data_store/.gitignore`.**
  The old file was an extension blocklist, and it had already failed: VMware
  exports (`.vmdk`, `-flat.vmdk`, `.vmx`, `.ovf`, `.ova`, `.vmsd`, `.vmxf`) were
  fully committable, because VM support was added to the pipeline without
  updating the list — and `data_store/raw/VM_files/` is where the docs tell you
  to put them. Replaced with deny-by-default, which also covers extensionless
  files and any future format. Verified all 23 tracked skeleton files survive.
