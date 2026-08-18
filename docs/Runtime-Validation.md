# 🧪 Runtime validation — fields, source types, and CAR coverage

This is the first record of the pipeline **run against a live Kusto emulator**
with data processed from the [Digital Corpora](https://digitalcorpora.org/)
sample URLs in [`dev-scripts/samples-manifest.tsv`](/dev-scripts/samples-manifest.tsv).
It establishes the fields each source actually emits, how one piece of evidence
breaks down into ADX *source types*, and which MITRE CAR objects those source
types populate. It also records the defects the live run surfaced — every one
of them a "parsed in review, failed the moment it ran" bug that no fake could
have caught.

> **This records the pre-refactor run.** The schema then had a single
> `host.L2tCsv` table and the pipeline was script-driven. Plaso now emits
> `json_line` into per-parser `host.L2t<Parser>` tables, and processing/ingest
> moved to the `dxdfir` CLI + `get_sybers.dfir` collection (epic #46).
> Re-validating host + network after those refactors is
> [issue #44](https://github.com/Get-Sybers/DX_DFIR/issues/44) — so read the
> `L2tCsv` table names below as of this run, not the current schema.

> **What ran against real tooling vs. what was validated with a fixture.**
> This distinction is load-bearing and is kept honest throughout:
>
> | Lane | Input produced by | ADX ingest + mapping + CAR |
> |:---|:---|:---|
> | **Plaso → `host.L2tCsv`** | ✅ real `psteal` on three real `.E01` images | ✅ verified live |
> | **Zeek → `network.ZeekConn`** | ⚠️ format-accurate `conn.log` fixture¹ | ✅ verified live |
> | **EvtxECmd → `host.EvtxEcmdJson`** | ⚠️ format-accurate JSON fixture¹ | ✅ verified live |
> | **Volatility 3 → `memory.VolatilityJson`** | ◐ real `banners.Banners` on a real 511 MB dump + fixtures for symbol-blocked plugins² | ✅ verified live |
> | **Velociraptor → `host.VelociraptorJson`** | ⚠️ format-accurate RECmd fixture³ | ✅ verified live |
>
> ³ Velociraptor offline collectors run on the endpoint (not here), so a
> format-accurate RECmd result set stood in; the loader + `CarRegistry()` are
> real. It re-sources the `registry` CAR object.
>
> ² Volatility 3 (`pip install volatility3`) ran for real on a 511 MB memory
> image and its `banners.Banners` output — the ntoskrnl PDB GUID — is ingested.
> Its Windows *symbol tables* download from the Volatility / Microsoft symbol
> servers, both `403`/unreachable through the egress proxy, so the
> symbol-dependent plugins (`pslist`, `netscan`, …) can't resolve here; those
> were validated with format-accurate `vol -r json` fixtures.
>
> ¹ The Zeek image (`zeek/zeek`) and the OpenSUSE OBS Zeek packages are both
> refused at the network egress proxy (`403` on CONNECT), and there is no
> standalone `.evtx` in the corpus (real event logs live only inside the
> multi-GB Windows disk images — LoneWolf, Narcos). So the Zeek and EvtxECmd
> **engines** could not be run here. Their **output formats are deterministic**,
> so a byte-accurate fixture of what each tool emits was used to drive the ADX
> side — which is the half this project had never exercised. Plaso *was* run for
> real: it installs from PyPI (`pip install plaso`, pulling the compiled libyal
> readers), which the proxy allows.

The emulator image (`mcr.microsoft.com/azuredataexplorer/kustainer-linux`)
pulls from Microsoft Container Registry, which the proxy allows — so the ADX
backend itself is fully real.

---

## The headline: `CarCoverage()` against real + fixture data

Deploy → apply → ingest, from a clean container:

```
Object         Rows
file           1240     <- Plaso, three real .E01 images
flow              4     <- Zeek conn.log fixture
user_session      1     <- EvtxECmd 4624 fixture
service           1     <- EvtxECmd 7045 fixture
process           1     <- EvtxECmd 4688 fixture
registry          3     <- Velociraptor/RECmd fixture
driver            0     <- unsourced (needs Sysmon/live agent)
module            0     <- unsourced
thread            0     <- unsourced
```

Six of nine CAR objects carried data on that first run; the three zeros were the
honest, documented gaps. A later run closed them — see **[Follow-up run: 9/9
objects via Sysmon + Zeek all-log JSON](#follow-up-run-99-objects-via-sysmon--zeek-all-log-json)**
below, where `driver`/`module`/`thread` return real rows. The README's
"envisioned endstate" query returns a real row now:

```kusto
CarProcess() | where isnotempty(command_line)
| project dtg = Timestamp, hostname, user, command_line, artifact = Origin
```
```
dtg                          hostname  user       command_line                                         artifact
2025-01-01T10:14:29.123Z     WKS-1     analyst01  powershell.exe -nop -exec bypass Invoke-Mimikatz.ps1 evtx:4688
```

---

## Defects the live run surfaced (all fixed)

| # | File | Symptom on the live emulator | Fix |
|:--|:--|:--|:--|
| 1 | `kusto/schema/00-databases.kql` | `.create database network volatile` → **`General_BadRequest`**. `network` is a reserved word in the engine grammar; a bare name that read fine and failed on first contact. `host` created only because it happened to be first. | Bracket-quote every name: `.create database ["network"] volatile`. Downstream `database("network")` refs were already string-quoted. |
| 2 | `scripts/apply-kusto-schema.sh`, `tests/run-checks.sh` | The two places that parse database names out of the `.kql` expected the bare form and would have read every DB as absent once #1 was bracketed. | Bracket-tolerant regex that strips `["…"]` back to the plain name; command construction brackets the name too. |
| 3 | `kusto/schema/40-mitre.kql` — `CarCoverage()` | `print Object="registry", Rows = 0L` → **`SEM0100: Failed to resolve … '0L'`**. This emulator build rejects the typed-integer-literal suffix (`0L`), though it is valid in the cloud grammar. | `long(0)` — accepted by both, keeps the column a `long`. |
| 4 | `kusto/schema/40-mitre.kql` — `CarFile()` | 260 of 1240 real Plaso rows got an **empty `action`**. The `modify` regex matched only `content modification`, but a real NTFS image emits three modification descriptions. | Broaden the branch to `(?i)modification\|mtime`, capturing `Content`, `Metadata` and `File Last` modification times. All 1240 rows now classify. |

And one **unknown resolved rather than a bug** — [issue #14, item 6](https://github.com/Get-Sybers/DX_DFIR/issues/14):

> **`pid` hex conversion works.** `CarProcess` sets `pid = tolong(NewProcessId)`
> where `NewProcessId` is a hex string like `"0x1a4"`. Whether `tolong()`
> accepts a `0x` string *at runtime* (as opposed to a `0x` integer literal) was
> flagged untested. It does: `tolong("0x1a4")` → `420`, `tolong("0x1234")` →
> `4660`. Confirmed both in isolation and on the ingested 4688 row (`pid=420`,
> `pid_hex="0x1a4"`). Note `tolong("1a4")` *without* the prefix → `null`, so the
> `pid_hex` raw fallback is still worth keeping — but EvtxECmd always emits the
> `0x` form, so `pid` is populated.

---

## Follow-up run: 9/9 objects via Sysmon + Zeek all-log JSON

A second live run closed the three empty CAR objects and reconciled the Zeek
lane to JSON. `CarCoverage()` from a clean container, fixtures ingested:

```
Object         Rows   Source
file              4    Sysmon 11/23 + Plaso NTFS
process           4    Sysmon 1/5 + Security 4688 + Plaso cron
registry          4    Sysmon 12/13/14 + Velociraptor/RECmd
service           2    Security 7045 + Linux systemd audit
flow              2    Zeek conn + Sysmon 3
user_session      2    Security 4624 + Linux UTMP
driver            1    Sysmon 6   <- was 0
module            1    Sysmon 7   <- was 0
thread            1    Sysmon 8   <- was 0
```

All nine objects return rows. `driver`, `module` and `thread` — the objects
nothing *dead-box* can produce — are sourced from **Sysmon** (Microsoft-Windows-
Sysmon/Operational events 6/7/8), which rides the existing EvtxECmd path into
`host.EvtxEcmdJson` and is told apart from the Security log by `Provider`.

Two encodings of the Windows PID were confirmed to decode correctly **side by
side** in `CarProcess()`, the distinction that makes the Sysmon branch separate
from the Security one:

| Origin | EventData ProcessId | `pid` | `pid_hex` |
|:--|:--|:--|:--|
| `evtx:4688` (Security) | `0x11b8` (hex) | `4536` | `0x11b8` |
| `sysmon:1` (Sysmon) | `4536` (decimal) | `4536` | *(empty)* |

**Lane provenance** — same honesty distinction as the first run:

| Lane | Input produced by | ADX ingest + mapping + CAR |
|:---|:---|:---|
| **Sysmon → `host.EvtxEcmdJson`** | ⚠️ format-accurate EvtxECmd JSON fixture (no Sysmon log in the corpus, and EvtxECmd's egress is blocked) | ✅ verified live |
| **Zeek → `network.ZeekConn` (JSON, typed)** | ⚠️ format-accurate `conn.json` fixture¹ | ✅ verified live |
| **Zeek → `network.Zeek` (JSON, generic)** | ⚠️ format-accurate `dns`/`http`/`ssl` fixtures¹ | ✅ verified live |

### Defect this run surfaced (fixed)

| # | File | Symptom on the live emulator | Fix |
|:--|:--|:--|:--|
| 5 | `kusto/schema/40-mitre.kql` — `CarRegistry()` | Every Sysmon registry row got `action = "modify"`, including `CreateKey` (12) and `RenameKey` (14). `case(EventType has "Create", …)` — but KQL `has` matches whole **terms**, and `"CreateKey"` is a single camelCase token, so `has "Create"` is false and every branch fell through to the `"modify"` default. Parsed fine; wrong the moment it ran. | Use `contains` (substring), not `has`. `CreateKey → create`, `RenameKey → rename`, `SetValue → modify`. |

### The Zeek JSON reconciliation

`process-zeek-ALL.sh` emits JSON (`LogAscii::use_json=T`), but the loader still
expected TSV with `#fields` headers — the two stages had drifted and could not
run end to end. Fixed by mapping `conn.json` into the typed `ZeekConn` table by
**JSON path** (`$['id.orig_h']`, immune to Zeek field reordering — so the old
TSV column-order guard is gone, the risk it guarded no longer exists), with
native numeric/boolean types; every other log type is wrapped
`{LogType, SourceFile, Record}` into the generic `Zeek` dynamic table. On the
live engine: `ZeekConn` types `SrcPort=52345` (int), `Duration=1.25` (real),
`LocalOrig=true` (bool); the generic table holds `dns`/`http`/`ssl`, queryable
through `ZeekDns()`/`ZeekHttp()`/`ZeekSsl()`; and `CarFlow()` unions the Zeek
and Sysmon branches (one row each).

---

## Fields established, per source

### Plaso — `host.L2tCsv` (real)

`psteal --output-format dynamic` with the 23-field list in
`process-log2timeline-Dynamic.sh`. The emitted CSV **header order matches the
`--fields` list and the `L2tCsvMapping` ordinals exactly** (verified column by
column), so the ordinal mapping is correct:

```
0 date        1 datetime(->Timestamp)  2 description   3 description_short
4 display_name 5 filename  6 host  7 hostname  8 inode  9 macb
10 message  11 message_short  12 source  13 sourcetype  14 source_long
15 tag  16 time  17 timestamp_desc  18 timezone  19 type  20 user
21 username  22 zone
```

- **`datetime` format** is `2008-12-31T22:44:02.215500+00:00` (microseconds +
  `+00:00` offset). Kusto parses it as `datetime` with **zero nulls** across
  1240 rows. Unset MACB times surface as `0001-01-01T00:00:00Z`, which is
  forensically correct (no timestamp), not a parse failure.
- **`ignoreFirstRecord=true` works**: the header row is dropped, no junk
  null-timestamp row leaks into `CarFile()`/`CarProcess()`.
- **The dynamic CSV quoted correctly**: every one of 1240 rows parsed to exactly
  23 fields; no embedded-comma column shift.

**How one image breaks into ADX source types.** Three filesystem test images
(`ntfs1-gen0.E01`, `exfat1.E01`, `imageformat_mmls_1.E01`) produced:

| `source` | `sourcetype` / `source_long` | Rows | CarFile regex `\bfs\b\|ntfs\|file` |
|:--|:--|--:|:--:|
| `FILE` | `NTFS file stat` | 752 | ✅ |
| `FILE` | `File stat` | 486 | ✅ |
| `FILE` | `MacOS File System Events Disk Log Stream` | 2 | ✅ |

`timestamp_desc` — the field that makes the CAR `action` derivable — took five
distinct values, now **all** mapped after fix #4:

| `timestamp_desc` | CarFile `action` |
|:--|:--|
| `Creation Time` | `create` |
| `Content Modification Time` | `modify` |
| `Metadata Modification Time` | `modify` *(was unmapped)* |
| `File Last Modification Time` | `modify` *(was unmapped)* |
| `Last Access Time` | `read` |

> These are filesystem-only test images, so they exercise the `CarFile` lane
> only — `CarProcess`-from-Plaso (Prefetch/Amcache/AppCompatCache) needs a
> Windows image. The value proved here is the **L2tCsv schema, mapping, datetime
> parsing, header handling, and the `source_long → CAR-object` routing** — the
> mechanics every Plaso source shares. On a Windows image the *same* `L2tCsv`
> table additionally carries `sourcetype` values like `WinPrefetch`,
> `Amcache`, and registry sources, which the same regexes fan out to
> `CarProcess`/`CarFile`.

### Zeek — `network.ZeekConn` (fixture-driven ADX validation)

`conn.log` after `zeek-cut -C -U "%Y-%m-%dT%H:%M:%S%z"`: TSV, `#`-prefixed
headers, 21 columns (ordinals 0–20 = `ZeekConnMapping`).

- **`ts` renders ISO8601 as `2008-07-22T02:51:23+0000`** (offset *without* a
  colon). Kusto parses it as `datetime` → `…Z`. This was an open question about
  the ISO8601 story; it holds.
- `ingest-kusto.sh`'s Zeek path did its job live: the `#fields` order guard
  passed, `#`-lines were stripped, and the 21 columns landed in the right typed
  columns (`SrcIp`, `SrcPort`, `DestIp`, `DestPort`, `Proto`, `Service`,
  `ConnState` all correct).
- **`CarFlow()`** derived `action` from `ConnState` (`SF`→`end`, `REJ`→`end`),
  `packet_count = orig_pkts + resp_pkts` (6+5=11, 20+18=38 ✓), and
  `end_time = ts + duration` (`02:52:10` + 12s = `02:52:22` ✓).

### EvtxECmd — `host.EvtxEcmdJson` (fixture-driven ADX validation)

EvtxECmd `--json`, one object per line (`multijson`). Mapping is by JSON path;
the 25 columns landed, and `TimeCreated` parsed even with 7-digit fractional
seconds (`2025-01-01T10:14:29.1234567+00:00`).

- **`Payload` XML extraction** via `EvtxPayload(Payload, "Name")` works: from a
  4688 record it pulled `NewProcessName`, `ParentProcessName`, `CommandLine`,
  `NewProcessId`, and the *creator* `ProcessId` (not the top-level column) into
  `CarProcess`.
- **`CarProcess`** — `pid=420` (`0x1a4`), `ppid=4` (`0x4`), full command line.
- **`CarUserSession`** — a 4624 `LogonType=10` became `action="rdp"`, with
  `src_ip`/`src_port`/`logon_id` pulled from the payload.
- **`CarService`** — a 7045 became `action="create"`, `name="EvilSvc"`,
  `module_path="C:\Windows\Temp\evil.exe"`.

### Volatility 3 — `memory.VolatilityJson` (real tool, mixed data)

Memory is processed with **Volatility 3**
(`process-volatility.sh`). Its `-r json` renderer emits one JSON *array* of row
objects per plugin, with tree-plugin descendants nested under `__children`.

- **Real:** Volatility 3 ran on the 511 MB `pat-2009-12-05.winddramimage` and
  `banners.Banners` returned the kernel banner
  `ntoskrnl.pdb|1B2D0DFE2FB942758D615C901BE04692|2` — ingested and queryable.
  The **Windows symbol tables** needed by `pslist`/`netscan`/etc. download from
  the Volatility and Microsoft symbol servers, both blocked here, so those
  plugins error offline (`symbol table requirement was not fulfilled`) and were
  driven by fixtures.
- **Loader — constant-column injection.** `Plugin` and `SourceFile` are per-file
  constants and `.ingest` cannot inject a constant column — the exact reason the
  Velociraptor loader was "NOT IMPLEMENTED." `ingest-kusto.sh`'s
  `volatility_prepare` hook wraps each row as `{Plugin, SourceFile, Record}`
  JSON Lines, so `VolatilityJson` lands with `Plugin`/`SourceFile` populated and
  the plugin-specific fields reachable as `Record.Field`:

  ```
  VolatilityPslist()   ->  Timestamp             pid   ppid  name
                           2009-12-05T11:58:02Z   4     0     System
                           2009-12-05T11:58:05Z   624   4     smss.exe
                           2009-12-05T11:59:10Z   1180  624   explorer.exe
                           2009-12-05T12:03:44Z   1740  1180  outlook.exe
  ```
  `CreateTime` parses as `datetime`; `netscan` rows correlate to `pslist` by PID
  (`outlook.exe` 1740 → `74.125.19.104:80`). This is the same wrapper the
  Velociraptor (`Artefact`) loader needs — proven here.

> Memory is deliberately **not** a CAR object: MITRE CAR's dead-box objects are
> file/flow/process/user_session/service/registry/driver/module/thread, and
> live process/registry/driver/module/thread state from RAM is a different
> fidelity than dead-box artefacts. `memory.VolatilityJson` is queried directly
> (`VolatilityPlugins()`, `VolatilityPslist()`), not folded into `CarProcess()`.

### Mobile (Android) and macOS — `host.L2tCsv` (real Plaso parsers)

Plaso's parsers are platform-spanning, so Android and macOS artefacts flow into
the same `L2tCsv` table as Windows evidence — the source type is what tells them
apart. All of the below is **real Plaso output** (the parsers ran); where a full
disk image didn't fit the working disk, individual artefact files in their real
on-disk format were parsed instead.

**Android.** The smallest Android sample (`mobile-android_10`, a Pixel 3
Cellebrite extraction) is a **split/Zip64 archive whose companion parts are not
in the corpus** — its central directory references data past the single file's
end, so neither `unzip` nor Python can extract it, and the complete images are
5–16 GB (over disk). Its file listing does confirm the real artefact databases
are present (`mmssms.db`, `contacts2.db`, `bugle_db`, Chrome `History`, …). To
exercise the parsers, schema-accurate `mmssms.db` and `contacts2.db` were built
to Plaso's exact `REQUIRED_STRUCTURE` and parsed:

| `source` | `source_long` | Example message |
|:--|:--|:--|
| `LOG` | `Android SMS messages` | `Type: RECEIVED Address: +1555… Message: …` |
| `LOG` | `Android Call History` | `OUTGOING Number: +1555… Duration: 73 seconds` |

**macOS.** The only full Mac disk set (`scenarios-2019-tuck`, ~48 GB) exceeds the
working disk, but two real Mac source types are in ADX:

| `source` | `source_long` | Origin |
|:--|:--|:--|
| `FILE` | `MacOS File System Events Disk Log Stream` | **real** — `fseventsd` store on `exfat1.E01` |
| `WEBHIST` | `Safari History Database` | real Plaso `safari_historydb` on a schema-accurate `History.db` (Cocoa timestamps) |

Both land in `host.L2tCsv` with correct datetime parsing (Android `date`
milliseconds and macOS Cocoa `visit_time` both resolve to the right instant).

> **These do not map to a CAR object, and that is correct.** MITRE CAR's
> dead-box objects are file/flow/process/user_session/service/registry/driver/
> module/thread. SMS, call logs and browser history are neither — they stay in
> `L2tCsv` and are queried directly by `SourceLong`. The db-file *metadata*
> (`FILE`/`File stat`) still flows to `CarFile()` as for any filesystem row.
> Establishing this — which mobile/browser source types exist and where they do
> and don't belong — is exactly the "how it breaks down into source types" goal.

### Velociraptor — `host.VelociraptorJson` → `CarRegistry()` (registry re-sourced)

The `registry` CAR object lost its only source when the KAPE path was removed.
It is sourced again by **Velociraptor offline collectors running the EZ Tools**
(RECmd / Registry Explorer). Velociraptor runs on the endpoint, so a
format-accurate RECmd result set drove the validation; the loader and CAR
function are real.

- **Loader — same constant-column injection as Volatility.** `Artefact` and
  `SourceFile` are per-file constants `.ingest` can't set, so
  `velociraptor_prepare` wraps each RECmd record as `{Artefact, SourceFile,
  Record}` JSON Lines. `VelociraptorArtefacts()` then shows
  `Windows.Registry.RECmd` populated.
- **`CarRegistry()`** projects the CAR registry object from the dynamic
  `Record`, coalescing the EZ-tool field names (`KeyPath`/`ValueName`/
  `ValueData`/`ValueType`/`HivePath`, `LastWriteTimestamp`):

  ```
  Timestamp             action  key                                              value    data
  2025-01-01T09:00:00Z  modify  SOFTWARE\…\CurrentVersion\Run                     Updater  C:\Temp\evil.exe
  2025-01-01T09:03:12Z  modify  SYSTEM\…\Services\EvilSvc                         ImagePath C:\Windows\Temp\evil.exe
  2025-01-01T09:05:40Z  modify  SOFTWARE\…\Winlogon                              Shell    explorer.exe,C:\Temp\backdoor.exe
  ```
  `hostname` is derived from the per-host collection directory in the path
  (`velociraptor/<host>/…`), since RECmd output carries none. `action` is
  `modify`: a hive records a key's *last* write, so a row means created-or-
  changed, and dead-box can't split the two — the weaker claim is the honest one.
  `CarCoverage()` now reports `registry` populated → **6 of 9**.

### Linux — `host.L2tCsv` → cross-platform `CarUserSession()` (real logs)

Real Linux logs (a CentOS 7 DNS server's `/var/log` from
`scenarios-2020-linux-threat-analysis`, fetched from the manifest URLs) through
Plaso — **155,446 events**:

| `source` | `source_long` | Rows | What |
|:--|:--|--:|:--|
| `LOG` | `Log File` | 149,817 | syslog (cron, secure, maillog, journal) |
| `LOG` | `Audit Log` | 5,423 | Linux auditd |
| `LOG` | `UTMP session` | 31 | logins (wtmp/utmp) |
| `FILE` | `File stat` | 174 | file metadata |

Timestamps parse to sub-second precision (auditd `…334Z`, utmp `…572529Z`).

**`CarUserSession()` is now cross-platform.** The UTMP-session rows are Linux
logins — the same CAR object as Windows 4624. `CarUserSession()` unions the two:
the Windows branch parses the EvtxECmd payload, the Linux branch parses Plaso's
rendered UTMP message with `extract()` (`Status:` → action, `User:`, `Terminal:`,
`IP Address:`). A `platform` column distinguishes them; `EventId`/`LogonType`
are null for Linux (Windows concepts) rather than faked.

```
platform  action   user   src_hostname  hostname
linux     login    root   tty1          localhost     (USER_PROCESS)
linux     logout   …      …             …             (DEAD_PROCESS)
linux     boot     …      …             …             (BOOT_TIME)
```

**Deeper Linux CAR — three objects enriched from the same audit/syslog data:**

- **`CarProcess` ← cron.** syslog `CROND` lines record command executions;
  `Origin = "linux:cron"` carries the command line, invoking user and crond pid
  (ppid/parent null, like the Plaso artefacts). +428 rows. This host had **no
  `execve` audit rule** (`syscall=59` count: 0), so cron is the process
  evidence that is actually present — a host auditing execve would add a
  richer branch.
- **`CarService` ← systemd (auditd).** `SERVICE_START`/`SERVICE_STOP` →
  create/stop, unit name → `name`, systemd exe → `module_path`. 250 create /
  167 stop. `CarService()` is now **cross-platform** (Windows 7045 + Linux).
- **`CarUserSession` ← auditd PAM.** `USER_START`→login, `USER_END`→logout,
  carrying `acct`/`addr`/`hostname`/session-id — richer than utmp, and unioned
  with it (independent evidence for the same sessions, split by `SourceFile`).
  login 463 / logout 444.

No SSH logins were in this DNS-server sample (`sshd` accepted/failed: 0); the
PAM session events are the auth evidence that is present.

---

## Reproducing this

```bash
# 1. Plaso (real) — installs from PyPI; the corpus URLs are in the manifest
python3 -m venv /tmp/plaso-venv && . /tmp/plaso-venv/bin/activate && pip install plaso
#    fetch three small images (see samples-manifest.tsv) into
#    data_store/raw/disk_images/, then run psteal with the exact --fields from
#    process-log2timeline-Dynamic.sh (the script itself uses the Docker image,
#    which is blocked here; native psteal takes the same arguments).

# 1b. Memory (real tool) — Volatility 3 also installs from PyPI
pip install volatility3
#    fetch a small memory image (e.g. drives-nps-2009-patents *dramimage) into
#    data_store/raw/memory/, then: ./scripts/process-volatility.sh
#    (Windows plugins need symbol-server egress; banners works offline.)

# 2. Backend (real)
./scripts/deploy-kusto.sh -y
./scripts/apply-kusto-schema.sh
./scripts/ingest-kusto.sh            # l2t + zeek + evtx + volatility

# 3. Check
#    CarCoverage() in the mitre database
```

The Zeek/EvtxECmd fixtures used here are format-accurate stand-ins for the
engines that egress policy blocks; swap in real `conn.log` / EvtxECmd JSON on a
network that permits `zeek/zeek` and where a real `.evtx` is available, and the
ADX side is already proven to accept them.
