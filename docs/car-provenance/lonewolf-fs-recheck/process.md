# PROPERTY-PROVENANCE CATALOGUE — MITRE CAR `process`, **UNMINED FILESYSTEM ARTEFACTS**
## Grounded in the REAL LoneWolf Windows-10 disk image (plaso timeline)

**Object:** `process`. This pass is the *filesystem-artefact* sweep — the on-disk residue that names
a program, its command line, its launching user or its scheduled/autostart recipe — deliberately
scoped to artefacts the earlier LoneWolf re-check **did not** analyse.

**Builds on (do NOT redo):** `../process.md` already settled the
execution-artefact family — **prefetch, amcache, shimcache/appcompatcache, userassist, BAM, SRUM** —
and the `user`-from-`\Users\<name>\` gap. Those findings stand; this document assumes them and covers
everything else on disk.

**Evidence (full-file, not sampled from a fixture):**
`data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (6.6 GB, `LoneWolf.E01` via plaso).
Host `DESKTOP-PM6C56D`; principal user `jcloudy` (SID domain `S-1-5-21-2734969515-1644526556-1039763013`).
Every count below is a full-file tally over that JSONL; every quoted
record is a verbatim real row from it.

**Maps checked:** `byakugan/byakugan/mappings/{plaso_exec,plaso_registry,plaso_shellitem,plaso_fs_extra,
plaso_artifacts,jlecmd,recmd}.py`; `byakugan/{crosssource.py,relationships.yml,
cascade_relationships.yml,enrich.py}`; all `sources/*.yaml`.

---

## 0. The routing truth (why these artefacts don't fill `process`)

Grepping every map: the **only** disk sources whose `object` is `process` are
`plaso_exec_prefetch`, `plaso_exec_winreg` (amcache/userassist/bam/appcompatcache), `plaso_exec_cron`,
and `l2t_srum` — i.e. exactly the six the prior pass covered. **Every other disk artefact routes to a
`file` or `registry` object, or is dropped raw.** The consequence for `process`:

| plaso data_type | LoneWolf rows | where it goes today | process fields it *could* fill but doesn't |
|---|---:|---|---|
| `windows:registry:service` | **1796** | `plaso_registry` → **registry**/key_edit | image_path, exe, command_line (ImagePath+args), user/sid (ObjectName) |
| `windows:registry:task_scheduler:task_cache:entry` | **1454** | `plaso_registry` → registry (task_name **not even in native**) | task name only — the command is in the XML plaso doesn't read |
| `windows:lnk:link` | **1639** (350 w/ args, 521 w/ workdir) | `l2t_lnk` → **file** (and *Not-a-time* rows dropped) | exe/image_path (target), command_line (args), current_working_directory |
| `pe_coff:file` | **150708** | `plaso_pecoff` → **file** (time-free) | sha256_hash (of an on-disk PE) — reaches process only via a join (§4) |
| `windows:registry:run` | **27** | `plaso_registry` → registry (`entries` list) | exe/image_path/command_line (autostart command) |
| `olecf:dest_list:entry` | **72** | **raw** (`plaso_olecf` handles only summary_info) | launching-app identity (AppId), opened-target path |
| `windows:tasks:job` (.job) | **4** | **raw** (no `winjob` map exists) | image_path, exe, **command_line**, **user** — all present natively |
| `windows:tasks:trigger` | **6** | **raw** | same as .job + a scheduled-start time |
| `windows:registry:winlogon` | **12** | `plaso_registry` → registry (`command` native) | exe/command_line (Shell=explorer.exe, Userinit) |
| `windows:registry:diagnosed_applications` | **4** | `plaso_registry` → registry (`process_name` **dropped**) | exe (`process_name`=chrome.exe) |
| `windows:registry:boot_execute` | **3** | `plaso_registry` → registry (`value` **dropped**) | command_line/exe (autochk) |
| `windows:registry:key_value` → **RecentApps** | **74** | `plaso_registry` → registry (values list) | exe/image_path (AppPath), run-count, run-time, user |
| `windows:registry:key_value` → **Compatibility Assistant\Store** | **5 keys** | `plaso_registry` → registry (value-names) | exe/image_path (value name = full exe path), user |
| `windows:registry:key_value` → **MUICache / CIT** | 62 / 9 | `plaso_registry` → registry | MUICache: exe path (value name); CIT: opaque/hashed |

**Absent from this image entirely (0 rows, no plaso parser fired):** `windows:timeline:*`
(**ActivitiesCache.db**), any WMI CIM (`OBJECTS.DATA`), `windows:wer` (**WER**), RecentFileCache.bcf,
`$MFT`/`fs:ntfs:mft` (only `fs:stat` + `usn_change` present — consistent with the prior pass), and any
Authenticode/catalog verification. These are §5.

---

## 1. Per-field provenance — all 29 `process` fields, FILESYSTEM artefacts

Legend — **mined?**: **NO** = no map lands it on `process`; **reg/file** = lands on another object
only; **join** = reachable on `process` via cross-source enrichment; **yes(prior)** = covered by the
execution-artefact pass. Confidence C=Confirmed on this data, I=Inferred/structural.

| field | fs artefact → native field | action | mined? (where / NO) | conf & caveats |
|---|---|---|---|---|
| **exe** | .job `application` (basename); Service `image_path`/ImagePath; RecentApps `AppPath`; CompatAssist\Store value-name; diagnosed_apps `process_name`; MUICache value-name; LNK target/`env_var_location`; Winlogon `command`; Run `entries`; BootExecute `value` | create | **NO for all** (.job/dest_list/trigger raw; rest → **reg**/**file**) | C. Every one carries a real program name; none reaches `process.exe`. |
| **image_path** | .job `application` (full `C:\…\DropboxUpdate.exe`); **Service `image_path`** (`\SystemRoot\…\iagpio.sys`); RecentApps `AppPath` (`C:\Windows\system32\notepad.exe`); CompatAssist value-name (`C:\…\FileSyncConfig.exe`); LNK `local_path`/`env_var_location` | create | **NO** — Service `image_path` is a **canonical column but on the `registry` object**; RecentApps/CompatAssist ride the unindexable `values` list; .job raw; LNK → file | C. Highest-volume clean path is Service (1796) + RecentApps (74). |
| **command_line** | **.job `application`+`parameters`** (`…DropboxUpdate.exe` + `/ua /installsource scheduler`); **LNK `command_line_arguments`** (350 rows, e.g. `/name Microsoft.DeviceManager`); Service ImagePath value (svchost `-k …`); Run `entries` command; Winlogon `command`; BootExecute `value` (`autocheck autochk *`) | create | **NO** (.job raw; LNK → file, *Not-a-time* dropped; Service/Run/Winlogon/BootExecute → reg native) | **C — CORRECTS the prior "no disk source for command_line".** .job and LNK are genuine disk sources of process ARGUMENTS. Recorded-not-run for LNK/Run/task (a recipe, not proof of an invocation). |
| **current_working_directory** | **LNK `working_directory`** (521 rows) | create | **NO** — → file native | C. The *only* disk source for cwd. It is the shortcut's recorded target workdir (recipe), not a live cwd. |
| **user** | **.job `username` = `DESKTOP-PM6C56D\jcloudy`** (a REAL name, not `"-"`); RecentApps/CompatAssist/MUICache per-user NTUSER path `\Users\jcloudy\`; Service **ObjectName** (LocalSystem / a run-as account) | create | **NO** (.job raw; hive-path un-mined exactly as the prior `\Users\<name>\` gap; ObjectName not extracted) | **C — the .job is the one disk artefact whose native user is populated.** Everything else needs the `\Users\<name>\` regex the engine already proves in `recmd.py`. |
| **sid** | Service ObjectName *iff* it is a SID; per-user hive path (but plaso renders `\Users\name\`, not `HKU\<SID>` — dead, per prior) | create | **NO** | I. No new strong disk SID source beyond BAM (prior). .job gives name, not SID. |
| **sha256_hash** | **`pe_coff:file` sha256** of the on-disk PE, keyed by path (150708 rows) | create | **join** — not a native `process` field, but `relationships.yml:process_image_content` (+ `crosssource.py` `definitive_content`) links a `process` whose `image_path` == a `file`'s `file_path`, attaching the PE's hash | **C — CORRECTS the prior "no sha256 for a disk process".** Works only when an execution artefact's path matches a pe_coff path; the join is wired but hash never lands *on* the process row. |
| **sha1_hash** | amcache `file_identifier` (prior pass — stranded, not `sha1`) | create | **NO** (prior) | C. No new fs source. |
| **md5_hash** | — none | create | NO | I. No disk artefact offers MD5. |
| **guid** | minted uuid5 spindle (as for every mapped disk row) | create | reg/file synth | I. Any newly-mapped source would get a synthetic spindle, never a Windows GUID. |
| **hostname** | `image_hostname` on all rows; dest_list also has native `hostname`=`desktop-pm6c56d` | create | reg/file (stamped) | C. `DESKTOP-PM6C56D` universally; fills trivially once a row is mapped. |
| **fqdn** | — (workgroup host, no dot) | — | NO | C. No domain. |
| **integrity_level** | Task **XML** `<Principal><RunLevel>` (HighestAvailable/LeastPrivilege) | create | **NO source in this pipeline** | I. The .job format has no RunLevel; the Task **XML** (`\Windows\System32\Tasks\*`) that does is **not parsed by plaso** (only the task_cache *registry* is, and it has no principal). Structurally null here. |
| **command_line (parent) / parent_exe / parent_image_path / parent_guid** | — | create | NO | I. No disk artefact records a parent. Structural. |
| **pid / ppid** | — (residue, no live id) | create | NO | I. Structural — same as the execution-artefact pass. |
| **env_vars** | — (LNK `env_var_location` is the *target's* path, NOT a process env block) | create | NO | I. Memory-only field. Do not mistake LNK env_var_location for `env_vars`. |
| **signer** | — (pe_coff carries NO Authenticode; catalog/$Secure not parsed) | create | NO | C. plaso `pe` gives imphash/pe_type/sections but does **not** verify signatures. Structurally null on disk. |
| **signature_valid** | — (no WinVerifyTrust / catalog lookup in the pipeline) | create | NO | C. Same — no signature verification anywhere on the disk lane. |
| **access_level / call_trace / target_address / target_guid / target_name / target_pid** | — (`access`-action fields) | access | NO | I. Every disk artefact is a `create`; the `access` sextet has no disk source (Sysmon 10 / memory only). |
| **uid** | — (no numeric uid in any Windows disk artefact) | create | NO | I. Structural. |

**FS artefacts CAN newly fill (if mapped):** `image_path`/`exe` (Service, RecentApps, CompatAssist,
.job, LNK), **`command_line`** (.job, LNK, Service, Run), **`current_working_directory`** (LNK),
**`user`** (.job natively; others via hive path), and `sha256_hash` (pe_coff, via the existing join).
Everything else is null, and for the parent/pid/ppid/access/env/integrity/signer set that null is
**structural and honest**, not a pipeline omission — with one nuance: `integrity_level` *does* have a
theoretical disk source (Task XML RunLevel) that this pipeline simply never parses.

---

## 2. The structurally-hard fields — which fs artefact uniquely supplies them

The prior pass concluded `command_line`, `user`, `integrity_level` and the parent set are unfillable
from disk. Real filesystem data revises three of those:

- **`command_line` — .job and LNK are genuine disk sources of process arguments.** Prefetch/shimcache/
  amcache/UA/BAM record a *path only* (prior pass, correctly). But the **Scheduled-Task `.job`** carries
  `application` + `parameters` — a complete command line — and **1,639 LNKs carry
  `command_line_arguments` on 350 of them**. Verbatim: `application="C:\Program Files (x86)\Dropbox\
  Update\DropboxUpdate.exe"`, `parameters="/ua /installsource scheduler"`. This is the single most
  important correction in this pass.
- **`current_working_directory` — LNK `working_directory` (521 rows) is the only disk source.** Nothing
  else on disk records a working directory.
- **`user` — the `.job` is the only disk artefact whose native user is a real name.** `username =
  "DESKTOP-PM6C56D\jcloudy"` (contrast the `"-"` on 100% of prefetch/shimcache/UA/amcache from the
  prior pass). Everywhere else the account is still in the `\Users\<name>\` path, unmined.
- **`integrity_level`** stays null — its disk source (Task XML `<RunLevel>`) is a file plaso does not
  parse; the `.job` format does not expose it.

---

## 3. Ranked highest-value UNMINED opportunities (with real LoneWolf evidence)

**Tier 1 — clean, high-volume, direct `process/create` shape:**

1. **RecentApps** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`, **74 rows**,
   per-user `jcloudy`). A UserAssist-class GUI-launch artefact with a *clean full path*. Real values:
   `AppPath="C:\Windows\system32\notepad.exe"`, `LaunchCount=7`, `LastAccessedTime=131666161949090000`
   (FILETIME), `AppId="{1AC14E77-…}\NOTEPAD.EXE"`. Today it is an opaque `windows:registry:key_value`
   → registry, with `AppPath` buried in the unindexable `values` list. **Map to process:** exe/
   image_path←AppPath, number_of_executions←LaunchCount, ts←LastAccessedTime, user←`\Users\jcloudy\`
   from `display_name`. **Best cost/value on this image** — a distinct source with a real path *and* a
   real user, both currently dropped.

2. **Services** (`windows:registry:service`, **1796 rows**). A service is a launcher. `image_path` is
   already the canonical column — but on the `registry` object. Real row: `name="iagpio"`,
   `image_path="\SystemRoot\System32\drivers\iagpio.sys"`. For win32 (non-driver) services the `values`
   list holds `ImagePath` (svchost command line → **command_line**) and `ObjectName` (the run-as
   account → **user/sid**). **Map to process/create** (autostart-configured), carrying image_path/exe
   now and command_line/user once the values list is flattened. Highest volume of any candidate.

3. **Scheduled-Task `.job` + `trigger`** (`windows:tasks:job` **4** + `windows:tasks:trigger` **6**,
   parser `winjob`, currently **raw — no map exists**). Lowest volume, **highest fidelity**: the only
   disk rows that give `image_path` + **`command_line`** + a **real `user`** together (see §2).
   Verbatim above. A ~15-line `winjob` map → process/create closes command_line+user+cwd in one source.

**Tier 2 — real execution/autostart evidence, lower volume or messier:**

4. **AppCompatFlags → Compatibility Assistant\Store** (per-user, **5 keys**, several exe each). The
   value *names* are full paths of programs that ran and tripped the compat assistant:
   `"C:\Program Files\DellTPad\ApMsgFwd.exe"`, `"C:\Users\jcloudy\AppData\Local\Microsoft\OneDrive\…\
   FileSyncConfig.exe"`, `"…\OneDriveSetup.exe"`, `"…\OfficeClickToRun.exe"`. Genuine
   presence-implies-execution evidence with a per-user hive → process exe/image_path + user. Today an
   opaque key_value key.

5. **Winlogon (12) / Run+RunOnce (27) / BootExecute (3)** — autostart commands →
   process. Real: Winlogon `command="explorer.exe"` (Shell, trigger Logon); BootExecute
   `value="autocheck autochk *"`. Note the HKLM `Run`/`RunOnce` `entries` list is **empty** on this
   image (nothing persisted there); value is in per-user hives / other keys. Low volume, but the
   command strings are dropped (`value`/`entries` not promoted).

6. **LNK launch-recipes** (350 with args, 521 with working_directory). Rich (`command_line_arguments`,
   `working_directory`, `env_var_location=%windir%\explorer.exe`) but **quality-caveated**: (a) a
   shortcut is a *recipe*, not proof of a run; (b) most LoneWolf LNKs here are system Start-Menu/WinX
   applets, not user-run binaries; (c) the `l2t_lnk` map only emits create/modify/read rows and sends
   **`Not a time`** to `default:None` — and *every* args-bearing example above is `Not a time`, so they
   are dropped before any object is built (this compounds the prior BACKLOG's "931/1639 LNK drop"). If
   promoted at all, promote to `file` first (as today) and treat a process view as a lead.

7. **diagnosed_applications `process_name`** (4 rows, `chrome.exe`) — literal process name at a "Last
   Detection Time"; trivially → process/exe, but tiny and single-app; `process_name` isn't even in
   `plaso_registry`'s native extract, so it's lost entirely.

**Tier 3 — hash enrichment (already half-wired):**

8. **pe_coff:file sha256 → process via image-path join.** 150,708 on-disk PEs carry a real SHA-256 by
   path. `relationships.yml:process_image_content` and `crosssource.py:definitive_content` already
   relate a `process` (from prefetch/shimcache/amcache path) to the `file` at the same path/hash — so
   the disk process's binary hash is *reachable* even though execution artefacts carry no hash. Verify
   the join actually fires on real paths; it is the cleanest route to `sha256_hash` for a
   disk-only process. (No signer — pe_coff does not do Authenticode; see §5.)

---

## 4. Jump Lists — the launching app (partially there, mostly raw)

`olecf:dest_list:entry` (**72**, parser `olecf/olecf_automatic_destinations`) is **raw** — the
`plaso_olecf` map handles only `olecf:summary_info`. Each DestList entry names the **launching
application** by the AutomaticDestinations filename hash (real: `display_name=…\AutomaticDestinations\
f01b4d95cf55d32a.automaticDestinations-ms`, `f01b4d95cf55d32a` = a known AppID) and the opened target
(`path="knownfolder:{FDD39AD0-…}"`), plus DLT `droid_*` GUIDs, `entry_number`, `pin_status`,
`hostname`. For the **process** object the value is indirect (AppID→app needs a lookup table, and the
target here is a folder). The *file* targets inside jump lists already reach `file` via
`windows:shell_item:file_entry` → `plaso_shellitem`. Net: dest_list is a weak process source; its main
loss is the launching-app identity, not a program path.

---

## 5. Honest no-sources (absent from this image / no parser / structural)

- **ActivitiesCache.db (Windows Timeline)** — **the single richest possible `process` disk source**
  (exe + command line via the activity payload + user + window title/`DisplayText` + start/end →
  **duration**). plaso's `windows_timeline` plugin exists but **fired 0 rows** here — no
  `windows:timeline:*` data_type, and no `ActivitiesCache`/`ConnectedDevicesPlatform` key in
  key_value. Either the plugin isn't in this plaso build's default set or the DB wasn't reached.
  **Flag for the provisioning epic (#134):** if Timeline matters, the plaso lane must parse
  `\Users\<u>\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db`. No evidence to mine today.
- **WMI `OBJECTS.DATA` (CommandLineEventConsumer → command_line)** — plaso has **no CIM-repository
  parser**; 0 rows. A real persistence/command_line source, absent. Needs a dedicated parser.
- **WER reports** — no `windows:wer` rows; the crashed-process path+version+modules are not ingested.
- **RecentFileCache.bcf** — no plaso parser; absent.
- **$MFT resident PE metadata / timestomp** — no `$MFT` data_type on LoneWolf (only `fs:stat` +
  `fs:ntfs:usn_change`), confirming the prior pass; the resident-attribute/`$FN` angle has no input.
- **Authenticode via catalog / `$Secure`** — no signature verification anywhere on the disk lane;
  `signer`/`signature_valid` are structurally null (pe_coff gives imphash/sections, never a signer).
- **hiberfil.sys / pagefile.sys carving** — memory territory (the `volatility` lane on `memdump.mem`
  is the live pid/ppid/parent/integrity source), not the plaso disk lane; out of this fs scope.
- **CIT** (`AppCompatFlags\CIT`, 9 rows) — present but **opaque**: value names are hashes
  (`"2BB8F37D"=1`), not readable program paths; plaso does not decode CIT. No usable process field.
- **MUICache** (62 key_value hits) — real MUICache lists exe paths as value names, but on this image
  the strong hits are `muicachebuilder` component-family keys under COMPONENTS (build metadata), not
  the classic `UsrClass…\MuiCache` exe→friendly-name map; treat as a weak/secondary exe-path source,
  behind RecentApps and Compatibility Assistant\Store.
- **RecentApps AppSwitched / ShellNoRoam** — 0 hits on this image.

---

## 6. Through-line (vs the prior LoneWolf pass)

The execution-artefact pass proved the pipeline drops the **user** that sits in the artefact path. This
filesystem pass finds the same pattern one level up: **the disk is full of program paths, command lines
and a real username that never reach the `process` object because the artefact is routed to `registry`
or `file`, or dropped raw.** Concretely, on real LoneWolf data:
- **command_line and current_working_directory — declared unfillable from disk — actually have disk
  sources** (`.job` application+parameters; LNK command_line_arguments+working_directory).
- **A real `user` (`DESKTOP-PM6C56D\jcloudy`) is sitting, populated, in 4 `.job` rows that no map
  reads.**
- **RecentApps + Services (1,870 rows) carry clean full exe paths** that land as opaque registry keys.
- **sha256 for a disk process is reachable** via the already-wired image-path/content join to the
  150,708 pe_coff file hashes.
The cheapest wins are RecentApps (a values-list flatten + the `\Users\<name>\` regex) and a ~15-line
`winjob` map; the biggest volume is Services; the biggest *absent* prize is ActivitiesCache.db.
