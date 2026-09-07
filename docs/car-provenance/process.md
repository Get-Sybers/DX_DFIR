# PROPERTY-PROVENANCE CATALOGUE — MITRE CAR `process`

**Object:** `process` — "A running program on a computer." The single most important CAR object:
**67 of 102** CAR analytics (66%) reference it, and its `create` action alone is cited **132×**
across their `data_model_references`. If any object must be complete, it is this one.

**Actions:** `create`, `terminate`, `access`.
**Canonical fields (29):** access_level, call_trace, command_line, current_working_directory,
env_vars, exe, fqdn, guid, hostname, image_path, integrity_level, md5_hash, parent_command_line,
parent_exe, parent_guid, parent_image_path, pid, ppid, sha1_hash, sha256_hash, sid,
signature_valid, signer, target_address, target_guid, target_name, target_pid, uid, user.

Grounded in (read verbatim):
`third_party/piiat-mitrecar/third_party/car/data_model/process.yaml` (+ `docs/data_model/process.md`);
`car_data_model.json`; the live engine maps
`piiat_mitrecar/mappings/{sysmon,evtx_windows,plaso_exec,plaso_srum}.py`,
`piiat_mem/mappings.py`, the memory plugin `plugins/windows/piiat/{processes,access}.py`;
generated sources `sources/{evtx_sysmon,evtx_process,memory,plaso_exec_prefetch,plaso_exec_winreg,plaso_exec_cron}.yaml`;
`piiat_mitrecar/enrich.py` + `relationships.yml`; `docs/CAR-Relations.md`; the quarantined
`to-be-validated/evtx_audit.yml`; and real evidence
(`data_store/processed/volatility/memdump.mem/car.db`, 180 process rows;
`data_store/processed/windows_logs/.../log_EvtxECmd_Output.json`).

---

## A. Source universe (process producers)

| # | Source (artefact key / predicate) | Tool / parser | Action(s) | Live? | Nature |
|---|---|---|---|---|---|
| S1 | **Sysmon EID 1** `evtx_sysmon`/`sysmon_proc_create` | EvtxECmd (Sysmon/Operational) | create | ✅ active | create-time telemetry — **richest single source** |
| S2 | **Sysmon EID 5** `evtx_sysmon`/`sysmon_proc_terminate` | EvtxECmd | terminate | ✅ active | terminate telemetry (shares ProcessGuid with S1) |
| S3 | **Sysmon EID 10** `evtx_sysmon`/`sysmon_proc_access` | EvtxECmd | access | ✅ active | cross-proc handle open (cred-dump/injection) |
| S4 | **Security 4688** `evtx_process`/`evtxwin_is_sec_4688` | EvtxECmd (Security) | create | ✅ active | audit-log process create |
| S5 | **Security 4689** `evtx_audit.yml`/`security_4689_process_exit` | EvtxECmd (Security) | terminate | ⛔ **INERT** (quarantined, un-validated) | audit-log process exit |
| S6 | **Memory processes** `windows.piiat.processes` | PIIAT-Mem / Volatility 3 | create | ✅ active | live PEB+token snapshot — **only source for a resident process with cleared logs** |
| S7 | **Memory access** `windows.piiat.access` | PIIAT-Mem (handle scan) | access | ✅ active | open Process-type handle = "A accesses B" |
| S8 | **Prefetch** `plaso_exec_prefetch`/`plaso_is_prefetch_execution` | Plaso L2tPrefetch (≈PECmd) | create | ✅ active | execution **proof** (run count/times) |
| S9 | **Amcache** `plaso_exec_winreg/amcache` | Plaso L2tWinreg (≈AmcacheParser) | create | ✅ active | presence→execution **inferred**; carries SHA-1 |
| S10 | **Userassist** `plaso_exec_winreg/userassist` | Plaso L2tWinreg | create | ✅ active | GUI-launch counter |
| S11 | **BAM/DAM** `plaso_exec_winreg/bam` | Plaso L2tWinreg | create | ✅ active | last-run time **+ per-user SID** |
| S12 | **AppCompatCache/Shimcache** `plaso_exec_winreg/appcompatcache` | Plaso L2tWinreg (≈AppCompatCacheParser) | create | ✅ active | presence-**inferred**; `native.execution_inferred=True`, time is $SI mtime, **not a run time** |
| S13 | **SRUM app usage** `l2t_srum/application_usage` | Plaso esedb/srum (SrumECmd can't run on Linux) | create | ✅ active | app demonstrably ran in the recorded hour |
| S14 | **Cron** `plaso_exec_cron`/`plaso_is_cron_task_run` | Plaso L2tText/syslog | create | ✅ active | Linux `CMD` task-run line |

**Identity notes carried over from grounding, so the tables below are not misread:**
- **S3 (EID 10)** is the ONLY Sysmon EID that populates process-`access` columns. **Sysmon EID 8
  (CreateRemoteThread) is mapped to the `thread` object, NOT process** — its Target* values land on
  `thread.tgt_*`/`native`, so it does **not** fill `process.target_*`. (Corrects a common assumption.)
- **Amcache "Link Time" row** (`plaso_exec_winreg/amcache_link_time`) is deliberately mapped to a
  **`file`** record (the PE compile stamp), **not** process — so it is not a process source and does
  not enter the timeline.
- **guid**: only Sysmon `ProcessGuid` (S1/S2) is a *real* Windows process GUID. Memory mints
  `proc-<offset>`; 4688 mints a per-record event id; every Plaso source mints a uuid5 **spindle**
  entity id (`piiat_mitrecar/spindle.yml`). All fill the `guid` slot honestly but are synthetic.
- **parent_guid** is never a native column — `enrich.py` (`ev["parent_guid"]`) resolves it, then
  inherits `parent_exe/parent_image_path/parent_command_line` from the resolved parent
  (`relationships.yml → from_parent_process`).

---

## B. Per-field provenance (the catalogue)

Legend — **map?**: ✅ mapped (file:line) · ⛔ mapped-but-inert · ✗ not mapped / no source.
Confidence — **D** definitive (native identity), **H** heuristic (pid+window / presence-inferred),
**C** config-conditional.

| Field | Sources → native field (✅ live · ⛔ inert · ✗ unmapped) | Action(s) | Currently mapped? | Confidence & caveats |
|---|---|---|---|---|
| **command_line** | S1 `CommandLine`; S4 `CommandLine`; S6 `CommandLine` (PEB); S14 `command` (full) · ✗ PowerShell-console/PSReadLine, bash_history, WMI-Activity, 4104 (all raw) | create | ✅ S1 `sysmon.py:269`, S4 `evtx_windows.py:318`, S6 `mem/mappings.py:153`, S14 `plaso_exec.py:384` | **D**/**H**. **S4 only if cmdline process-creation auditing is ON** (else honest null). S6 null when PEB paged out (evidence: 157/180). Execution artefacts (S8–S13) record path only, **never args**. Analytics #2 field (46 refs). |
| **exe** | S1/S2 `Image`; S3 `SourceImage`; S4 `NewProcessName`; S5 `ProcessName`; S6 `basename(Path)`→`ImageFileName`; S7 `ProcessName`; S8 `executable`; S9 `basename(full_path)`; S10 `basename(UEME_RUNPATH)`; S11 `basename(path)`; S12 `basename(path)`; S13 `basename(application)`; S14 `basename(command[0])` | create, terminate, access | ✅ **every source** (S5 ⛔) | **D**. The one near-universal field (180/180 in memory) and the **#1 analytics field (47 refs)**. S6 always fills via 15-char `ImageFileName` fallback even when `Path` null. |
| **image_path** | S1/S2 `Image`; S3 `SourceImage`; S4 `NewProcessName`; S5 `ProcessName`; S6 `Path` (PEB); S9 `full_path`; S10 path-form value only; S11 `path`; S12 `path` (NT `\??\`); S13 `\Device\...` form only; S14 rooted `/path` only · **✗ S8 (prefetch)**, **✗ S7 (mem-access)** | create, terminate, access | ✅ most; **✗ prefetch**, **✗ mem-access** | **D**/**H**. **Prefetch fills `exe` only — `image_path` stays null** (`path_hints[]` unindexable → surfaced native). S10/S13/S14 fill only when the value is provably a path. S6 157/180 (null→exe fallback). |
| **pid** | S1 `ProcessId`; S2 `ProcessId`; S3 `SourceProcessId`; S4 `hex_int(NewProcessId)`; S5 `hex_int(ProcessId)`; S6 `PID`; S7 `PID`; S14 `pid` (crond worker) · **✗ S8–S13** | create, terminate, access | ✅ live sources; ✗ execution-inferred | **D**. Execution artefacts (prefetch/amcache/UA/BAM/shimcache/SRUM) record **no pid** — honest null. |
| **ppid** | S1 `ParentProcessId`; S4 `hex_int(ProcessId)` (creator); S6 `PPID` · ✗ all others | create | ✅ S1, S4, S6 | **D**. Only the three create-time live sources carry it. |
| **parent_exe** | S1 `basename(ParentImage)`; S4 `basename(ParentProcessName)`; S6 `basename(ParentPath)`; *enrich* from resolved parent | create | ✅ S1, S4, S6 (native); enrich fill | **D**. Native on all three; **#3 analytics field (16 refs)**. |
| **parent_image_path** | S1 `ParentImage`; S4 `ParentProcessName`; S6 `ParentPath` | create | ✅ S1, S4, S6 | **D**. |
| **parent_command_line** | S1 `ParentCommandLine` (native) · S6/S4 via *enrich* inheritance from resolved parent | create | ✅ S1 `sysmon.py:271`; S4/S6 enriched | **D** (S1); **D/H** (enrich: definitive via ParentProcessGuid/memory guid, heuristic via 4688 ppid+window). Only Sysmon EID 1 carries it *natively*. |
| **parent_guid** | **Resolved, never native.** Key: S1 `ParentProcessGuid`→definitive; S6 parent guid→definitive; S4 ppid+create-window→heuristic | create | ✅ via `enrich.py:474` | **D** (S1/S6, 164/180 in memory) vs **H** (S4). No source asserts it directly. |
| **guid** | S1/S2 `ProcessGuid` (**real**); S6 `proc-<offset>` (synth 180/180); S4 record-id (synth); S8–S14 uuid5 **spindle** (synth); S3/S7 event-id for the access row | create, terminate, access | ✅ all | **D**. **Only Sysmon ProcessGuid is a true GUID**; everything else is a minted identity filling the slot. On `access`, the row `guid` is the event id — the process's own guid is `owning_guid` (S3 `SourceProcessGUID`, S7 `proc_guid(OwnerOffset)`). |
| **hostname** | S1/S2/S3 `Computer`[0]; S4 `host_label(Computer)`; S6 image_context; S8–S12 `image_hostname`; S14 `image_hostname`→`hostname` · **✗ S13 (SRUM)** | create, terminate, access | ✅ near-universal; **✗ SRUM** | **D**. **SRUM app-usage sets no host key** — a real (small) gap. |
| **fqdn** | S1/S2/S3 `Computer` **only when it contains a dot** · **✗ S4, ✗ S6, ✗ all Plaso** | create, terminate, access | ✅ Sysmon only (conditional) | **C**. Only Sysmon, and only when `Computer` is a real FQDN. **4688 sets hostname but NOT fqdn.** Memory/Plaso carry hostname without domain (0/180). Frequently null. |
| **integrity_level** | S1 `IntegrityLevel` (string); S4 `MandatoryLabel` (S-1-16 SID→vocab); S6 token label · ✗ all Plaso | create | ✅ S1, S4, S6 | **D**. Normalized to low/medium/high/system across sources. Memory 164/180. |
| **current_working_directory** | S1 `CurrentDirectory`; S6 `Cwd` (PEB) · **✗ S4, ✗ all Plaso** | create | ✅ S1, S6 only | **D**. **Only Sysmon EID 1 and memory** supply CWD — 4688 and every execution artefact leave it null. |
| **env_vars** | **S6 `EnvVars` (PEB) — SOLE SOURCE** (156/180) · ✗ everything else | create | ✅ **memory only** `mem/mappings.py:165` | **D**. **Structurally memory-exclusive.** No log or disk artefact records a process's environment block. |
| **user** | S1 `User`; S2 `User`; S3 `SourceUser`; S4 `TargetUserName`→`SubjectUserName`; S5 `SubjectUserName`; S6 `User` (token); S8 `username`; S9 `username`; S10 `username`; S11 `username`; S12 `username`; S14 `username` · **✗ S7 (mem-access), ✗ S13 (SRUM)** | create, terminate, access | ✅ broad (S5 ⛔) | **D**/**C**. Plaso `username` is usually `"-"`→null; the real owner hides in `native.hive_user_sid` (UA). `enrich.py` canonicalizes well-known SIDs → names and fills blanks (e.g. "Local System" ×). |
| **sid** | S4 `TargetUserSid`→`SubjectUserSid` (S-1-0-0 guarded); S5 `SubjectUserSid`; S6 `Sid` (token, 164/180); S11 `user_identifier`; S13 `user_identifier` (S-1- form) · **✗ S1 (Sysmon EID1 has User name, NO SID)** · ✗ S8/S9/S10/S12/S14 | create | ✅ S4, S6, S11, S13 (S5 ⛔) | **D**. **Key gap: Sysmon EID 1 does not carry a SID** — the map leaves it null; SID for a Sysmon-only host comes only via memory or 4688. Userassist's `hive_user_sid` is native-only (join key), not canonical `sid`. |
| **uid** | S6 `Sid` (Windows token SID reused as uid, 164/180) · **✗ everything else** | create | ✅ **memory only** `mem/mappings.py:161` | **D**. Effectively memory-exclusive. 4688/BAM/SRUM fill `sid` but **not** `uid`; cron maps `username`→user, no numeric uid. Linux uid has **no live source**. |
| **md5_hash** | S1 `Hashes` (`MD5=`) **iff MD5 in Sysmon HashAlgorithms** · **✗ S9 amcache (SHA-1 only), ✗ S6 (0/180), ✗ all else** | create | ✅ **Sysmon EID 1 only** `sysmon.py:153` | **C**. Single-sourced and config-dependent — often null. |
| **sha1_hash** | S1 `Hashes` (`SHA1=`, config); **S9 amcache `sha1`** (definitive on-disk hash) · ✗ S6 (0/180) | create | ✅ S1, **S9** `plaso_exec.py:286` | **D** (amcache) / **C** (Sysmon). **Amcache is the key non-Sysmon hash source** — the only hash for a binary that is gone or was never Sysmon-logged. |
| **sha256_hash** | S1 `Hashes` (`SHA256=`, Sysmon default) · **✗ amcache (SHA-1 only), ✗ memory, ✗ all else** | create | ✅ **Sysmon EID 1 only** `sysmon.py:155` | **C**. The model's default hash, yet **single-sourced** here. Null without Sysmon. |
| **access_level** | S3 `GrantedAccess`; S7 `GrantedAccess` · ✗ else | access | ✅ S3 `sysmon.py:419`, S7 `mem/mappings.py:181` | **D**. Raw mask (e.g. `0x1FFFFF`), not decoded. Access action only. |
| **call_trace** | S3 `CallTrace` · **✗ S7 (memory has no call stack), ✗ else** | access | ✅ **Sysmon EID 10 only** `sysmon.py:420` | **D**. Sysmon-exclusive; access only. |
| **target_pid** | S3 `TargetProcessId`; S7 `TargetPid` · ✗ else | access | ✅ S3, S7 | **D**. Access only. |
| **target_guid** | S3 `TargetProcessGUID`; S7 `proc_guid(TargetOffset)` · ✗ else | access | ✅ S3 `sysmon.py:417`, S7 `mem/mappings.py:183` | **D**. Access only. |
| **target_name** | S3 `basename(TargetImage)`; S7 `TargetName` · ✗ else | access | ✅ S3, S7 | **D**. Access only. |
| **target_address** | **✗ NO SOURCE.** Model example (`08048000-0804c000`) is a Linux `/proc/<pid>/maps` range; Sysmon EID 10 has no address range (EID 8 `StartAddress`→`thread.start_address`). | access | ✗ **none** | Honest no-source. Not populated by any current or realistically-addable Windows source. |
| **signer** | **✗ NO PROCESS SOURCE.** Sysmon EID 1 `Company`/`OriginalFileName` are kept native (a PE string ≠ Authenticode signer — deliberate near-miss avoidance). Amcache `Publisher` not mapped. (Only `module`/`driver` EID 6/7 map `signer`.) | create | ✗ **none** | **Honest gap.** Would need PE Authenticode parse (not done) or amcache Publisher promotion. Structurally null everywhere for process. |
| **signature_valid** | **✗ NO PROCESS SOURCE** (0/180). Same story as `signer` — only module/driver EID 6/7 `SignatureStatus` map it. | create | ✗ **none** | **Honest gap.** No WinVerifyTrust step in the process path. |

---

## C. Currently-mapped fill matrix (live sources only)

`✔` native/derived at map time · `⊕` filled by enrichment (parent/owner inherit or SID canonicalization) ·
blank = null.

### create
| field | S1 Sysmon1 | S4 4688 | S6 Mem | S8 Prefetch | S9 Amcache | S10 UserAssist | S11 BAM | S12 Shimcache | S13 SRUM | S14 Cron |
|---|---|---|---|---|---|---|---|---|---|---|
| exe | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| image_path | ✔ | ✔ | ✔ | | ✔ | ○ | ✔ | ✔ | ○ | ○ |
| command_line | ✔ | ○ | ✔ | | | | | | | ✔ |
| pid | ✔ | ✔ | ✔ | | | | | | | ✔ |
| ppid | ✔ | ✔ | ✔ | | | | | | | |
| parent_exe | ✔ | ✔ | ✔ | | | | | | | |
| parent_image_path | ✔ | ✔ | ✔ | | | | | | | |
| parent_command_line | ✔ | ⊕ | ⊕ | | | | | | | |
| parent_guid | ⊕D | ⊕H | ⊕D | | | | | | | |
| guid | ✔real | ✔synth | ✔synth | ✔synth | ✔synth | ✔synth | ✔synth | ✔synth | ✔synth | ✔synth |
| hostname | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | | ✔ |
| fqdn | ○ | | | | | | | | | |
| integrity_level | ✔ | ✔ | ✔ | | | | | | | |
| current_working_directory | ✔ | | ✔ | | | | | | | |
| env_vars | | | ✔ | | | | | | | |
| user | ✔ | ✔/⊕ | ✔/⊕ | ○ | ○ | ○ | ✔ | ○ | | ✔ |
| sid | | ✔ | ✔ | | | | ✔ | ✔ | | |
| uid | | | ✔ | | | | | | | |
| md5_hash | ○ | | | | | | | | | |
| sha1_hash | ○ | | | | ✔ | | | | | |
| sha256_hash | ○ | | | | | | | | | |

`○` = conditional (config/audit policy on, or value provably a path/host).

### terminate — **S2 Sysmon EID 5** (active) · S5 4689 (⛔ inert)
Fills: `exe, image_path, pid, user, guid(real), hostname, fqdn○`. (4689 would add `sid`.)
**Memory emits no terminate** (snapshot: 180/180 create, 0 terminate); exit times feed only enrich R2 window-bounding.

### access — **S3 Sysmon EID 10** + **S7 memory access** (both active)
Fills: `pid, exe, image_path(S3), access_level, call_trace(S3 only), target_pid, target_guid, target_name, user(S3 only), hostname/fqdn(S3)`.
*Evidence note:* both maps exist but neither fired in the sampled corpus (car.db access=0; raw evtx sample had EID 1/5 only, no EID 10) — access is real but sparse in current test data.

---

## D. Coverage summary

- **Fully, richly covered (multi-source, high confidence):** exe, image_path, pid, ppid, parent_exe,
  parent_image_path, integrity_level, user, hostname, guid, command_line. These carry the analytics load
  (exe/command_line/parent_exe/image_path = 119 of the 132 create references).
- **Access triad well covered** (Sysmon EID 10 + memory access): access_level, call_trace, target_pid,
  target_guid, target_name.
- **Total live process producers: 13** (S1–S4, S6–S14); one inert (S5/4689).

## E. UNMAPPED / single-source gaps — ranked

**Tier 1 — genuinely single-source (a whole class of evidence disappears if that one source is absent):**
1. **`env_vars` — MEMORY ONLY.** No log/disk artefact records a process's environment block. Absent memory ⇒ always null.
2. **`current_working_directory` — Sysmon EID 1 + memory only.** 4688 and all execution artefacts leave it null.
3. **`uid` — memory only.** Windows token SID reused as uid; no other source fills it, and Linux uid has no live source (cron maps only `username`).
4. **`sha256_hash` — Sysmon EID 1 only** (config-dependent). The model's default hash is single-sourced.
5. **`md5_hash` — Sysmon EID 1 only** *and* requires MD5 in the configured HashAlgorithms.
6. **`call_trace` — Sysmon EID 10 only** (memory access has no call stack).

**Tier 2 — honest no-source (structurally null for process; not a pipeline omission):**
7. **`signer`** and **`signature_valid`** — no process producer maps either (only module/driver EID 6/7 do).
   Fillable in principle: amcache `Publisher`/`IsPeSigned` (currently kept raw), or a PE Authenticode verify — neither implemented.
8. **`target_address`** — no Windows source; a Linux `/proc/maps` concept with no artefact behind it.

**Tier 3 — fillable field the pipeline currently leaves null (fixable):**
9. **`sid` missing from Sysmon EID 1.** A Sysmon-only Windows host gets `user` (name) but no SID from process-create — SID then depends on 4688 or memory being present. (Sysmon EID 1 genuinely lacks a SID field, so this is a data limit, but a host with 4688 *and* Sysmon can cross-fill via enrichment on the LogonId/user — not currently done for `sid`.)
10. **`hostname` null on SRUM app-usage** (`l2t_srum/application_usage` sets no host key, unlike every sibling source) — a small, clearly fixable omission in `plaso_srum.py`.
11. **`image_path` null on prefetch** — `Record.path_hints[]` holds the full path but is a list the marker set cannot index, so only `exe` is filled (path surfaced as `native.path_hints`). Fixable with a list-index marker.
12. **`fqdn` rarely filled** — only Sysmon, only when `Computer` is a dotted FQDN; 4688 could set it from `Computer` the same way but does not.

**Tier 4 — evidence classes with NO process mapping at all (raw-but-queryable, per canonical-or-raw rule):**
PowerShell console/PSReadLine history & bash_history (command_line evidence), PowerShell 4104 script-block,
WMI-Activity/Operational & WMI-remote 4688, MUICache (GUI-exec), Security 4696 (primary-token assigned),
scheduled-task 4698 registration. None has a clean CAR process action, so all stay raw.
