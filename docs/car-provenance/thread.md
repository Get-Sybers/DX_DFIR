# CAR `thread` — Property-Provenance Catalogue

Authoritative "find once, done" map of every canonical `thread` field to every artefact/source
in this repo that can supply it. Grounded in the pinned CAR data model, the two live CAR engines
(EVTX/Sysmon lane = `piiat-mitrecar`; memory lane = `piiat-mem`), and the current processed evidence.
READ-ONLY analysis.

## Canonical object (authoritative)

Source of truth: `/opt/github/DX_DFIR/car_data_model.json` (lines 337-363) and
`third_party/piiat-mitrecar/third_party/car/data_model/thread.yaml`.

- **Fields (15):** hostname, src_pid, src_tid, tgt_pid, tgt_tid, stack_base, stack_limit,
  start_address, start_function, start_module, start_module_name, user, uid,
  user_stack_base, user_stack_limit
- **Actions (4):** create, remote_create, suspend, terminate

Semantics that drive the whole catalogue (from `thread.yaml`):
- `src_pid`/`src_tid` = **the CREATOR** — the process/thread that *created* the new thread.
- `tgt_pid`/`tgt_tid` = **the new thread** — the process it runs in + the new thread's id.
- `remote_create` = a `create` where `src_pid != tgt_pid` (cross-process = injection).
- `user` = "the user context in which the **source** thread was running" — impersonation-aware,
  may differ from the process user.
- `stack_*` / `user_stack_*` = live TEB/KTHREAD stack bounds — a **runtime memory** concept.

## The two source lanes in this repo

| Lane | Engine | Object/action emitted | Where |
|---|---|---|---|
| **Sysmon EID 8 (CreateRemoteThread)** | `piiat-mitrecar` | `thread/remote_create` | `piiat_mitrecar/mappings/sysmon.py` L442-467; source card `sources/evtx_sysmon.yaml` L319-339 |
| **Memory / Volatility 3** | `piiat-mem` | `thread/create` | plugin `plugins/windows/piiat/threads.py`; map `piiat_mem/mappings.py` L204-222 (+ built-in fallback `windows.thrdscan` L261-272) |

Sysmon EID 8 is the ONLY host/log artefact in the repo that maps to `thread` (all three pinned CAR
sensor cards — `sysmon_10.4`, `sysmon_11.0`, `sysmon_13` — cover `thread` only via EID 8; no
osquery/auditd/EDR/ETW thread source exists here). The **Plaso `l2t_winevt` adapter** is an
*alternate derivation of the same Sysmon EID 8 record* (identical field list —
`piiat_mitrecar/adapters/winevt.py` L95-98), feeding the same `evtx_sysmon` map; it is not an
independent source, so it is folded into the Sysmon column below.

### Critical honesty note — the raw Sysmon EID 8 event has NO SourceUser and NO source TID

The upstream CAR sensor `coverage_map` (`thread.yaml` L60-71) and the `sysmon_13.yaml` card claim
EID 8 supplies `src_tid`, `uid`, and `user` directly. **That overclaims.** The actual Sysmon
CreateRemoteThread record carries only: `SourceProcessGuid/Id`, `SourceImage`,
`TargetProcessGuid/Id`, `TargetImage`, `NewThreadId`, `StartAddress`, `StartModule`,
`StartFunction` (confirmed by both the engine map L453-466 and the Plaso adapter field list
L95-98). There is **no `SourceUser`** and **no source-thread id** in the event. This repo's engine
is the honest one: it maps only what is present, and fills `user`/`hostname` via enrichment.

---

## Per-field provenance — action `remote_create` (Sysmon EID 8)

Map: `piiat_mitrecar/mappings/sysmon.py` L448-467. Owner link = `SourceProcessGuid` (tier-1
definitive). Enrichment inheritance from the owning **source** process: `piiat_mitrecar/
relationships.yml` L21-29 (`exe, image_path, command_line, user, sid, fqdn, hostname, ppid`).

| field | source → native field | action | currently mapped? (yes+where / NO) | confidence & caveats |
|---|---|---|---|---|
| hostname | Sysmon EID 8 → `Computer` (first DNS label) | remote_create | **yes** — sysmon.py L462 `hostname:_HOSTNAME`; also enrich-inheritable | high. Derived (first label of Computer). |
| src_pid | Sysmon EID 8 → `SourceProcessId` | remote_create | **yes** — sysmon.py L454 `src_pid:payload("SourceProcessId")` | high, direct. The creator/injector process = the ACTING/owner process. |
| src_tid | — (no source-thread id in EID 8) | remote_create | **NO** | HONEST NO-SOURCE. Sysmon does not record the creating thread. Not recoverable from EID 8. |
| tgt_pid | Sysmon EID 8 → `TargetProcessId` | remote_create | **yes** — sysmon.py L455 `tgt_pid:payload("TargetProcessId")` | high, direct. The injected (target) process. |
| tgt_tid | Sysmon EID 8 → `NewThreadId` | remote_create | **yes** — sysmon.py L456 `tgt_tid:payload("NewThreadId")` | high, direct. The new thread's id. |
| stack_base | — | remote_create | **NO** | HONEST NO-SOURCE for EID 8. Stack bounds are a live-memory (KTHREAD) concept; not in the event. Memory only (see `create`). |
| stack_limit | — | remote_create | **NO** | HONEST NO-SOURCE for EID 8. Memory only. |
| start_address | Sysmon EID 8 → `StartAddress` | remote_create | **yes** — sysmon.py L457 `start_address:payload("StartAddress")` | high, direct. THE injection evidence (entry point of the injected thread). |
| start_function | Sysmon EID 8 → `StartFunction` | remote_create | **yes** — sysmon.py L460 `start_function:payload("StartFunction")` | high, direct. Sysmon resolves the export (e.g. `LoadLibraryA`) — the CAR-2013-10-002 detector key. Present only when Sysmon could resolve it. |
| start_module | Sysmon EID 8 → `StartModule` | remote_create | **yes** — sysmon.py L458 `start_module:payload("StartModule")` | high, direct. The module the start address resides in. |
| start_module_name | Sysmon EID 8 → `basename(StartModule)` | remote_create | **yes** — sysmon.py L459 `start_module_name:basename(payload("StartModule"))` | high, derived (basename). |
| user | Sysmon EID 8 → (NOT in event) → **enrich-inherited** from the SOURCE process (`SourceProcessGuid` owner) | remote_create | **yes (indirect)** — not in map; filled by enrich `_inherit` from owning source process (relationships.yml L25) | medium. NOT from the thread event itself; inherited (definitive link) = the source process's user. Cannot capture thread-level impersonation (semantic gap vs CAR's "source thread's user context"). Null if the source EID 1 create is absent from the same source_host. |
| uid | — (see caveat) | remote_create | **NO** | GAP. `thread` has `uid` (not `sid`); the Sysmon-lane inherit list carries `sid`, and `thread` has no `sid` field, so nothing fills `uid`. (Contrast the memory lane, which inherits `uid`.) Fixable by adding `uid` to `from_owning_process` or a sid→uid inherit. |
| user_stack_base | — | remote_create | **NO** | HONEST NO-SOURCE for EID 8. TEB-only → memory. |
| user_stack_limit | — | remote_create | **NO** | HONEST NO-SOURCE for EID 8. TEB-only → memory. |

**Bonus / relationship (not a canonical field):** `TargetProcessGuid` is surfaced native
(sysmon.py L466) and consumed by **R5 thread-injection dual-link** (`piiat_mitrecar/enrich.py`
L488-498; `docs/CAR-Relations.md` L154): owner = source process, and
`_native.target_process_guid` = the injected target (both definitive by ProcessGuid). This is the
dual-link that makes the injection edge explicit. `TargetImage` stays native (no CAR thread field).

---

## Per-field provenance — action `create` (Memory / Volatility 3)

Plugin: `third_party/piiat-mem/plugins/windows/piiat/threads.py` (pool-tag scan = finds unlinked /
hidden threads). Map: `piiat_mem/mappings.py` L204-222. Owner link = `OwnerOffset`
(`_ETHREAD.Tcb.Process` → owning `_EPROCESS` offset, tier-1 definitive). Enrichment: host identity
from the image's own registry (`enrich.py` L309-318) + inheritance from the owning process
(`_INHERIT` incl. `user, sid, uid, hostname` — `enrich.py` L72, L288-291, L377-380).

> The memory lane emits action **`create`**, never `remote_create`: a snapshot records the thread's
> existence and its OWNING process, but not *who created it* — so `src_pid`/`src_tid` are
> unknowable from memory. Injection is inferred from an unbacked/wrong-module start, not asserted as
> a `src_pid`.

| field | source → native field | action | currently mapped? (yes+where / NO) | confidence & caveats |
|---|---|---|---|---|
| hostname | Memory → image registry (`ComputerName`) via enrich | create | **yes (enrich)** — enrich.py L309-318 (`_host_identity`) | high per-artefact. Not from the thread record; from the image's own registry. Null if registry evidence absent. |
| src_pid | — (creator not recorded in a snapshot) | create | **NO** | HONEST NO-SOURCE. Memory records the thread's owner (=target), not its creator. |
| src_tid | — | create | **NO** | HONEST NO-SOURCE. |
| tgt_pid | Memory → `PID` (`_ETHREAD.Cid.UniqueProcess`) | create | **yes** — mappings.py L208 `tgt_pid:"PID"` | high, direct. The process the thread runs in = the thread's owner. |
| tgt_tid | Memory → `TID` (`_ETHREAD.Cid.UniqueThread`) | create | **yes** — mappings.py L208 `tgt_tid:"TID"` | high, direct. |
| stack_base | Memory → `StackBase` (`_ETHREAD.Tcb.StackBase`, KERNEL stack) | create | **yes** — mappings.py L218; plugin L353 | high, direct. **MEMORY-ONLY field.** Kernel stack bounds from KTHREAD. |
| stack_limit | Memory → `StackLimit` (`_ETHREAD.Tcb.StackLimit`, KERNEL stack) | create | **yes** — mappings.py L218; plugin L357 | high, direct. **MEMORY-ONLY field.** |
| start_address | Memory → `Win32StartAddress` (user-mode entry point) | create | **yes** — mappings.py L213; plugin L319 | high, direct. Kernel `StartAddress` is kept native (L221) — Win32 pair is the user-mode truth; mixing address+module across pairs is deliberately avoided (injection false-negative risk, L209-212). |
| start_function | Memory → `Win32StartFunction` (resolved export at Win32 start) | create | **yes** — mappings.py L217; plugin L322-347 (`_path_and_symbol`, in-memory export table, symbol+disp notation) | medium-high. Resolved from the module's in-memory export table (bare name on exact match, `Name+0x<disp>` otherwise). `NotAvailableValue` for an unbacked start with no export — **that N/A IS the injection signal**, never guessed. |
| start_module | Memory → `Win32StartPath` (VAD file path of Win32 start) | create | **yes** — mappings.py L214; plugin L327-347 | high. The mapped module holding the user-mode entry point; unbacked = injected (no path). |
| start_module_name | Memory → `basename(Win32StartPath)` | create | **yes** — mappings.py L215 | high, derived. |
| user | Memory → enrich-inherited from owning process (`OwnerOffset`) | create | **yes (enrich)** — enrich.py L72 (`_INHERIT` has `user`), L377-380 | medium. The OWNING (target) process's user, not a creator/impersonation context. Well-known SIDs canonicalised (enrich.py L320-324). |
| uid | Memory → enrich-inherited from owning process (owner SID → `uid`) | create | **yes (enrich)** — enrich.py L72 (`_INHERIT` has `uid`), L377-380 | medium. Owning process's account SID. (Memory lane fills `uid`; the Sysmon lane does not — asymmetry.) |
| user_stack_base | Memory → `UserStackBase` (`TEB.NtTib.StackBase`, USER stack) | create | **yes** — mappings.py L219; plugin L111-131, L363-366 | high when resident. **MEMORY-ONLY / TEB-ONLY field.** Read through the owner's rebuilt DTB address space; `NotAvailableValue` for a paged-out TEB or dead process (honest null). |
| user_stack_limit | Memory → `UserStackLimit` (`TEB.NtTib.StackLimit`, USER stack) | create | **yes** — mappings.py L219; plugin L111-131 | high when resident. **MEMORY-ONLY / TEB-ONLY field.** |

**Native evidence kept (not canonical thread fields):** `ExitTime` (only meaningful for TERMINATED
threads — Win10 unions it with KeyedWaitChain, gated on the cross-thread TERMINATED flag; kept in
`_native`, plugin L301-312 / map L221), kernel `StartAddress`, kernel `StartPath`, kernel
`StartFunction`, `Offset` (the `_ETHREAD` reuse-proof identity = the CAR `guid` basis).

**Fallback source:** built-in `windows.thrdscan` (map `mappings.py` L261-272) maps the same
`tgt_pid/tgt_tid/start_address/start_module/start_module_name` but **no stacks and no user-stack**
(thrdscan doesn't emit them). It is SUPERSEDED by `windows.piiat.threads` when present
(`mappings.py` L99-100 `SUPERSEDES`), so it only matters if the custom plugin wasn't run.

---

## Actions `suspend` and `terminate` — no source

| action | source in repo? | notes |
|---|---|---|
| suspend | **NONE** | No artefact in the repo emits `thread/suspend`. Sysmon has no thread-suspend event; would require ETW Threat-Intelligence provider (`KERNEL_THREATINT_TASK_SUSPENDTHREAD`) or EDR telemetry — neither ingested. HONEST NO-SOURCE. |
| terminate | **NONE (as a CAR event)** | No artefact emits a `thread/terminate` event. Memory *observes* thread death via `_ETHREAD.ExitTime`, but the plugin surfaces `ExitTime` only as **native evidence on the `create` record** (plugin L301-312, map keeps it L221) — it does not synthesise a terminate action. So `terminate` is unmapped; the death timestamp is queryable but not a canonical action. |

---

## Coverage summary

**Fields with a real source (11 of 15):** hostname, src_pid, tgt_pid, tgt_tid, start_address,
start_function, start_module, start_module_name, user, uid, + the four stack fields when memory is
present. Split by lane:

| field | Sysmon EID 8 (remote_create) | Memory (create) |
|---|---|---|
| hostname | yes (direct) | yes (enrich) |
| src_pid | **yes (only source)** | no |
| src_tid | no | no |
| tgt_pid | yes | yes |
| tgt_tid | yes | yes |
| stack_base | no | **yes (only source)** |
| stack_limit | no | **yes (only source)** |
| start_address | yes | yes |
| start_function | yes | yes |
| start_module | yes | yes |
| start_module_name | yes | yes |
| user | yes (enrich, source proc) | yes (enrich, owning proc) |
| uid | **no (lane gap)** | yes (enrich) |
| user_stack_base | no | **yes (only source)** |
| user_stack_limit | no | **yes (only source)** |

**Field-level takeaways:**
- **`src_pid` is Sysmon-EID-8-only** (memory can't name the creator).
- **`stack_base`, `stack_limit`, `user_stack_base`, `user_stack_limit` are memory-only** (TEB/KTHREAD
  live state; no log/host artefact carries them). Confirms the task's premise exactly.
- **`start_address` + `start_module`/`start_function`** are the ONE overlap where both lanes supply
  the value — Sysmon for the remote (injected) thread, memory for any live thread.
- **`src_tid` has NO source anywhere** — honest dead field for this repo.

**Action coverage:** `remote_create` (Sysmon) and `create` (memory) are covered; `suspend` and
`terminate` have no source.

## UNMAPPED gaps, ranked

1. **Memory threads plugin not in the processed store → all live-thread + stack fields currently
   absent.** The `windows.piiat.threads` plugin (and its `thread/create` rows carrying stacks,
   user-stacks, live tgt_pid/tid, live start_address/module/function) exists in code but was NOT run
   against the current memory image: `data_store/processed/volatility/memdump.mem/plugins/` contains
   only processes, registry, sessions, mftscan, pslist, banners — **no threads output**. This is the
   single biggest gap: every stack field and every live-thread field depends on running this plugin.
   *(Highest impact — it is the only source for 4 of the 15 fields and the whole `create` action.)*

2. **No Sysmon EID 8 in the current processed evidence → `remote_create` is entirely unpopulated
   here.** The only processed EvtxECmd output
   (`data_store/processed/windows_logs/unspecified_host/log_EvtxECmd_Output.json`, Provider
   Microsoft-Windows-Sysmon) contains **only EID 1 and EID 5** — no EID 8. So the `thread/remote_create`
   code path has no data to fire on in the LS24 light set. Code is correct; evidence is missing.

3. **`thread.uid` is unmapped in the Sysmon lane (asymmetry bug).** The memory lane inherits `uid`
   from the owning process; the Sysmon lane's `from_owning_process` inherit list
   (`piiat-mitrecar/piiat_mitrecar/relationships.yml` L21-29) carries `sid` (which `thread` lacks)
   but not `uid`, so `thread.uid` stays null on every Sysmon `remote_create`. Low-effort fix: add
   `uid` to that list, or map the source process SID into the thread `uid`.

4. **`src_tid` — genuinely no source.** Neither Sysmon EID 8 (no source-thread id) nor memory
   (records the thread's own id, not its creator's) can supply the creating thread id. Only ETW
   thread providers or an EDR would. Honest permanent null for this repo.

5. **`suspend` / `terminate` actions — no source.** No artefact emits these. Memory holds `ExitTime`
   (native evidence on the create record) but no terminate event is synthesised. A future
   enhancement could emit `thread/terminate` from the plugin's gated `ExitTime`, or ingest the ETW
   Threat-Intelligence provider for both suspend and terminate.

6. **Upstream CAR sensor cards overclaim EID 8.** `thread.yaml` `coverage_map` (L60-71) and
   `sysmon_13.yaml` list `src_tid`, `uid`, `user` as Sysmon-provided for `remote_create`, but the
   real event carries none of them directly (`user` is only reachable by inheritance, `uid`/`src_tid`
   not at all). Documentation-vs-reality mismatch worth noting when trusting the upstream coverage map.

## Key files (absolute paths)

- Canonical model: `/opt/github/DX_DFIR/car_data_model.json` (L337-363);
  `/opt/github/DX_DFIR/third_party/piiat-mitrecar/third_party/car/data_model/thread.yaml`
- Sysmon EID 8 map: `/opt/github/DX_DFIR/third_party/piiat-mitrecar/piiat_mitrecar/mappings/sysmon.py` (L442-467)
- Sysmon source card: `/opt/github/DX_DFIR/third_party/piiat-mitrecar/sources/evtx_sysmon.yaml` (L319-353)
- Plaso alt-derivation of EID 8: `/opt/github/DX_DFIR/third_party/piiat-mitrecar/piiat_mitrecar/adapters/winevt.py` (L95-98)
- Sysmon-lane enrich (inherit + R5 dual-link): `/opt/github/DX_DFIR/third_party/piiat-mitrecar/piiat_mitrecar/enrich.py` (L257-260, L488-498); rules `/opt/github/DX_DFIR/third_party/piiat-mitrecar/piiat_mitrecar/relationships.yml` (L21-29)
- Memory threads plugin: `/opt/github/DX_DFIR/third_party/piiat-mem/plugins/windows/piiat/threads.py`
- Memory CAR map: `/opt/github/DX_DFIR/third_party/piiat-mem/piiat_mem/mappings.py` (L204-222 piiat.threads, L261-272 thrdscan fallback, L99-104 SUPERSEDES)
- Memory-lane enrich (host id + inherit): `/opt/github/DX_DFIR/third_party/piiat-mem/piiat_mem/enrich.py` (L72, L288-291, L309-324, L377-380)
- Injection analytics: `/opt/github/DX_DFIR/third_party/piiat-mitrecar/third_party/car/analytics/CAR-2013-10-002.yaml` (LoadLibrary injection); `.../CAR-2021-05-011.yaml` (remote thread into LSASS)
- R5 relationship doc: `/opt/github/DX_DFIR/docs/CAR-Relations.md` (L154)
- Evidence checked (both empty of thread data): `/opt/github/DX_DFIR/data_store/processed/volatility/memdump.mem/plugins/` (no threads jsonl); `/opt/github/DX_DFIR/data_store/processed/windows_logs/unspecified_host/log_EvtxECmd_Output.json` (EID 1/5 only)
