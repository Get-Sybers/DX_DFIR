# PROPERTY-PROVENANCE CATALOGUE — MITRE CAR `thread`, FILESYSTEM / DISK ARTEFACTS
## Grounded in the REAL LoneWolf Windows-10 disk image (plaso timeline)

**Object:** `thread` — the smallest scheduled unit of execution, a purely **runtime** entity
(TEB / KTHREAD / `_ETHREAD` live state). This pass is scoped to **dead-box FILESYSTEM / disk
artefacts** only: WER, crash dumps / minidumps, `hiberfil.sys` / `pagefile.sys` / `MEMORY.DMP`
(memory-on-disk), prefetch, scheduled tasks — **not** event logs (Sysmon EID 8) and **not** live
memory (Volatility), both of which are the runtime lanes already catalogued in
`scratchpad/car-provenance/thread.md` (LS24).

**Bottom line up front (the honest headline this pass exists to confirm):**
`thread` has **near-zero filesystem provenance**. It is a runtime object sourced almost entirely
from ETW/Sysmon (the `remote_create` lane) and live memory (the `create` lane). Every one of its 15
fields is **structurally null from ordinary disk artefacts**, and every disk artefact that touches
threads at all does so **only as `fs:stat` filesystem metadata (name / timestamps / size), never as
parsed content**. There is exactly **one genuine — but entirely UNMINED — disk source**: a **parsed
user-mode crash dump / minidump** (and, as memory-on-disk, a **carved `hiberfil.sys`/`pagefile.sys`**),
which is really "memory on disk". Both are present on the real LoneWolf image; the pipeline captures
only their filesystem metadata and parses none of their contents.

**Fields (15):** hostname, src_pid, src_tid, stack_base, stack_limit, start_address, start_function,
start_module, start_module_name, tgt_pid, tgt_tid, uid, user, user_stack_base, user_stack_limit.
**Actions (4):** create, remote_create, suspend, terminate.
(Authoritative: `car_data_model.json` L337-363; `third_party/piiat-mitrecar/third_party/car/data_model/thread.yaml`.)

**Evidence (full-file tallies, read verbatim — not a thin fixture):**
`/opt/github/DX_DFIR/data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl`
(6.6 GB, LoneWolf `LoneWolf.E01` via plaso). Host `DESKTOP-PM6C56D`; the only real interactive user
is **`jcloudy`** (+ `defaultuser0` OOBE). 66 distinct `data_type`s in the whole timeline.

---

## 0. What the pipeline can do with threads from disk (code reality)

Exhaustive grep of the ingest code (`third_party/piiat-mitrecar/piiat_mitrecar` + `sources`,
`third_party/piiat-mem/piiat_mem`, `python/`):

- **The ONLY `thread` producer in the entire pipeline is Sysmon EID 8** (`mappings/sysmon.py`
  L442-467, `thread/remote_create`) — a **runtime event log**, out of scope here — plus the memory
  lane (`piiat-mem`, `thread/create`) — **runtime memory**, out of scope here.
- **No minidump / WER / crashdump / hiberfil / pagefile parser or map exists anywhere.**
  `grep -rniE "minidump|reportarchive|report\.wer|localdumps|crashdumps|hiberfil|pagefile|\.mdmp|\.hdmp"`
  over all pipeline code returns **zero** matches. There is no code path that opens a `.dmp`, a
  `Report.wer`, or a page/hibernation file.
- **`fs:stat` (the filesystem-metadata data_type, 1.97 M rows) maps only to the CAR `file` object**
  (`mappings/plaso_fs_extra.py` — "Plaso filesystem/file artefacts → CAR file"), **never to
  `thread`.** So even where a dump/hiber/WER file is seen on disk, it lands as a `file/create|modify`
  record, contributing **nothing** to any `thread` field.

Conclusion: from disk, the pipeline maps **not a single `thread` field**. The rest of this document
is about what *could* be mined and honestly documenting why almost none of it can.

---

## 1. Disk-artefact universe that could conceivably bear on threads (full-file counts)

| Artefact | how it appears in the timeline | rows | thread relevance | parsed content? |
|---|---|---:|---|---|
| **User-mode crash dumps** (`*.dmp`) | `fs:stat` metadata only | 6 distinct files (see §2) | **THE one real disk source** of faulting-thread TID + stack + loaded modules | ❌ **contents never parsed** |
| **`hiberfil.sys`** (memory-on-disk) | `fs:stat` metadata only | 1 file, **6.83 GB** | live thread stacks/TEBs/KTHREADs **iff carved** (= the memory `create` lane) | ❌ not carved by plaso |
| **`pagefile.sys` / `swapfile.sys`** (memory-on-disk) | `fs:stat` metadata only | pagefile 3.08 GB; swapfile present | paged-out thread stacks **iff carved** | ❌ not carved |
| **kernel `MEMORY.DMP`** | **not present as a file** — the 6 "MEMORY.DMP" hits are `CrashControl` **registry config** (DumpFile path + FilesNotToBackup), not a dump | 0 files | would carry every thread if it existed | n/a (no file) |
| **WER `Report.wer`** | `fs:stat` metadata only | 104 `.wer` fs hits (~13 distinct AppCrash/NonCritical reports) | faulting **module/offset** (weak `start_module`), **no TID/stack** | ❌ **no `windows:wer` data_type emitted at all** |
| **Prefetch** (`windows:prefetch:execution`) | parsed | 1312 | `mapped_files` = per-**process** loaded-DLL list → `start_module` *candidates* only | ✅ but no thread binding |
| **Scheduled tasks** (`task_cache:entry` / `windows:tasks:job` / `:trigger`) | parsed | 1454 / 4 / 6 | launch **command** → weak proxy for the eventual **main thread's** start command | ✅ but no thread fields |

Everything else in the 66-`data_type` universe (registry, LNK, shellbags, browser, USN, PE, etc.)
has **no bearing on threads whatsoever**.

---

## 2. The one genuine exception: crash dumps / minidumps (present, real, UNMINED)

Real user-mode crash dumps exist on the LoneWolf disk — captured by Windows Error Reporting /
`LocalDumps` / Chrome Crashpad — and each is **the only dead-box artefact that actually contains
thread runtime state** (the faulting thread's TID, its call stack, and the module list at crash time):

```
\Users\jcloudy\AppData\Local\CrashDumps\Dropbox.exe.13188.dmp          (jcloudy)
\Users\jcloudy\AppData\Local\CrashDumps\Dropbox.exe.5748.dmp           (jcloudy)
\Users\jcloudy\AppData\Local\CrashDumps\Dropbox.exe.9780.dmp           (jcloudy)
\Windows\System32\config\systemprofile\AppData\Local\CrashDumps\svchost.exe.4104.dmp   (SYSTEM)
\Users\jcloudy\AppData\Local\Google\Chrome\User Data\Crashpad\reports\080881cc-….dmp   (Chrome Crashpad)
\Users\jcloudy\AppData\Local\Google\Chrome\User Data\Crashpad\reports\561ca1c6-….dmp   (Chrome Crashpad)
```
(each also duplicated in the `VSS2:` shadow copy).

**Every one of these is stored only as an `fs:stat` / `filestat` record** — keys are exactly
`display_name, filename, file_size, file_entry_type, timestamp(_desc), inode, is_allocated,
sha256_hash (of the .dmp file itself)`. **No thread content is extracted.** A minidump parser
(`minidumpparser` / `dbghelp` / a Volatility-style walk) run over these files *could* yield, for the
**faulting thread only**:

- `tgt_tid` — the crashing thread's id (in the MINIDUMP_THREAD list),
- `tgt_pid` — the process the thread runs in,
- `stack_base` / `stack_limit` / `user_stack_base` / `user_stack_limit` — from the thread's TEB /
  stack range embedded in the dump,
- `start_address` — the thread's start / instruction pointer,
- `start_module` / `start_module_name` — resolved against the dump's ModuleList.

That is **five-plus `thread` fields recoverable from disk** — but for **one thread per dump** (the
faulting one; a minidump need not include every thread's full stack), and **only after parsing the
dump body**, which the pipeline never does. This is the single real UNMINED opportunity for `thread`.

**A bonus that needs no dump-body parse:** the CrashDumps filename convention `<image>.<pid>.dmp`
embeds the crashing process's **PID** — `svchost.exe.4104.dmp` → PID 4104, `Dropbox.exe.13188.dmp`
→ PID 13188. That is a weak-but-real **`tgt_pid`** signal recoverable by regex from the `fs:stat`
`display_name` alone. Currently unmined (fs:stat → `file` object only).

---

## 3. Memory-on-disk: hiberfil.sys / pagefile.sys (a thread source ONLY if carved)

`\hiberfil.sys` (6.83 GB) and `\pagefile.sys` (3.08 GB) are literally **RAM written to disk**. If
carved with a memory forensics engine they yield the full live-thread universe — `_ETHREAD`/`KTHREAD`
stacks, TEB user-stacks, start addresses, every TID — i.e. **exactly the memory `create` lane already
catalogued** in the LS24 `thread.md` (`stack_base`/`stack_limit`/`user_stack_base`/`user_stack_limit`
are memory-only fields sourced from KTHREAD/TEB). **Be explicit:** this is *memory-on-disk*, not a
filesystem artefact in any meaningful sense — the values come from parsing RAM structures, not from
NTFS metadata or a Windows on-disk log. Plaso records these files **only as `fs:stat` metadata** and
carves nothing. No kernel `MEMORY.DMP` exists on this image (the string hits are `CrashControl`
registry config pointing at where one *would* be written, not a file).

So: hiberfil/pagefile are a *route to* the runtime `create` lane, not an independent disk source, and
they belong to the Volatility lane, not the plaso/disk lane.

---

## 4. WER Report.wer: present, but weak for threads — and unparsed anyway

104 `Report.wer` `fs:stat` hits, ~13 distinct crash reports incl.
`AppCrash_svchost.exe_…`, `AppCrash_Dropbox.exe_…` (×3), `NonCritical_…taskhostw/OneDrive/Update`.
**There is NO `windows:wer` data_type in the timeline** — plaso's WER parser never fired; the `.wer`
files exist purely as filesystem metadata.

Even if parsed, a WER `Report.wer` is **the wrong artefact for `thread`**: its text carries the
faulting **application**, the faulting **module** + offset, and an exception code — which touches
`start_module`/`start_module_name` *weakly* (the module the fault was in ≈ where the thread was
executing) — but it carries **no thread id, no stack, no start address**. The thread stack lives in
the companion `.dmp` (§2), not the `.wer`. So WER is at best a corroborating `start_module` hint, and
here it is unmined on both counts (no parser, and it maps to `file` regardless).

---

## 5. Prefetch and scheduled tasks: indirect, and honestly nil for `thread`

**Prefetch (1312 rows, parsed).** Each `.pf` carries `mapped_files` — the list of DLLs/modules the
process loaded in its first ~10 s (e.g. `NTDLL.DLL`, `KERNEL32.DLL`, … 54 entries for `TASKHOSTW.EXE`).
This is a per-**process** module set. It supplies a pool of **`start_module` *candidates*** (a
thread's start address is usually inside one of the process's loaded modules) — but there is **no
thread record, no TID, no start address, no per-thread linkage**: you cannot say *which* thread
started in *which* module. For the `thread` object this is honest nil (it is a `module`/`process`
artefact). Documented as the single, very weak indirect signal.

**Scheduled tasks (1454 TaskCache + 4 `.job` + 6 trigger, parsed).** A `.job`/TaskCache action is a
process-launch command — e.g. `Application: C:\Program Files (x86)\Dropbox\Update\DropboxUpdate.exe
/ua /installsource scheduler`, `Scheduled by: DESKTOP-PM6C56D\jcloudy`. When the task runs it creates
a process and its initial/main thread, so the action is a **weak proxy for that main thread's start
command** — but a launch command is **not even a CAR `thread` field** (`thread` has
`start_address`/`start_module`/`start_function`, not a command line), and the record has **no TID, no
stack, no start address**. `Scheduled by` gives the owning **user** (weakly inheritable to the
launched *process*, not the thread). Honest nil for `thread`.

---

## 6. Per-field provenance — all 15 `thread` fields, FILESYSTEM artefacts only

Legend — **mined?**: essentially all **NO**. "UNMINED (dump)" = recoverable only by a minidump-body
parser that does not exist; "carve" = only via hiberfil/pagefile carving (= the memory lane).

| field | fs artefact → native field | action | mined? | confidence & caveats |
|---|---|---|---|---|
| hostname | image context → `image_hostname` (`DESKTOP-PM6C56D`), stamped on every plaso row | (n/a) | **NO** for a *thread* record (no thread record is emitted from disk); the value exists generically on every fs row | high value / low specificity. Not thread-specific; it is the image's host, inherited by any object. |
| src_pid | — (the CREATOR is never recorded on disk) | create/remote_create | **NO** | HONEST NO-SOURCE, permanent. No dead-box artefact records who *created* a thread. Only ETW/EDR do. |
| src_tid | — | remote_create | **NO** | HONEST NO-SOURCE, permanent. The creating thread id exists in no disk artefact (nor in Sysmon nor memory — see LS24). Dead field for disk. |
| stack_base | crash dump (faulting thread's stack range) → parse; or `hiberfil/pagefile` carve | create | **NO** — UNMINED (dump) / carve | Memory-only concept. Recoverable ONLY by parsing a `.dmp` body (faulting thread) or carving RAM-on-disk. Not from NTFS/logs. |
| stack_limit | crash dump → parse; or carve | create | **NO** — UNMINED (dump) / carve | as above. |
| start_address | crash dump (faulting thread IP/start) → parse; or carve | create | **NO** — UNMINED (dump) / carve | The `.dmp` MINIDUMP_THREAD carries the faulting thread's start/instruction pointer. Unparsed. |
| start_function | crash dump → resolve against dump ModuleList; or carve | create | **NO** — UNMINED (dump) / carve | Needs symbol resolution over the dump's module list; never done. WER gives faulting module but not a function. |
| start_module | crash dump ModuleList / WER faulting module / prefetch `mapped_files` (candidates) | create | **NO** — UNMINED (dump); weak candidates from prefetch/WER | Best disk signal is the `.dmp` module list for the faulting thread; prefetch/WER give only process-level *candidates*, no thread binding. |
| start_module_name | `basename` of any of the above | create | **NO** — UNMINED (dump) | derived from start_module; same caveats. |
| tgt_pid | crash dump body (owning PID); **or `<image>.<pid>.dmp` filename regex** on the `fs:stat` display_name | create | **NO** — UNMINED (weak, filename) | Rare exception: the CrashDumps filename embeds the PID (`svchost.exe.4104.dmp` → 4104). Recoverable from fs:stat path without parsing the dump — but currently fs:stat → `file` only. |
| tgt_tid | crash dump (faulting thread id) → parse; or carve | create | **NO** — UNMINED (dump) / carve | The one thread id a dump does hold (the faulting thread). Unparsed. No other disk source. |
| uid | — (no numeric uid on any Windows disk artefact) | (n/a) | **NO** | HONEST NO-SOURCE, permanent. Windows disk artefacts carry SIDs at best, never a numeric uid; `thread` has `uid` not `sid`. |
| user | owning path of the dump/WER file (`\Users\jcloudy\…\CrashDumps\` → jcloudy; `…\systemprofile\…` → SYSTEM); task `Scheduled by` | create | **NO** — weak, path-inherited | Not a thread attribute; it is the *file owner* (dump author = the crashing process's user), a weak proxy for the thread's process user. Not impersonation-aware. |
| user_stack_base | crash dump (TEB) → parse; or carve | create | **NO** — UNMINED (dump) / carve | TEB-only. Same as stacks. |
| user_stack_limit | crash dump (TEB) → parse; or carve | create | **NO** — UNMINED (dump) / carve | TEB-only. Same as stacks. |

**Action coverage from disk:** `create` — only via a parsed dump/carve (unmined). `remote_create` —
**no disk source ever** (injection/creator lineage is runtime-only; `src_pid`/`src_tid` unknowable
from disk). `suspend` — **no disk source ever**. `terminate` — **no disk source ever** (a crash dump
implies a thread *died*, but records the faulting thread's live state at crash, not a terminate event;
and it is unparsed regardless).

---

## 7. Honest NO-SOURCE section (the point of this pass)

`thread` is a **runtime object**. The following is true and worth stating plainly:

1. **From ordinary disk artefacts — NTFS metadata, registry, event logs' on-disk form, LNK,
   shellbags, browser, prefetch, scheduled tasks, USN, PE — not one `thread` field is fillable.**
   These artefacts record files, keys, executions, and launches; **none records a unit of execution
   (a thread), its stack, its TEB, its start address, its TID, or who created it.** The pipeline
   reflects this exactly: **zero** `thread` rows are emitted from any disk source, and `fs:stat`
   (where dumps/hiber/page/WER surface) maps only to the `file` object.

2. **`src_pid`, `src_tid`, `uid` have NO disk source at all — permanent honest nulls.** The thread's
   *creator* (src_pid/src_tid) is a lineage fact captured only by live ETW/EDR (and even Sysmon EID 8
   lacks src_tid — see LS24). A numeric `uid` does not exist in Windows disk artefacts.

3. **`remote_create`, `suspend`, `terminate` actions have NO disk source whatsoever.** Thread
   injection, suspension, and termination are runtime events. Nothing on disk asserts them.

4. **The stack quartet (`stack_base`/`stack_limit`/`user_stack_base`/`user_stack_limit`),
   `start_address`, `tgt_tid` are memory-only** (KTHREAD/TEB live state). Their *only* dead-box route
   is **memory-on-disk that has been carved** (hiberfil/pagefile/a crash dump) — i.e. you are back in
   the memory lane, not a filesystem lane. Confirms the LS24 catalogue's "memory-only" finding from
   the disk side.

5. **`hostname` and `user` are the only fields with any generic disk value, and even those are
   inherited context, not thread facts:** `hostname` from the image (`DESKTOP-PM6C56D`, on every row),
   `user` from a dump/WER file's owning path (`\Users\jcloudy\` / SYSTEM) — the *process/file* owner,
   never the thread's (impersonation-aware) user context.

**The rare exceptions (genuine UNMINED opportunities), ranked:**

- **A. Parse the user-mode crash dumps / minidumps** (`*.dmp` in `…\CrashDumps\` and Chrome
  `Crashpad\reports\`). This is the ONE artefact that actually holds thread runtime state on disk:
  faulting-thread `tgt_tid`, `stack_*`/`user_stack_*`, `start_address`, and `start_module(_name)` via
  the dump ModuleList. Present on LoneWolf (6 files: Dropbox×3, svchost, Chrome×2); today captured as
  `fs:stat` metadata only. Real but narrow (one — the faulting — thread per dump) and no parser exists.
- **B. Regex `tgt_pid` out of the CrashDumps filename** (`<image>.<pid>.dmp`) — a zero-cost weak
  `tgt_pid`/process-link from the fs:stat `display_name`, no dump-body parse needed. Unmined.
- **C. Carve `hiberfil.sys` / `pagefile.sys`** → the full memory `create` lane (all stack/start/TID
  fields). This is memory-on-disk = the Volatility lane, not a new filesystem source; flag it as the
  bridge, not as disk provenance.
- **D. (weak) Parse WER `Report.wer`** for faulting **module** → corroborating `start_module` only;
  no TID/stack. Not currently parsed (no `windows:wer` data_type) and maps to `file` anyway.
- **E. (very weak / not really thread) Prefetch `mapped_files`** as `start_module` *candidates*, and
  **scheduled-task** launch command as a main-thread start-command proxy — neither has a thread
  record; document as context, not sources.

**Net:** `thread` is confirmed a runtime/ETW/memory object with **essentially nil dead-box filesystem
provenance**. The only honest disk exceptions are *memory-on-disk* (crash dumps and carved
hiber/page), which are memory content that happens to live in a file — and even those are entirely
unmined by the current pipeline (captured as filenames, never parsed).

---

## 8. Key files & evidence (absolute paths)

- Evidence: `/opt/github/DX_DFIR/data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (6.6 GB)
- Canonical model: `/opt/github/DX_DFIR/car_data_model.json` (L337-363);
  `/opt/github/DX_DFIR/third_party/piiat-mitrecar/third_party/car/data_model/thread.yaml`
- Only `thread` producer (runtime, out of scope): `…/piiat_mitrecar/mappings/sysmon.py` (L442-467, EID 8)
- `fs:stat` → **file** object (never thread): `…/piiat_mitrecar/mappings/plaso_fs_extra.py`
- Prior runtime catalogue (Sysmon EID 8 + memory lanes): `scratchpad/car-provenance/thread.md`
- Confirmed ABSENT from the pipeline (grep, zero matches): any minidump / WER / crashdump / hiberfil /
  pagefile parser or map across `piiat_mitrecar`, `piiat-mem/piiat_mem`, `sources`, `python/`.
- Real disk artefacts (all `fs:stat` metadata only, contents unparsed): crash dumps
  `\Users\jcloudy\AppData\Local\CrashDumps\Dropbox.exe.{13188,5748,9780}.dmp`,
  `\Windows\System32\config\systemprofile\AppData\Local\CrashDumps\svchost.exe.4104.dmp`,
  Chrome `…\Crashpad\reports\{080881cc…,561ca1c6…}.dmp`; memory-on-disk `\hiberfil.sys` (6.83 GB),
  `\pagefile.sys` (3.08 GB), `\swapfile.sys`; WER `\ProgramData\Microsoft\Windows\WER\ReportArchive\
  {AppCrash_svchost.exe,AppCrash_Dropbox.exe×3,NonCritical_…}\Report.wer` (104 fs hits).
  No kernel `MEMORY.DMP` file (the 6 hits are `CrashControl` registry config).
