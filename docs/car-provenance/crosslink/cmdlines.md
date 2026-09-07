# Command-line cross-artefact linkage hunt — DX_DFIR processed dataset

READ-ONLY analysis over the processed dataset `data_store/processed/`.
Command-bearing artefacts extracted by a single streaming pass over the 6.6 GB
LoneWolf disk timeline plus targeted reads of the Sysmon evtx, Hayabusa timeline,
Volatility plugins and `car.db`.

---

## 0. The single most important finding: the four sources are FOUR DIFFERENT HOSTS

The task frames the goal as "the SAME execution seen via log + memory + prefetch/amcache
+ tasks". On this dataset that literal cross-vantage convergence is **not physically
possible across all three of log+memory+disk**, because the command-rich sources come
from three unrelated machines (plus a Linux box):

| Source file(s) | Host | Command vantage it provides |
|---|---|---|
| `log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (LoneWolf.E01 disk, user `jcloudy`) | **DESKTOP-PM6C56D** | Disk artefacts: prefetch, amcache, shimcache, BAM, UserAssist, LNK args, Run keys, Services ImagePath, .job tasks, RunMRU. **No full argv anywhere.** |
| `windows_logs/unspecified_host/log_EvtxECmd_Output.json` + `signatures/hayabusa/timeline.jsonl` | **DESKTOP-M913391** | Sysmon EID 1 process creation — **full command line with argv**. |
| `volatility/memdump.mem/plugins/*.jsonl` + `car.db` | **BGP-WS1-CONF** | Memory-resident process command lines (full argv). |
| `log2timeline/jsonl/5g-webui.jsonl` | **5g-webui** (Linux) | `fs:stat` + `linux:utmp` only — no Windows command artefacts. |

Consequences:
- **CAR `command_line` is populated ONLY from the memory host (BGP-WS1-CONF).** The disk
  host's rich execution evidence and the Sysmon host's full cmdlines never enter CAR.
- The true multi-vantage convergence therefore exists **within** each host, not across
  them. This report gives the strongest real convergence cluster for each host, and is
  explicit about which vantage supplies exe-only vs full argv.

---

## 1. Command / distinctive-exe inventory (what each artefact carries)

### DESKTOP-PM6C56D — LoneWolf disk (log2timeline), no argv, not in CAR
Counts are records extracted from the 4.17 M-line timeline:

| Artefact (`data_type`) | Records | Field carrying command evidence | Argv? |
|---|---|---|---|
| `windows:prefetch:execution` | 1,312 | `executable`, `path_hints`, `run_count` | exe + run count only |
| `windows:registry:amcache` | 604 | `full_path`, `filename`, `sha256`? | full path only |
| `windows:registry:appcompatcache` (shimcache) | 1,463 | `path` | full path only |
| `windows:registry:bam` | 76 | `path` (+ last-run time, user SID) | full path only |
| `windows:registry:userassist` | 153 | `value_name`, `number_of_executions` | path only (GUI launches) |
| `windows:lnk:link` | 1,639 (350 with args) | `command_line_arguments`, `local_path` | **args present** |
| `windows:registry:service` | 1,796 (634 with args) | `image_path`, `name` | **args present** (`-k`, `/svc`, `-s …`) |
| `windows:registry:run` | 27 (31 entries) | `entries` (name→command) | **full command line** |
| `windows:tasks:job` (.job) | 4 (all with params) | `application` + `parameters` | **args present** |
| `windows:registry:task_scheduler:task_cache:entry` | 1,454 | `task_name`, `task_identifier` | name only, no args |
| `windows:registry:mrulistex` (RecentDocs/OpenSaveMRU/CIDSizeMRU) | 65 | `entries` (typed/selected paths) | typed path, no argv |
| `windows:evtx:record` EID 4688 | 80 | `strings` = image path only | **NO cmdline** (audit-cmdline off) |
| `windows:evtx:record` EID 4104 (PS ScriptBlock) | 2 | script text | script only |

### DESKTOP-M913391 — Sysmon host (full argv)
- `EvtxECmd` EID 1 (`Microsoft-Windows-Sysmon/Operational`): `ExecutableInfo` = full argv,
  `PayloadData6` = `ParentCommandLine`. ~45 process-creation events.
- `hayabusa/timeline.jsonl`: `Details.Cmdline` + `Details.ParentCmdline` = full argv, plus
  Sigma `RuleTitle`. RuleTitles present: `Proc Exec` (45), `Proc Terminated` (40),
  **`Cmd.EXE Missing Space Characters Execution Anomaly` (1)**.

### BGP-WS1-CONF — memory host (full resident argv)
- `windows.piiat.processes.jsonl`: `CommandLine`, `ImageFileName`, `Path`, `Cwd`, `EnvVars`, SID, integrity.
- `windows.pslist.jsonl`: `ImageFileName` (exe only), PID/PPID, CreateTime.
- `car.db → process` (180 rows, **157 with `command_line`**): the **normalized** form of
  `piiat.processes` (verified: winlogbeat cmdline byte-identical between the two).
- `car.db → service` table exists with a `command_line` column but is **0 rows** (empty).

---

## 2. Cross-artefact linkage table (real values)

Legend for "supplies": **exe**=binary name only · **path**=full image path, no args ·
**argv**=full command line with arguments · **args**=arguments only.

| Distinctive command / binary | Host | Artefacts carrying it (+ what each supplies) | In CAR `command_line`? | Convergence use |
|---|---|---|---|---|
| **`s3browser-win32.exe`** (`C:\Program Files\S3 Browser\`) — insider S3 exfil tool | DESKTOP-PM6C56D | prefetch (exe `S3BROWSER-WIN32.EXE`, run_count=5, path) · amcache (path `c:\program files\s3 browser\s3browser-win32.exe` + `s3browser-con.exe`) · bam (`\Device\HarddiskVolume4\Program Files\S3 Browser\s3browser-win32.exe` + last-run) · userassist (path, execs=2 & 4) · mrulistex (typed `s3browser-win32.exe`) · lnk/shellitem (shortcut) | **NO** (disk host absent from CAR) | **6-vantage execution proof of one binary** — install + first run + repeated GUI launches. Every vantage is exe/path only; **argv is unrecoverable on this host**. |
| **`s3browser-7-6-9.exe`** installer (Downloads → Temp `IS-*.TMP`) | DESKTOP-PM6C56D | prefetch (`S3BROWSER-7-6-9.EXE` from `\USERS\JCLOUDY\DOWNLOADS`, then `.TMP` from `\APPDATA\LOCAL\TEMP\IS-SE75Q.TMP`) · amcache (`c:\users\jcloudy\downloads\s3browser-7-6-9.exe`) | NO | Ties the download → temp-extract → install chain; anchors S3 Browser provenance to `jcloudy`'s Downloads. |
| **`GoogleUpdateSetup.exe` / `GoogleUpdate.exe`** (incl. `\Temp\GUME1E0.tmp\`) | DESKTOP-PM6C56D | prefetch (27) · amcache (28) · shimcache (24) · bam (1) | NO | **4-vantage** disk convergence; shows shimcache+amcache+prefetch agreeing on the same image path across temp + install locations. |
| **`OneDriveSetup.exe` / OneDrive.exe** | DESKTOP-PM6C56D | prefetch (11) · amcache (14) · shimcache (12) | NO | 3-vantage; also appears as an argv-bearing native command via the Run key (below). |
| **`chrome.exe`** | DESKTOP-PM6C56D | prefetch · amcache · bam · shimcache · **lnk `--incognito`, `--win-jumplist-action=most-visited http://aws.amazon.com/`** | NO | Disk vantages give exe/path; **only the LNK preserves the argv** (`--incognito`, jumplist URLs) — argv lives solely in unnormalized native. |
| **obfuscated `cmd /c` env-var payload** (decodes to `flag{UKxhry6MoKCYdLV7RglTI5wEE23terqKVvf2FLdz2GexLeSMQ0jB0cmZPw1ITKn8D8r8vZs6iD1h90GU}`) | DESKTOP-M913391 | EvtxECmd EID1 (`ExecutableInfo` full argv) · hayabusa (`Details.Cmdline` full argv) · **hayabusa Sigma detection** (`Cmd.EXE Missing Space Characters Execution Anomaly`) | n/a (Sysmon host not in CAR) | **3-vantage on one execution, all full argv** — raw evtx ↔ timeline ↔ signature. The canonical "same command seen via log + detection" convergence. |
| `cmd.exe /c "ver"` , `ipconfig` , `whoami`-style recon | DESKTOP-M913391 | EvtxECmd EID1 (argv) · hayabusa (argv, `Proc Exec`) | n/a | evtx ↔ hayabusa full-argv convergence; classic hands-on-keyboard recon sequence. |
| `MicrosoftEdgeUpdate.exe /ua /installsource scheduler` | DESKTOP-M913391 | EvtxECmd EID1 (argv) · hayabusa (argv) | n/a | evtx ↔ hayabusa; note same `/ua /installsource scheduler` pattern also appears as a **.job** on the LoneWolf host (DropboxUpdate) — same scheduler idiom, two hosts, two artefact classes. |
| **`winlogbeat.exe … --environment=windows_service -c …yml --path.home … -E logging.files.redirect_stderr=true`** | BGP-WS1-CONF | piiat.processes (`CommandLine` full argv) · car.db process (`command_line` full argv, **normalized copy**) · pslist (exe only) | **YES** (memory-derived) | **3-vantage memory convergence**: pslist=exe vantage, piiat=raw resident argv, CAR=normalized argv. Demonstrates the one place normalization actually fires. |
| `scoringbot.exe`, `owncloud_crash_reporter.exe "…\*.dmp"`, `FTK Imager.exe`, `Everything.exe -svc`, `sshd.exe`, `nssm.exe` | BGP-WS1-CONF | piiat.processes (argv) · car.db process (argv) · pslist (exe) | YES | Same 3-vantage memory pattern; `owncloud_crash_reporter` argv reveals a crash-dump path in Temp only visible in the resident cmdline. |

---

## 3. Best multi-vantage execution links on real data (ranked)

1. **S3 Browser on DESKTOP-PM6C56D — 6 disk vantages, 0 argv.**
   prefetch(run_count=5) + amcache + bam(last-run + SID) + userassist(execs 2→4) +
   mrulistex(typed) + lnk. This is the strongest *breadth* convergence in the whole
   dataset and it is the LoneWolf insider's exfil tool. Its lesson: on a disk-only host
   you can prove *that* a binary ran six different ways yet **never recover its arguments**
   — the S3 bucket/keys it was pointed at are not in any of these artefacts.

2. **Obfuscated `cmd /c` on DESKTOP-M913391 — 3 vantages, all full argv.**
   Raw Sysmon EID1 `ExecutableInfo` ↔ Hayabusa `Details.Cmdline` ↔ Hayabusa Sigma hit
   `Cmd.EXE Missing Space Characters Execution Anomaly`. The `set …&&` alphabet builder
   and the `%%var%%%%var%%` expansion decode (88 single-char env vars, 86 tokens) to a
   `flag{…}` string — a DOSfuscation / character-substitution technique. This is the
   textbook "same execution, log + detection" convergence.

3. **winlogbeat / scoringbot / owncloud on BGP-WS1-CONF — 3 vantages incl. CAR.**
   pslist(exe) ↔ piiat.processes(argv) ↔ car.db process(argv). Only cluster where a full
   argv is actually lifted into CAR `command_line`, and proves CAR.process == normalized
   piiat.processes (identical strings).

---

## 4. Command lines / args sitting in native/raw, NOT lifted to CAR `command_line`

CAR only holds argv for **157 memory processes on one host**. Everything below is real
command content present in the processed data that **no CAR `command_line` field
normalises** — quantified with live examples.

| Native source | Records with a command/args | In CAR? | Real examples (verbatim) |
|---|---|---|---|
| **Services `image_path`** (`windows:registry:service`) | **634 of 1,796** carry arguments | CAR `service` table = **0 rows** | `%SystemRoot%\System32\svchost.exe -k netsvcs -p` · `"…\DropboxUpdate.exe" /svc` · `"…\GoogleUpdate.exe" /medsvc` · `"…\NVDisplay.Container.exe" -s NVDisplay.ContainerLocalSystem -f "C:\ProgramData\NVIDIA\…log" -l 3 -d "…plugins\LocalSystem"` — the `-k <group>` service-host grouping (the exact `-k netsvcs` flag the task calls out) is only in native. |
| **Run/RunOnce keys** (`windows:registry:run`) | 31 entries | not in CAR | `Uninstall 18.025.0204.0009: C:\Windows\system32\cmd.exe /q /c rmdir /s /q "C:\Users\jcloudy\AppData\Local\Microsoft\OneDrive\18.025.0204.0009"` · `GrpConv: grpconv -o` · `Dropbox: "…\Dropbox.exe" /systemstartup` · `GoogleDriveSync: "…\googledrivesync.exe" /autostart` |
| **Scheduled-task `.job`** (`windows:tasks:job`) | 4 (all with params) | not in CAR | `application=…\DropboxUpdate.exe  parameters=/ua /installsource scheduler` · `parameters=/c` |
| **LNK `command_line_arguments`** (`windows:lnk:link`) | **350** non-empty | not in CAR | chrome `--incognito` · chrome `--win-jumplist-action=most-visited http://aws.amazon.com/` · `AppVLP.exe "C:\Program Files (x86)\…\Office16\DCF\DATABASECOMPARE.EXE"` · `C:\Users\jcloudy\Downloads\rootkey.csv 5` |
| **RunMRU / OpenSaveMRU / RecentDocs** (`windows:registry:mrulistex`) | 65 (43 RecentDocs, OpenSavePidlMRU per-ext) | not in CAR | typed/selected `s3browser-win32.exe`, `rootkey.csv`, `key.txt`, `Operation 2nd Hand Smoke.pptx`, `The Cloudy Manifesto.docx` |
| **Prefetch / Amcache / Shimcache / BAM / UserAssist** | 1,312 / 604 / 1,463 / 76 / 153 | not in CAR (CAR `file` table is memory-MFT-derived, not these) | e.g. shimcache-only `C:\Temp\NVIDIA\3DVision\nvStInst.exe`, `C:\Users\jcloudy\…\TempState\Downloads\ChromeSetup.exe` — execution/existence evidence, exe/path only. |
| **Sysmon EID1 / Hayabusa (DESKTOP-M913391)** | ~45 full argv | not in CAR (host absent from CAR) | the obfuscated `cmd /c`, `cmd /c "ver"`, `ipconfig`, `python.exe -m ipykernel_launcher …`, EdgeUpdate `/ua /installsource scheduler` |

**Net:** the only argv that reaches CAR is the memory host's; **≈1,000+ real command
fragments across services(634), LNK(350), Run(31), .job(4), RunMRU(65)** — plus every
Sysmon EID1 argv — are stranded in native artefacts. This confirms and quantifies the
prior audit flags (LNK args, .job parameters, RunMRU, Services ImagePath args).

---

## 5. YARA rule stubs for high-signal command patterns

Rules target **rendered command-line text** (Sysmon `CommandLine`, memory `CommandLine`,
LNK args, Run/Service values, plaso `message`). `[O]` = grounded in an observed hit in
this dataset; `[P]` = proactive stub for the class. Tune before production; several will
also match on benign strings and are meant as triage leads.

```yara
/* [O] DOSfuscation: env-var char-substitution alphabet builder.
   Observed on DESKTOP-M913391: `cmd /c env =set IllllIIIll= &&set ...=<char>&&...`
   88 single-char SET assignments then %%var%%%%var%% expansion -> flag{...}. */
rule CMD_EnvVar_CharSub_Obfuscation
{
    meta:
        author = "DX_DFIR car-crosslink hunt"
        desc   = "DOSfuscation via mass single-char SET vars then %var% expansion"
        ref    = "DESKTOP-M913391 Sysmon EID1 obfuscated cmd /c"
    strings:
        $set_run  = /(&&set [A-Za-z]{6,12}=.){20,}/    // long &&set X=<char> chain
        $cmd      = "cmd /c" nocase
        $expand   = /(%%?[A-Za-z]{6,12}%%?){15,}/       // long %var%%var% expansion
    condition:
        $cmd and ($set_run or $expand)
}

/* [O] cmd.exe missing-space / caret / token-concatenation anomaly.
   Mirrors Hayabusa's "Cmd.EXE Missing Space Characters Execution Anomaly". */
rule CMD_MissingSpace_TokenConcat
{
    strings:
        $a = /cmd(\.exe)?["' ]{0,2}\/c["' ]{0,2}[%^]/ nocase
        $b = "&&set " nocase
        $c = /\^[a-z]/ nocase          // caret-escaped chars
    condition:
        $a and ($b or #c > 5)
}

/* [O] LOLBin / tool executed from user-writable Downloads or Temp.
   Observed: s3browser-7-6-9.exe from \Users\jcloudy\Downloads then \AppData\Local\Temp\IS-*.TMP;
   GoogleUpdate from \Temp\GUME1E0.tmp; setup.exe from C:\Temp\NVIDIA. */
rule Exec_From_User_Temp_Or_Downloads
{
    strings:
        $p1 = /\\Users\\[^\\]+\\Downloads\\[^\\"]+\.(exe|tmp|scr|com|ps1|bat|cmd)/ nocase
        $p2 = /\\Users\\[^\\]+\\AppData\\Local\\Temp\\[^"]+\.(exe|tmp|dll|scr)/ nocase
        $p3 = /\\Windows\\TEMP\\[^"]+\.(exe|tmp)/ nocase
    condition:
        any of them
}

/* [P/O] svchost anomaly: svchost with NO -k service group (or unknown group).
   Legit svchost in this data always carries -k <group>; bare svchost is suspect. */
rule Svchost_Missing_ServiceGroup
{
    strings:
        $svc      = /svchost\.exe/ nocase
        $dash_k   = /svchost\.exe"?\s+-k\s+[A-Za-z]/ nocase
    condition:
        $svc and not $dash_k
}

/* [P] Known-bad command flags: encoded/hidden PowerShell, remote download, LOLBin download.
   Not observed here (this dataset's PS is benign) - proactive triage stub. */
rule Suspicious_CommandLine_Flags
{
    strings:
        $enc1 = /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
        $enc2 = "-w hidden" nocase
        $enc3 = "FromBase64String" nocase
        $dl1  = "DownloadString" nocase
        $dl2  = "DownloadFile" nocase
        $dl3  = /Invoke-(Expression|WebRequest)/ nocase
        $lol1 = /(certutil|bitsadmin|mshta|regsvr32|rundll32)\b.{0,80}(http|\\\\|\/urlcache|javascript:)/ nocase
    condition:
        any of them
}

/* [O] Destructive/uninstall-style cmd wrappers seen in autoruns.
   Observed Run key: cmd.exe /q /c rmdir /s /q "...\OneDrive\18.025...". Benign here,
   but the /q /c rmdir /s /q wrapper is a common wiper/cleanup idiom - triage lead. */
rule CMD_Silent_RecursiveDelete
{
    strings:
        $a = /cmd(\.exe)?\s+\/q\s+\/c\s+rmdir\s+\/s\s+\/q/ nocase
        $b = /cmd(\.exe)?\s+\/c\s+del\s+\/f\s+\/q/ nocase
    condition:
        any of them
}
```

---

## 6. Practical takeaways for the CAR normalisation layer

- **Populate CAR `service.command_line` from `windows:registry:service.image_path`** — 634
  populated ImagePaths (incl. the `-k <group>` grouping) are being dropped today.
- **Add an autoruns/persistence normalisation** for `windows:registry:run.entries` and
  `windows:tasks:job` (application+parameters) → `command_line`; these carry real argv
  (`cmd.exe /q /c rmdir …`, DropboxUpdate `/ua /installsource scheduler`).
- **Lift `windows:lnk:link.command_line_arguments`** (350 non-empty) — on disk-only hosts
  the LNK is frequently the *only* artefact that preserves a process's argv (e.g. chrome
  `--incognito`, `rootkey.csv 5`).
- **Cross-vantage keying:** on a disk-only host, join prefetch↔amcache↔shimcache↔bam↔
  userassist on the **normalised image path** (exe basename + folder) to build the
  "execution proof" cluster; you will get breadth of evidence but must accept that argv is
  absent. Reserve the "same command across log+memory" convergence for hosts where a
  process-creation log (Sysmon EID1 / audited 4688-with-cmdline) or a memory capture
  exists — and note the LoneWolf 4688 events here are argv-less (audit-cmdline disabled).

---

### Artefact-extraction working files
This pass projected per-artefact JSONL out of the processed tree —
`prefetch.jsonl amcache.jsonl appcompatcache.jsonl bam.jsonl userassist.jsonl lnk.jsonl
service.jsonl run.jsonl taskjob.jsonl taskcache.jsonl mrulistex.jsonl shellitem.jsonl
evtx_proc.jsonl` plus the extracted value lists `pf_exe.txt am_path.txt shim_path.txt
bam_path.txt ua_val.txt` — as intermediate scratch (not committed). The findings above
are the durable output; the projections are reproducible from `data_store/processed/`.
