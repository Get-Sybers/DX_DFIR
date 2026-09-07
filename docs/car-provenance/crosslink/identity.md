# Identity-Linkage Hunt: SIDs & Usernames as Cross-Artefact Convergence Keys

Dataset: `/opt/github/DX_DFIR/data_store/processed/` — READ-ONLY hunt. All values below are real, pulled from the processed data.

## TL;DR

- The processed dataset contains **FOUR distinct hosts**, each with its own machine SID — the single most important cross-artefact discovery. Identity keys let you (a) prove which artefacts belong to the same account/host, and (b) expose that ~100% of disk-artefact identity is never lifted into a normalised CAR field.
- The **only** CAR store that exists (`volatility/memdump.mem/car.db`) is built solely from the **memory** image. Nothing from the disk (plaso/EvtxECmd/hayabusa) or network (zeek) is normalised into any CAR table — so 100% of those artefacts' identity is unmined by definition.
- On the disk plaso timeline the native `username` field is `"-"` for **4,169,732 of 4,169,774** records (**99.999%**), yet SIDs and `\Users\<name>\` paths are everywhere.

---

## The four hosts (machine-SID ↔ RID ↔ username reconciliation, real values)

| Host | Source artefacts | Machine SID | RID → username (real) |
|---|---|---|---|
| **DESKTOP-PM6C56D** (evtx hostname `WIN-1M3263ACE5D`, pre-rename; computer acct `WIN-1M3263ACE5D$`) | `log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (disk, 6.6GB) | `S-1-5-21-2734969515-1644526556-1039763013` | **1001→jcloudy** (login 15/23), **1000→defaultuser0** (login 2), 500→Administrator, 501→Guest, 503→DefaultAccount, 504→WDAGUtilityAccount, 513→(Domain Users group) |
| **memdump.mem** | `volatility/memdump.mem/` (memory → `car.db` + piiat plugins) | `S-1-5-21-2899045035-919344695-3383792992` | **500→Administrator**, **1000→gt** (`C:\Users\gt`), **1001→scoringbot** (`C:\Users\scoringbot`) |
| **DESKTOP-M913391** | `windows_logs/unspecified_host/log_EvtxECmd_Output.json` + `signatures/hayabusa/timeline.jsonl` | `S-1-5-21-3081547798-3199192215-1922722758` | **100137→JDH** (`DESKTOP-M913391\JDH`, `C:\Users\JDH`) |
| **5g-webui** (Linux) | `log2timeline/jsonl/5g-webui.jsonl` (7.8GB, `linux:utmp:event`, `syslog:ssh:login`) | n/a (Linux, no NT SID) | usernames: **root**, **LS23_BT10**, **gt**, **_mcs**, LOGIN |

Zeek network artefacts (`zeek/*/*.json`): **zero SIDs, zero `\Users\`** — as expected, no identity to mine.

### THE identity spine (DESKTOP-PM6C56D / jcloudy) — the canonical reconciliation chain

```
SAM  (windows:registry:sam_users)           Username: jcloudy   RID: 1001   Login count: 15
   +  ProfileList machine SID                S-1-5-21-2734969515-1644526556-1039763013
   =  full SID                               S-1-5-21-2734969515-1644526556-1039763013-1001
   -> ProfileList ProfileImagePath           C:\Users\jcloudy
   -> HKU\<SID> hive / UserAssist (HKCU)      per-user execution
   -> evtx SubjectUserSid (record 4728)       jcloudy (-1001) added to group -513 (Domain Users), subject S-1-5-18
   -> BAM  (defaultuser0, RID 1000)           program-execution attribution
   -> google_drive_sync_log (app self-binds): "Using SID PySID:S-1-5-21-2734969515-1644526556-1039763013-1001
                                                for account 'DESKTOP-PM6C56D\jcloudy'"
```
A single derivation of `...-1001 = jcloudy = C:\Users\jcloudy` attributes **every** row in the convergence table below.

---

## Convergence keys — same SID/user across ≥2 artefacts

| value (SID / user) | artefacts it appears in | normalised to CAR user/uid/sid? | link / convergence use |
|---|---|---|---|
| **jcloudy** = `S-1-5-21-2734969515-1644526556-1039763013-1001` | `\Users\jcloudy` path in ~20 disk data_types: fs:stat (92 909), registry:key_value (28 057), chrome:cache (21 636), google_drive_sync_log (18 700), chrome:cookie (8 863), chrome:history (2 293), pe_coff:file (1 323), msie:webcache (921), chrome:autofill (802), shell_item/shellbags (782), evtx (690), lnk:link (597), distributed_link_tracking (160), userassist (151), olecf:dest_list/jumplist (72), registry:mrulistex (65), registry:bagmru (60), openxml:metadata (55), chrome downloads (42). **SID (RID 1001)** in: evtx (42 838), fs:stat (2 448), registry (917), ntfs:usn_change (268), google_drive (133), prefetch (118), bam (64), task_scheduler (6), deleted_item (5). SAM RID 1001, ProfileList. | **NO** (disk → no CAR store; native `username`=`-`). Real value only in `windows:registry:sam_users` message + 10 evtx/task records. | **Primary convergence spine.** One derivation links web history + shellbags + LNK + jumplists + prefetch + evtx logons + file ownership + Drive sync to the same human. |
| **defaultuser0** = `...-1039763013-1000` | SAM (`sam_users`, RID 1000, login 2), ProfileList, **BAM** `UserSettings\<SID>` execution (message: `[S-1-5-21-2734969515-1644526556-1039763013-1000]`), `\Users\defaultuser0` (10 348 path hits) | **NO** — BAM `username`=`-`, SID only in message string | Ties OOBE/first-boot program execution (BAM) to the staged default profile; distinguishes automated vs. interactive (jcloudy) activity. |
| **gt** | memory host RID 1000 = `C:\Users\gt` (piiat.registry ProfileList) **AND** 5g-webui Linux utmp `username=gt` | Memory: partial (process/session `User` set); Linux: native `username` populated; **no CAR store for either → not in CAR** | **Cross-host username convergence** — same operator/account name `gt` on the memory Windows host and the 5G Linux host; candidate pivot linking the two captures. |
| **Administrator** = `...-3383792992-500` (memory host) | car.db `process` (38 rows, sid+uid+user set), `user_session` (login_id `0x3697b`), piiat ProfileList `C:\Users\Administrator` | **YES (memory only)** — process.sid/uid/user + user_session.uid populated | Links running processes ↔ logon session ↔ profile on the memory host. |
| **JDH** = `S-1-5-21-3081547798-3199192215-1922722758-100137` | EvtxECmd `UserName=DESKTOP-M913391\JDH` (69), hayabusa `Details`/`Users\JDH` (25), SID in EvtxECmd Payload (4) + hayabusa (2) | **partial** — EvtxECmd `UserName` field set, but `UserId` field = `S-1-5-18` only (JDH's SID `-100137` sits in raw Payload, not lifted); hayabusa has **no** user/sid field at all | Confirms EvtxECmd export and hayabusa signatures are derived from the **same** evtx (host DESKTOP-M913391). |
| **S-1-5-18 / S-1-5-19 / S-1-5-20** (well-known) | disk evtx (84 464 lines w/ 18/19/20), memory car.db process (18→81, 19→29, 20→11) + user_session, EvtxECmd UserId (85) | Memory: **YES**; disk/EvtxECmd: mostly raw | Baseline system-account noise; used to separate service from interactive activity. |
| **`...-1039763013-513`** (Domain Users group) | disk evtx (58) e.g. record 4728 group-membership | **NO** | Group-membership convergence: shows jcloudy's group context at account creation. |

---

## Dataset-wide count of UN-normalised user/SID occurrences, by artefact

**Disk plaso `DESKTOP-PM6C56D.jsonl` — records whose raw line carries a full `S-1-5-21-…-RID` SID while CAR user/uid/sid = null (no CAR store exists for disk, so 100% unnormalised):**

| data_type (artefact) | records carrying an S-1-5-21 SID | native `username` |
|---|---|---|
| windows:evtx:record | 48 230 | `-` (SID lives in `strings` / `xml_string` array) |
| windows:registry:key_value | 4 282 | `-` (SID in `key_path`/message, e.g. HKU\<SID>, ProfileList) |
| fs:stat | 2 544 | `-` (owner SID in NTFS security descriptor) |
| fs:ntfs:usn_change | 268 | `-` |
| windows:prefetch:execution | 133 | `-` |
| google_drive_sync_log:entry | 123 | `-` (app log self-binds SID↔`DESKTOP-PM6C56D\jcloudy`) |
| windows:registry:bam | 72 | `-` (SID = `UserSettings\<SID>` key) |
| windows:registry:task_scheduler:task_cache:entry | 6 | `-` |
| windows:metadata:deleted_item | 5 | `-` |

Native `username` field across the **entire** 4 169 774-record disk timeline: `"-"` on **4 169 732** (99.999%). The only real values (42 records total): `windows:registry:sam_users` (jcloudy×9, WDAGUtilityAccount×6, Administrator/Guest/DefaultAccount/defaultuser0 ×3 each), `windows:tasks:job`/`trigger` (`DESKTOP-PM6C56D\jcloudy` ×10), and 5 stray evtx records.

**Memory CAR store `car.db` (the only populated CAR db) — identity-field coverage of populated tables:**

| CAR table | rows | user | uid | sid / owner | verdict |
|---|---|---|---|---|---|
| `process` | 180 | 159 | 164 | sid 164 | **normalised** (only well-behaved table) |
| `user_session` | 9 | 4 | 9 | login_id 9 | uid always set; `user` null for font-driver-host SIDs (S-1-5-90/96-*) |
| `file` (MFTScan) | 31 828 | **0** | **0** | owner 0 / owner_uid 0 | **0% — every identity column null** |
| `registry` | 12 171 | **2** | — | — | **~99.98% null** |
| `authentication`,`driver`,`email`,`flow`,`http`,`module`,`service`,`socket`,`thread` | 0 | — | — | — | empty (no source data mapped) |

So even inside the CAR store, only `process` (and mostly `user_session`) actually normalise identity; `file` and `registry` — 44k rows — carry none. `image_context` (163 rows) is raw plugin passthrough.

**EvtxECmd export:** `UserName` populated (`DESKTOP-M913391\JDH`, `NT AUTHORITY\SYSTEM`) but `UserId` = `S-1-5-18` on 85 records only — JDH's SID `-100137` remains in the raw Payload, unlifted. **Hayabusa:** schema has **no** user/uid/sid field; identity exists only inside free-text `Details`.

---

## YARA rule stubs — sweep for unmined identity in raw/native artefacts

```yara
rule DFIR_Windows_SID_Any
{
    // Any Windows SID (well-known + domain/machine with RID). Hunts SIDs buried in
    // evtx <strings>/xml, registry key_paths (HKU\<SID>, BAM UserSettings\<SID>),
    // fs:stat security descriptors, and app logs (e.g. Google Drive "Using SID ...").
    meta:
        author = "dxdfir car-crosslink identity hunt"
        purpose = "flag identity keys that no CAR user/uid/sid field normalises"
    strings:
        $sid_domain    = /S-1-5-21-[0-9]{6,}-[0-9]{6,}-[0-9]{6,}-[0-9]{1,7}/ ascii wide
        $sid_wellknown = /S-1-5-(18|19|20)\b/ ascii wide
    condition:
        $sid_domain or $sid_wellknown
}

rule DFIR_Case_MachineSIDs
{
    // The four hosts' anchors in THIS dataset — pin an artefact to a specific host.
    meta:
        note = "PM6C56D=jcloudy disk; 2899045035=Administrator/gt/scoringbot memory; 3081547798=JDH evtx"
    strings:
        $h_desktop_pm6c56d = "S-1-5-21-2734969515-1644526556-1039763013" ascii wide
        $h_memdump         = "S-1-5-21-2899045035-919344695-3383792992"  ascii wide
        $h_m913391         = "S-1-5-21-3081547798-3199192215-1922722758"  ascii wide
    condition:
        any of them
}

rule DFIR_Windows_UserProfilePath
{
    // \Users\<name>\ profile paths — the disk-side convergence key (shellbags, LNK,
    // jumplists, chrome, google-drive, fs:stat). Excludes noise dirs to cut FPs.
    strings:
        // real named profiles seen in this case
        $case_users = /\\Users\\(jcloudy|defaultuser0|Administrator|gt|scoringbot|JDH)\\/ nocase ascii wide
        // generic profile-dir catch (validate hits: strip Public/Default/desktop.ini noise)
        $any_user   = /[\\\/]Users[\\\/][A-Za-z][A-Za-z0-9_.\- ]{1,32}[\\\/]/ nocase ascii wide
        $not_public = /\\Users\\(Public|Default|All Users)\\/ nocase ascii wide
    condition:
        $case_users or ($any_user and not $not_public)
}

rule DFIR_Linux_Identity
{
    // 5g-webui host: usernames appear in utmp/wtmp/ssh, not SIDs.
    strings:
        $u = /\b(root|LS23_BT10|gt|_mcs)\b/ ascii
        $ssh = "syslog:ssh:login" ascii
    condition:
        $ssh and $u
}
```

---

## So what (analyst use)

1. **`jcloudy` = `S-1-5-21-2734969515-1644526556-1039763013-1001`** is the case spine: one derivation attributes ~185k disk records (web history, shellbags, LNK, jumplists, prefetch, evtx logons, NTFS ownership, Drive sync) to one human — none of which the pipeline currently normalises.
2. **`gt`** is a cross-host pivot (memory Windows host RID 1000 ↔ 5G Linux utmp) worth confirming as the same operator.
3. **Biggest normalisation gap:** the disk (4.17M records) and the 44k `file`+`registry` CAR rows carry identity only in raw fields (`strings`, `key_path`, `native`, security descriptors) — a derivation lifting SID→username via SAM+Profilea spine would populate the null `user`/`uid`/`sid` CAR columns wholesale.
