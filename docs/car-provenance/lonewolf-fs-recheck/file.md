# CAR `file` — FILESYSTEM / disk-artefact provenance, deep sweep (LoneWolf)

Second-pass, filesystem-focused re-audit of the CAR **file** object. Builds on
`../file.md` (which covered LNK / shell items /
jump-list shell-items / USN / Recycle Bin / filestat, the user-from-path gap, the
LNK "Not a time" drop, and the $MFT-absent finding). This pass hunts the
**disk/filesystem artefacts that could fill `file` properties but the pipeline is
NOT mining** — the $MFT metafiles, ADS/Zone.Identifier, $Secure/$SDS, PE/OLE/
OOXML document metadata, amcache hashes+company, jump-list DestList, and the
save/open MRU strings.

Everything is grounded in the REAL plaso output
`data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl`
(LoneWolf Win10, **4,169,774 rows**, whole-file counts below) and the live maps in
`byakugan/piiat_mitrecar/mappings/`. READ-ONLY.

---

## 0. What LoneWolf actually contains — file-bearing data_types (whole-file, grounded)

| data_type | count | map today | → CAR object | mined for `file`? |
|---|---:|---|---|---|
| `fs:stat` (filestat) | **1,968,065** | `l2t_filestat` (plaso_linux.py:351) | file | YES (path/mac/sha256) |
| `windows:registry:key_value` | 1,506,720 | `plaso_registry` | registry | n/a (registry) |
| `fs:ntfs:usn_change` | **359,999** | `l2t_usnjrnl` (plaso_linux.py:356) | file | YES (bare-leaf path) |
| **`pe_coff:file`** | **150,708** | `plaso_pecoff` (plaso_fs_extra.py:188) | file | **YES — NEW** (path+sha256+imphash) |
| `windows:evtx:record` | 116,494 | evtx maps | (events) | n/a |
| `windows:shell_item:file_entry` | 2,069 | `plaso_shellitem` | file | YES |
| `windows:lnk:link` | 1,639 | `l2t_lnk` | file | PARTLY (Not-a-time drop) |
| `windows:registry:appcompatcache` | 1,463 | `plaso_exec_winreg` | process | n/a |
| `windows:prefetch:execution` | 1,312 | `plaso_exec_prefetch` | process | n/a |
| **`olecf:summary_info`** | **276** | `plaso_olecf` (plaso_fs_extra.py:197) | file | **YES — NEW** (author→owner,sha256) |
| `windows:distributed_link_tracking:creation` | **254** | — | — | **NO — unmapped** |
| **`openxml:metadata`** | **223** | — | — | **NO — unmapped** |
| `windows:registry:userassist` | 153 | `plaso_exec_winreg` | process | n/a |
| `windows:registry:bam` | 76 | `plaso_exec_winreg` | process | n/a |
| **`olecf:dest_list:entry`** | **72** | — | — | **NO — unmapped** |
| `windows:registry:mrulistex` | 65 | `plaso_registry` | registry | **file NOT surfaced** |
| `windows:registry:bagmru` | 62 | `plaso_registry` (+shell items) | registry/file | shell-item half only |
| **`olecf:document_summary_info`** | **49** | — | — | **NO — unmapped (has `company`!)** |
| `windows:registry:mrulist` | 17 | `plaso_registry` | registry | **file NOT surfaced** |
| `windows:metadata:deleted_item` | 5 | `l2t_recyclebin` | file | YES |
| `fs:ntfs:mft` | **0 — ABSENT** | `l2t_mft` (plaso_linux.py:354) | file | **NO INPUT** |
| `windows:srum:*` | **0 — ABSENT** | `l2t_srum` (plaso_srum.py) | flow/process | **NO INPUT** |

**Two structural absences reconfirmed (they gate half the sweep):**

1. **No `$MFT`.** `fs:ntfs:mft` = 0; the `mft` parser did not run. So there is
   **no `$SI`/`$FN` pair** (`attribute_name`/`STANDARD_INFORMATION`/`$FILE_NAME`
   line-hits = **0**), **no resident `$DATA`** (`:$DATA` hits = 0), **no `$I30`**
   (0), and **no MFT security descriptor** (`security_descriptor` key = 0). The
   on-disk timeline is filestat + USN only. **This is the single biggest unmined
   file source and it is a COLLECTION-lane gap, not a map gap** (see §3.1).

2. **No ADS / Zone.Identifier.** `Zone.Identifier` line-hits = **0**; there is no
   `windows:zone_identifier` data_type and filestat emits no `:streamname` ADS
   rows on this image. So mark-of-the-web / download-provenance (HostUrl,
   ReferrerUrl) has **no source here** — also a collection/parser gap (§3.6).

**Metafiles present as paths only (no content parser):** `$Secure` 16, `$ObjId`
16, `$LogFile` 16, `$I30` 0, `$SDS` 0 — these are just filestat rows for the NTFS
metafiles; plaso has no parser that decodes `$Secure:$SDS` (owner SID/ACL),
`$LogFile` (transactions) or `$ObjId`. `thumbcache` (782 hits) and `IconCache`
(1,266 hits) are likewise just the `.db` file paths — **no thumbcache/iconcache
parser exists**, so the deleted-file thumbnails/paths inside them are unmined.

---

## 1. Per-field provenance matrix — filesystem/disk artefacts (LoneWolf-grounded)

Legend: **Y** mapped & populated · **Y·NEW** newly mapped since the prior pass ·
**Y·null** mapped but null on this evidence · **PARTIAL** some source mapped,
a richer one unmined · **N** no source · **UNMINED** a real source is present
and is NOT mapped to this field.

| field | fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|---|
| **company** | `olecf:document_summary_info.company` (49); `windows:registry:amcache.company_name` (564/604) | create | **UNMINED** | **The ONLY on-disk sources for `company`, and BOTH are dropped.** doc-summary carries `company="Microsoft"` verbatim; amcache carries the binary's `company_name`. High-value, fully grounded. See §3.2/§3.3. |
| **content** | (MFT resident `$DATA`) | create/write | **N** | No `$MFT` → no resident small-file content; no carving. Honest null (blocked by §3.1). |
| **creation_time** | filestat/usn/shellitem/lnk `Timestamp` on create rows | create | **Y** | Present. Unchanged from prior pass. |
| **extension** | all file maps, `ext(path)` | all | **Y** | Universal (incl. pe_coff/olecf/openxml NEW). |
| **file_name** | all file maps, `basename(path)` | all | **Y** | Universal. |
| **file_path** | filestat `filename`; usn bare-leaf `filename`; **pe_coff `display_name`**; **olecf `display_name`**; lnk/shellitem/recyclebin (prior); **UNMINED: `olecf:dest_list:entry.path`, mrulistex/mrulist `entries`** | all | **PARTIAL** | pe_coff/olecf paths now mapped (NEW). USN still bare-leaf (needs MFT join). Jump-list DestList `path` (72) and the save/open MRU `entries` file strings are NOT surfaced as file rows (§3.4/§3.5). |
| **fqdn** | `olecf:dest_list:entry.hostname` (33/72, e.g. `desktop-pm6c56d`) | read | **UNMINED (weak)** | DestList records the host the file lived on — it is the imaged host here, so it maps to `hostname`, not a remote fqdn. Honest: no true fqdn source on disk. |
| **gid** | filestat `group_identifier` | c/d/m/r | **Y·null** | 0 of 1.97M fs:stat rows carry it (NTFS, no POSIX block). |
| **group** | — | — | **N** | No name resolution; no gid here anyway. |
| **hostname** | all maps `image_hostname` = `DESKTOP-PM6C56D` | all | **Y** | Universal. |
| **image_path** | — | — | **N** | Files at rest have no acting process image. |
| **link_target** | lnk `link_target` (prior) | c/m/r | **Y** (see prior §1b) | Lost on 328 "Not a time" LNK rows (prior finding, still open). |
| **md5_hash** | filestat `md5_hash` | create | **Y·null** | Mapped; **0** of 1.97M filestat rows carry md5 (only sha256 hasher ran). |
| **sha1_hash** | filestat `sha1_hash`; **amcache `file_identifier` (the program SHA-1)** | create | **PARTIAL / UNMINED** | filestat sha1 = 0 rows. **amcache: the SHA-1 IS present (604 rows, `file_identifier` = `0000`+40hex) but the map reads a non-existent `sha1` key → file.sha1_hash resolves NULL.** Grounded bug, §3.3. |
| **sha256_hash** | filestat `sha256_hash` (1,641,661); **pe_coff `sha256_hash` (150,708)**; **olecf/openxml `sha256_hash`** | create | **Y·NEW (big)** | filestat 83% coverage. **pe_coff added 150k file hashes + 104k imphashes (native).** olecf/doc-summary/openxml each carry the document's own sha256. Strong. |
| **mime_type** | — | — | **N** | No host MIME computation. |
| **mode** | filestat `mode` | c/d/m/r | **Y·null** | 0 of 1.97M (NTFS, no POSIX mode). No `$Secure` ACL decode either. |
| **owner** | `olecf:summary_info.author` → owner (mapped); `openxml` creator (UNMINED); (MFT/$Secure owner SID) | create | **PARTIAL** | OLE `author`→`owner` is mapped (NEW). openxml `creator`/`lastModifiedBy` NOT mapped (§3.2). True NTFS owner (SID via `$Secure:$SDS` / MFT SD) has **no source** (§3.1). |
| **owner_uid** | filestat `owner_identifier`; (MFT/$Secure owner SID) | c/d/m/r | **Y·null / N** | filestat: 0 of 1.97M. NTFS owner SID would come from `$Secure:$SDS` / MFT security descriptor — **absent** (§3.1). |
| **pid / ppid** | — | — | **N** | No acting process on a file-at-rest artefact. |
| **previous_creation_time** | (MFT `$SI` vs `$FN`) | create/timestomp | **N** | No `$MFT` → no `$SI`/`$FN` pair to diff. Blocked by §3.1. |
| **signature_valid** | (Authenticode / catalog `.cat` / amcache) | create | **N** | pe_coff carries **0** signer/signature keys (plaso `pe` does not verify Authenticode); catroot `.cat` not parsed; amcache here has no signer field. Only the **Sysmon EVTX** map fills this (event-log, not disk). §3.6. |
| **signer** | (Authenticode / catalog / amcache publisher) | create | **N** | Same as signature_valid — no on-disk producer. §3.6. |
| **uid** | Recycle Bin `$Recycle.Bin\S-1-5-21-…-<RID>` SID in path (prior, still UNMINED) | delete | **UNMINED** | Prior finding: the SID is verbatim in the artefact path, unextracted. |
| **user** | all maps `username` = `"-"`; identity in the artefact PATH (prior) | all | **UNMINED** | Prior #1 gap: `username` null 100%, `\Users\<name>\` in the path not mined. Unchanged. |

---

## 2. What is NEWLY mined since the prior pass (credit where due)

Three maps that did not exist / were not exercised in the first pass now pull
disk-file evidence — worth recording so the backlog does not re-flag them:

- **`plaso_pecoff` (plaso_fs_extra.py)** — **150,708** `pe_coff:file` rows → a
  timestamp-less `file/create` each, carrying `file_path` + the binary's own
  **`sha256_hash`**, with **`imphash`** (104,460), `pe_type`, `export_dll_name`
  (93,624) and `section_names` native. This is now the largest single source of
  executable hashes on the image. (Correctly time-free: every PE stamp is a
  compile/link time, not a host event — here all 150k are `timestamp_desc="Not a
  time"` so only the placeholder variant fires.)
- **`plaso_olecf` (plaso_fs_extra.py)** — **276** `olecf:summary_info` rows → file
  with `author`→**`owner`**, the document's `sha256_hash`, and title/application/
  last_saved_by native. Legacy Office (.doc/.xls) authoring metadata.
- **`l2t_srum` map exists** but SRUM is still **0 rows** (parser not wired) — so
  it fires on nothing (matches the prior backlog #7; unchanged).

---

## 3. Ranked UNMINED opportunities (value × groundedness, filesystem-only)

### 3.1 `$MFT` metafiles — the master blocker (COLLECTION-lane fix) — HIGHEST
The `mft` parser did not run (`fs:ntfs:mft` = 0). Extracting `$MFT` unlocks, in
one stroke, five things nothing else on a Windows image can give:
- **`previous_creation_time` + action `timestomp`** — the `$SI` creation vs `$FN`
  creation diff (the classic `$SI < $FN` timestomp tell). No other artefact has a
  second birth stamp to compare.
- **`content`** — MFT-**resident `$DATA`** for small files (< ~700 B): the file's
  bytes live inside the MFT entry. The only non-carving path to `file.content`.
- **`owner_uid` / `owner`** — the entry's security-id → `$Secure:$SDS` owner SID
  (see §3.7). NTFS's real owner, which POSIX `mode`/`owner_id` can never supply.
- **`$I30` deleted filenames** — index slack in directory entries recovers names
  of deleted files (extra `file`/`delete` rows).
- **USN full paths** — `parent_file_reference` → MFT join reconstructs the
  directory for all 359,999 bare-leaf USN rows (prior finding).

The `l2t_mft` map (plaso_linux.py:354) is already well-formed (it even documents
the `path_hints[0]`/`$SI`-vs-`$FN` intent). **The fix is to make the plaso lane
run the `mft` parser and collect `$MFT`** — flag to epic #134. Until then every
row above is an honest null *for want of input*, not a map defect.

### 3.2 `olecf:document_summary_info` + `openxml:metadata` → file (map gap) — HIGH
Two document-metadata data_types are **present and completely unmapped**:
- `olecf:document_summary_info` (49) — carries **`company`** (e.g. `"Microsoft"`),
  `application_version`, `shared_document`, and the doc's own `sha256_hash`. This
  is the **only on-disk `file.company` source** and it is dropped. It is the exact
  sibling of the already-mapped `olecf:summary_info`; the same `_ole_map` shape
  extended with `company` closes it.
- `openxml:metadata` (223) — modern OOXML (.docx/.xlsx/.pptx/templates). The
  `czip/oxml` parser exposes core/app properties (creator, last_modified_by,
  company, application, revision). On LoneWolf these rows are Office *template*
  files so creator/company are sparse, but every row still yields `file_path` +
  the document's `sha256_hash`, and the map belongs for real authored docs.
  Map: → `file`, `owner`=creator, `company`=company, `sha256_hash`, timestamp-less
  (all rows here are "Not a time"), authoring fields native. **Clean, low-risk.**

### 3.3 amcache → file: recover the SHA-1 (+ company) — HIGH, grounded bug
All **604** `windows:registry:amcache` rows are `timestamp_desc="Link Time"`, so
they route **entirely** to the timestamp-less `file` record in
`plaso_exec.py:244` (`plaso_is_amcache_link_time`) — the execution/process
variant fires 0×. But that file record has two grounded defects:
- `props.sha1_hash = _R("sha1")` — **there is no `sha1` key.** The program SHA-1
  is in **`file_identifier`** (all 604 rows: length 44 = a `"0000"` pad + 40 hex,
  e.g. `00009842cd168f6b…`). So `file.sha1_hash` resolves **NULL** today while the
  hash is sitting right there. Fix: `regex1(file_identifier, r"0000([0-9a-f]{40})")`.
- `company_name` (564), `product_name` (572), `file_version` (552) are **not
  carried** — `company_name` → `file.company`, product/version native.

amcache is the richest on-disk hash+identity source for executables *that also
names the company*; both fixes are one line each. (This is the "file half" of the
prior backlog's "amcache double-bug" #3 — recorded here for the `file` object.)

### 3.4 `olecf:dest_list:entry` (jump-list DestList) → file/read — MEDIUM-HIGH
**72** rows, **unmapped**. Each DestList entry is a file the user opened via a
jump list, carrying a clean **`path`** (target file), the origin **`hostname`**
(`desktop-pm6c56d` — where the file lived), `entry_number`, `pin_status`, and the
DLT **`droid`/`birth_droid`** volume+file GUIDs (object-ID origin). Today only the
jump-list *shell-item* halves reach `file` (via `plaso_shellitem`); the DestList
entries — which hold the richest metadata (origin host, pin/access, droids) — are
dropped. Map: → `file`/`read`, `file_path`=`path`, droids/hostname/pin native.
Recorded-not-trusted (a DestList entry can be stale). Grounds real case activity
(the `f01b4d95…automaticDestinations-ms` under `\Users\jcloudy\…\Recent`).

### 3.5 save/open MRU `entries` → file/read (accessed files + the app) — MEDIUM
`RecentDocs` (93), `OpenSavePidlMRU` (88), `LastVisitedPidlMRU` (20) arrive as
`windows:registry:mrulistex`/`mrulist` and today become **registry `key_edit`**
rows only — the accessed FILE named in the value is preserved only as a native
`entries` string, never a CAR `file`/read. These strings name the case-defining
files verbatim:
- RecentDocs `.txt`: `"Path: key.txt, Shell item: [key.lnk]"` (the ransom-note file)
- OpenSavePidlMRU `\html`: `"Shell item path: <My Computer> {b4bfcc3a-…}\Cubs'
  Anthony Rizzo …'It's too Easy to Get a Gun'.html"` (downloaded/saved articles)
- LastVisitedPidlMRU: `"Path: s3browser-win32.exe, Shell item path: …"` and
  `"Path: chrome.exe, …\Users\jcloudy\Desktop"` — the **application** used *and*
  the folder it last visited.
Opportunity: parse `Path:\s*([^,]+)` / `Shell item path:\s*(?:<[^>]+>\s*)?(.+)`
out of `entries` and emit a `file`/read (LastVisited's `Path:` also gives the
opening app). **Caveat:** this parses plaso's rendered `entries` text (brittle,
recorded-not-trusted); some shell-item halves already surface via
`plaso_shellitem`, so scope to the string-only cases (RecentDocs value,
LastVisited `Path: <app>`). Medium confidence.

### 3.6 `signer` / `signature_valid` — NO on-disk source (TOOL gap) — noted
pe_coff:file carries **0** signer/signature keys (plaso `pe` extracts
imphash/sha256/sections but does **not** verify Authenticode). The security
catalog (`catroot\*.cat`) is not parsed; amcache here has no signer field. The
only producer of `file.signer`/`file.signature_valid` in the whole repo is the
**Sysmon EVTX** map (`sysmon.py:246`, EID 6/7 — event-log, out of scope for disk
artefacts). To fill these from a dead disk you would need an Authenticode/catalog
extractor that does not exist. Honest no-source; flag to the collection lane as a
tool gap, not a map gap.

### 3.7 `$Secure:$SDS` owner SID + ACL → owner/owner_uid/acl_modify — BLOCKED
The canonical NTFS owner/ACL source. `$Secure`/`$SDS` are present only as filestat
metafile *paths* (no content decode); `security_descriptor` key = 0 everywhere.
Ties to §3.1 — needs `$MFT` security-ids + `$Secure:$SDS` parsing. `acl_modify`
has no producer at all on this image.

### 3.8 thumbcache / IconCache — NO parser (TOOL gap) — noted
`thumbcache_*.db` (782 path hits) and `IconCache.db` (1,266) hold thumbnails/paths
of **deleted** files — a classic recovery source. Plaso has no parser for them,
so their contents are unmined; only the container files appear via filestat.
Tool/collection gap (e.g. thumbcache_viewer-class extraction).

### 3.9 `windows:distributed_link_tracking:creation` → native only — LOW
**254** rows, unmapped. Carries `uuid` (ObjectID / DLT file-droid GUID), a
node **`mac_address`** (the origin machine's NIC), `origin` (the .lnk) and a
Creation Time. No clean CAR **file** field fits a tracking GUID or a MAC —
best surfaced as native provenance / a correlation key on the related LNK, not a
`file`-field win. Recorded for completeness.

---

## 4. Honest no-sources on filesystem artefacts (correctly NULL here)

- **`content`, `previous_creation_time`, action `timestomp`, `$I30` names, true
  NTFS `owner`/`owner_uid`** — all blocked by the absent `$MFT`/`$Secure` (§3.1,
  §3.7). Honest null *for want of input* (maps are fine / ready).
- **`signer`, `signature_valid`, `acl_modify`** — no on-disk extractor exists
  (§3.6, §3.7). Tool gap.
- **`mime_type`, `pid`, `ppid`, `image_path`, `group`, `fqdn`** — no disk artefact
  carries them.
- **`mode`, `owner_uid`, `gid` (POSIX)** — 0 of 1.97M NTFS `fs:stat` rows (POSIX
  block absent on NTFS; the maps are correct, the data isn't in this image).
- **`md5_hash`, `sha1_hash` (filestat)** — 0 rows (only the sha256 hasher ran).
- **ADS / Zone.Identifier (mark-of-the-web, HostUrl)** — 0 rows; no ADS emitted
  and no zone parser (§0, §3.6-adjacent). Collection/parser gap.

---

## 5. Ranked one-line-ish backlog (this pass, `file`-object only)

1. **Collect `$MFT`** (make the plaso lane run the `mft` parser) → unlocks
   `previous_creation_time`, `timestomp`, resident `content`, `$I30` deleted
   names, USN full-path join, and the security-id for owner. **Epic #134.** (§3.1)
2. **amcache file record**: read the SHA-1 from `file_identifier` (strip the
   `0000` pad) into `sha1_hash`, and map `company_name`→`company`. 604 rows,
   grounded. (§3.3)
3. **Map `olecf:document_summary_info`** (→ `company` + sha256) and
   **`openxml:metadata`** (→ owner/creator + company + sha256) — both present,
   both unmapped; extend the existing `_ole_map` shape. (§3.2)
4. **Map `olecf:dest_list:entry`** → file/read with `path` + native droids/host. (§3.4)
5. **Surface save/open MRU accessed files**: parse `entries` on RecentDocs /
   OpenSavePidlMRU / LastVisitedPidlMRU → file/read (+ the opening app from
   LastVisited `Path:`). Brittle string parse, recorded. (§3.5)
6. **Tool gaps to flag (not map fixes):** Authenticode/catalog signer verify
   (§3.6), `$Secure:$SDS` ACL decode (§3.7), thumbcache/IconCache extraction
   (§3.8), SRUM parser wiring (still 0 rows), ADS/Zone.Identifier collection (§0).

---

### Appendix — verbatim record excerpts used (grounded)

- **pe_coff:file (mined):** `display_name "VSS2:NTFS:\Windows\SysWOW64\en-US\
  msieftp.dll.mui"`, `sha256_hash "cf027a6c…"`, `pe_type "Dynamic Link Library
  (DLL)"`, `timestamp_desc "Not a time"`. (150,708 rows; imphash on 104,460.)
- **olecf:document_summary_info (UNMAPPED):** `display_name "NTFS:\…\
  MsoIrmProtector.xls"`, **`company "Microsoft"`**, `application_version
  "11.5870"`, `sha256_hash "fe2adbf0…"`.
- **openxml:metadata (UNMAPPED):** `display_name "NTFS:\Program Files (x86)\
  Microsoft Office\root\Templates\1033\Access\DataType\Phone.accft"`,
  `sha256_hash "8e1f7668…"`, `parser "czip/oxml"`.
- **amcache (SHA-1 in the wrong key):** `full_path "c:\program files\google\drive\
  googledrivesync.exe"`, **`file_identifier "00009842cd168f6b4d8be8979f3a40fb4de6f9afcbee"`**
  (0000 + 40hex), `company_name ""`/`product_name ""` (empty on this entry),
  `timestamp_desc "Link Time"`, `sha256_hash` = the Amcache.hve's own hash.
- **olecf:dest_list:entry (UNMAPPED):** `display_name "…\Users\jcloudy\…\Recent\
  AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms"`, has `path`,
  `hostname "desktop-pm6c56d"`, `droid_file_identifier "{3869c1ca-…}"`,
  `entry_number 3`, `pin_status`.
- **RecentDocs MRU (file NOT surfaced):** key `…\Explorer\RecentDocs\.txt`,
  `entries ["Index: 1 [MRU Value 0]: Path: key.txt, Shell item: [key.lnk]"]`.
- **LastVisitedPidlMRU (app + folder, NOT surfaced):** `entries ["… Path:
  chrome.exe, Shell item path: <My Computer> C:\\Users\\jcloudy\\Desktop", "…
  Path: s3browser-win32.exe, …"]`.
- **fs:stat (NTFS):** `filename "\Users\jcloudy\…\waterGlass.svg"`, `sha256_hash
  "bd2f81d3…"`, `file_size 5263`, `is_allocated true` — NO `mode`/
  `owner_identifier`/`group_identifier`/`md5`/`sha1`.
- **usn:** `filename "oleaut32.dll"` (bare leaf), `display_name
  "VSS1:NTFS:\$Extend\$UsnJrnl:$J"`, `update_reason_flags 2147483648`.
