# CAR `file` object — Property-Provenance Catalogue

Authoritative "find once, done" map of **every canonical field → every artefact/source that can supply it**, grounded in the DX_DFIR engine as it stands today. READ-ONLY analysis.

- **Object semantics:** `third_party/piiat-mitrecar/third_party/car/data_model/file.yaml`; `car_data_model.json` (canonical field list confirmed identical to the task).
- **Canonical fields (26):** company, content, creation_time, extension, file_name, file_path, fqdn, gid, group, hostname, image_path, link_target, md5_hash, mime_type, mode, owner, owner_uid, pid, ppid, previous_creation_time, sha1_hash, sha256_hash, signature_valid, signer, uid, user.
- **Actions (7):** acl_modify, create, delete, modify, read, timestomp, write.

**Legend for "mapped?"** — `YES` (active map emits it) with file:line; `INERT` (spec exists but quarantined in `to-be-validated/evtx_audit.yml`, never runs); `NO` (nothing in the engine, source may or may not exist).

---

## 1. Source universe (every producer that emits — or provably could emit — a CAR `file`)

### Active maps (currently emit `file` rows)

| # | Source (map key) | Origin | Actions | Map location |
|---|---|---|---|---|
| S1 | **l2t_filestat** | disk image — filestat (`fs:stat`, POSIX/$SI stat) | create, delete, modify, read | `piiat_mitrecar/mappings/plaso_linux.py:351` (`_macb_entry`, `posix=True, hashes=True`) |
| S2 | **l2t_mft** | disk image — NTFS `$MFT` (MFTECmd/plaso `mft`) | create, delete, modify, read | `plaso_linux.py:354` |
| S3 | **l2t_usnjrnl** | disk image — NTFS `$UsnJrnl:$J` | create (0x100), delete (0x200), modify (default) | `plaso_linux.py:356` |
| S4 | **l2t_lnk** | disk image — Windows `.lnk` target MAC times | create, modify, read | `piiat_mitrecar/mappings/plaso_artifacts.py:110` |
| S5 | **l2t_recyclebin** | disk image — `$Recycle.Bin` / INFO2 | delete | `plaso_artifacts.py:120` |
| S6 | **plaso_shellitem** | disk image — shell items in LNK + shellbags (`windows:shell_item:file_entry`) | create, modify, read | `piiat_mitrecar/mappings/plaso_shellitem.py:97` |
| S7 | **plaso_pecoff** | disk image — PE binary (`pe_coff:file`) | create (ts=None, off-timeline) | `piiat_mitrecar/mappings/plaso_fs_extra.py:188` |
| S8 | **plaso_olecf** | disk image — OLE document `olecf:summary_info` | create, modify | `plaso_fs_extra.py:197` |
| S9 | **plaso_fseventsd** | disk image — macOS FSEvents journal | modify only | `plaso_fs_extra.py:163` |
| S10 | **plaso_exec_winreg / amcache_link_time** | disk image — Amcache "Link Time" row | create (ts=None, off-timeline) | `piiat_mitrecar/mappings/plaso_exec.py:244` |
| S11 | **jlecmd_dest** | disk image — jump-list DestList entry | read | `piiat_mitrecar/mappings/jlecmd.py:25` |
| S12 | **evtx_sysmon EID 11** (FileCreate) | Sysmon Operational | create | `piiat_mitrecar/mappings/sysmon.py:346` |
| S13 | **evtx_sysmon EID 23** (FileDelete) | Sysmon Operational | delete | `sysmon.py:369` |
| S14 | **evtx_more 4907** (SACL change, ObjectType=File) | Security log | acl_modify | `piiat_mitrecar/mappings/evtx_more.py:98` |
| S15 | **zeek_files** (files.log) | network pcap — Zeek file analyzer | create ("first seen on wire") | `piiat_mitrecar/mappings/zeek_extra.py:67` |
| S16 | **windows.mftscan.MFTScan** | memory image — Volatility `$MFT` pages (PIIAT-Mem, finished-CAR passthrough) | create | `third_party/piiat-mem/piiat_mem/mappings.py:192` (+ merge `enrich.py:154`) |
| S17 | **windows.piiat.files** | memory image — handle-enumerated files with owner | (action None — inventory) | `piiat-mem/piiat_mem/mappings.py:236` |
| S18 | **windows.filescan** | memory image — `FILE_OBJECT` pool scan | (action None — inventory) | `piiat-mem/piiat_mem/mappings.py:300` |

### Inert / to-be-validated (spec written, NOT wired into the pipeline)

Quarantined in `third_party/piiat-mitrecar/to-be-validated/evtx_audit.yml` (pipeline note: `piiat_mitrecar/pipeline.py:45`). These are schema-grounded but no corpus has the audit subcategory enabled, so they never run.

| # | Source | Actions | Spec |
|---|---|---|---|
| I1 | **Security 4663** object access (ObjectType=File) | read / write / delete (by `AccessMask`) | `evtx_audit.yml:33` |
| I2 | **Security 4660** object deleted | delete (path via paired 4663 HandleId) | `evtx_audit.yml:56` |
| I3 | **Security 4670** permissions changed | acl_modify | `evtx_audit.yml:72` |
| I4 | **Security 5140** share access | read / write | `evtx_audit.yml:127` |
| I5 | **Security 5145** detailed share access | read / write (+ per-file leaf) | `evtx_audit.yml:141` |
| I6 | **Security 5058** key-file operation | read (present in lonewolf; action inferred) | `evtx_audit.yml:206` |

### Groundable but entirely absent (no active map, no quarantined spec)

| # | Source | Would supply | Native fields |
|---|---|---|---|
| N1 | **Sysmon EID 2** (FileCreateTime / timestomp) | **timestomp** action, `previous_creation_time`, `creation_time` | `PreviousCreationUtcTime`, `CreationUtcTime`, `TargetFilename`, `Image`, `User` |
| N2 | **Sysmon EID 15** (FileCreateStreamHash) | ADS `content`, `md5/sha1/sha256_hash` on create | `Hash`, `Contents`, `TargetFilename` |
| N3 | **Sysmon EID 26** (FileDeleteDetected) | delete (logged-not-archived) | same shape as EID 23 |
| N4 | **Security 4656/4658** (handle request/close) | open→read/write correlation | `ObjectName`, `AccessMask`, `HandleId` |
| N5 | disk **$MFT $SI vs $FN** split (plaso `mft` emits per-attribute rows w/ `attribute_name`) | **timestomp** via $SI/$FN birth mismatch, `previous_creation_time` | `attribute_name`, the FN vs SI Created stamps |
| N6 | disk **$MFT security descriptor / $Secure** | NTFS `owner`/`owner_uid`/`uid` (owner SID), NTFS `mode` (ACL) | owner SID, group SID, DACL |
| N7 | **Volatility windows.dumpfiles** | `content` / hashes of memory-resident file | dumped bytes (written to disk, not into CAR today) |
| N8 | **Suricata fileinfo / eve.json** | `mime_type`, `md5/sha1/sha256`, `file_name` (network) | magic, stored hashes |
| N9 | **PE VERSIONINFO + Authenticode** (no hasher/verify plugin exists in-repo) | `company`, `signer`, `signature_valid` | CompanyName, cert subject, WinVerifyTrust verdict |

---

## 2. Per-field provenance matrix

Format: `field | sources (source → native field) | action(s) | mapped? | confidence & caveats`

### company
| | |
|---|---|
| **sources** | PE VERSIONINFO `CompanyName` (N9, not extracted by plaso `pe_coff`); Autoruns / Sysmon `Company` field (maps to **process/module**, never file) |
| **actions** | create, modify (per MITRE coverage_map) |
| **mapped?** | **NO** — no active or inert source. `plaso_pecoff` extracts imphash/pe_type/sections but *not* VERSIONINFO company (`plaso_fs_extra.py:109-111`). |
| **confidence** | High-confidence no-source. Genuinely needs a richer PE VERSIONINFO parser or Autoruns. Honest null everywhere. |

### content
| | |
|---|---|
| **sources** | Sysmon EID 15 `Contents` (ADS only, N2); Volatility `windows.dumpfiles` (N7); Zeek/Suricata extracted-file bytes; disk carving |
| **actions** | write, create |
| **mapped?** | **NO** — nothing emits `content`. dumpfiles writes bytes to disk, never into a CAR column. |
| **confidence** | High-confidence no-source. Inline file content rarely belongs in CAR; deliberately hard. Honest null. |

### creation_time
| | |
|---|---|
| **sources** | filestat → `Timestamp` (SI birth, create rows only) `plaso_linux.py:210`; mft → `Timestamp`; usnjrnl → `Timestamp` (0x100 create); lnk → `Timestamp`; shellitem → `Timestamp` `plaso_shellitem.py:69`; **Sysmon EID 11 → `CreationUtcTime`** (the file's OWN stamp, not event time) `sysmon.py:357`; mftscan-mem → `Created` (SI) `piiat-mem mappings.py:196` |
| **actions** | create (asserted only on action=create — any other MACB row's time is provably not the birth time; see `plaso_linux.py:209`) |
| **mapped?** | **YES** — broad. |
| **confidence** | Strong. Caveat: Sysmon 11 correctly separates file-creation stamp from event ts (overwrite verdict in native); plaso asserts it only on the create variant. |

### extension
| | |
|---|---|
| **sources** | every file source, derived `ext(path)` |
| **actions** | all |
| **mapped?** | **YES** — universal (S1–S18, incl. zeek `ext(filename)`). |
| **confidence** | Trivial derivation; only null when the path/name is null (e.g. 4660). |

### file_name
| | |
|---|---|
| **sources** | every file source, `basename(path)` (zeek/mftscan-mem straight from `filename`/`Filename`) |
| **actions** | all |
| **mapped?** | **YES** — universal. |
| **confidence** | Strong. Only 4660 (I2) lacks it (no ObjectName in the record). |

### file_path
| | |
|---|---|
| **sources** | filestat (`filename`\|`display_name`); mft (`name`\|`filename`; note plaso can't index `path_hints[0]` — kept native); usnjrnl; lnk (`local_path`\|`network_path`\|`link_target`); recyclebin (`original_filename`); shellitem (`shell_item_path`\|`long_name`\|`name`); pecoff; olecf; fseventsd (`path`); amcache_link (`full_path`); jlecmd (`Path`); Sysmon 11/23 (`TargetFilename`); 4907 (`ObjectName`); piiat.files (`Path`); filescan (`Name`) |
| **actions** | all |
| **mapped?** | **YES** — broad. |
| **confidence** | Strong. **NOT** on zeek_files (network file — no host path) or mftscan-mem (only `Filename`, full path not in memory-resident $MFT). |

### fqdn
| | |
|---|---|
| **sources** | Sysmon 11/23 → `EVTX_FQDN` (Computer, only if dotted) `sysmon.py:200`; 4907 → `_FQDN` |
| **actions** | create, delete, acl_modify |
| **mapped?** | **YES (partial)** — Windows EVTX host-telemetry only. |
| **confidence** | Medium. Plaso disk sources map only `hostname` (image_hostname), never fqdn — honest null, not a near-miss. |

### gid
| | |
|---|---|
| **sources** | **l2t_filestat → `group_identifier`** (POSIX numeric) `plaso_linux.py:208` |
| **actions** | create, delete, modify, read |
| **mapped?** | **YES (filestat only)**. |
| **confidence** | Strong on POSIX (verified on real evidence: `fs:stat` EXT record carries `group_identifier: 0`). No NTFS analogue (NTFS has no gid). |

### group
| | |
|---|---|
| **sources** | POSIX `/etc/group` join on gid (not implemented) |
| **actions** | — |
| **mapped?** | **NO** — filestat carries only the numeric gid, never the group name. |
| **confidence** | High-confidence no-source. Requires a passwd/group resolution step. Honest null. |

### hostname
| | |
|---|---|
| **sources** | filestat/mft/usn/lnk/recyclebin/shellitem/pecoff/olecf/fseventsd/amcache (`image_hostname`); jlecmd (`Hostname`); Sysmon 11/23 + 4907 (`Computer` first label) |
| **actions** | all |
| **mapped?** | **YES** — broad. |
| **confidence** | Strong. NOT on zeek_files (network file, no host) or mftscan-mem props. For disk artefacts it is the imaged-host stamp (recorded, not the event's own claim). |

### image_path
| | |
|---|---|
| **sources** | Sysmon 11/23 → `Image` (acting process exe) `sysmon.py:196`; 4907 → `ProcessName` |
| **actions** | create, delete, acl_modify |
| **mapped?** | **YES (partial)** — Windows host-telemetry only. |
| **confidence** | Medium. MITRE defines the hash fields as "hash of the file at image_path"; for disk artefacts the file IS the subject (file_path==the hashed file), so image_path is left null there rather than duplicating file_path. INERT 4663/4660/4670/5140/5145 also carry `ProcessName`→image_path. |

### link_target
| | |
|---|---|
| **sources** | **l2t_lnk → `link_target`** (the shortcut's stored target string) `plaso_artifacts.py:101` |
| **actions** | create, modify, read |
| **mapped?** | **YES (lnk only)**. |
| **confidence** | Medium. Recorded-not-trusted (a .lnk can be stale/crafted). POSIX symlinks (fseventsd/OSSEM `symlink_name`) are NOT mapped to link_target — potential add. |

### md5_hash
| | |
|---|---|
| **sources** | filestat → `md5_hash` (file's own) `plaso_linux.py:195`; **Sysmon EID 23** → `MD5=` from `Hashes` `sysmon.py:154`; zeek_files → `md5` |
| **actions** | create (filestat), delete (Sysmon 23, zeek create) |
| **mapped?** | **YES** (3 sources). |
| **confidence** | Strong. **NOT** on mft/usnjrnl (a hash there would be the `$MFT`/`$UsnJrnl` artefact's own — deliberately omitted, `plaso_linux.py:33`), **NOT** on Sysmon EID 11 create (event carries no hash). Sysmon EID 15 (N2) would add it on create. |

### mime_type
| | |
|---|---|
| **sources** | **zeek_files → `mime_type`** (incl. `application/x-dosexec` = PE) `zeek_extra.py:76`; Suricata fileinfo magic (N8) |
| **actions** | create |
| **mapped?** | **YES (zeek only)**. |
| **confidence** | Medium. Network-observed only. No host source computes MIME; libmagic on carved/dumped files would be the host path. |

### mode
| | |
|---|---|
| **sources** | **l2t_filestat → `mode`** (POSIX permission bits, e.g. `420`=0o644) `plaso_linux.py:207`; NTFS ACL (N6 — not mapped) |
| **actions** | create, delete, modify, read |
| **mapped?** | **YES (filestat POSIX only)**. |
| **confidence** | Strong on POSIX (verified: real `fs:stat` EXT record `mode: 420`). **GAP:** NTFS "ACL" mode has no source — 4670/4907 carry `OldSd`/`NewSd` and mftscan-mem carries `Permissions`, all kept **native**, never decoded into `mode`. |

### owner
| | |
|---|---|
| **sources** | plaso_olecf → `author` (document author — best-effort near-miss) `plaso_fs_extra.py:142`; POSIX passwd join (not implemented); NTFS owner-SID→name (N6) |
| **actions** | create, modify (olecf) |
| **mapped?** | **weak/near-miss (olecf author only)** — no true filesystem-owner name anywhere. |
| **confidence** | Low. The OLE `author` is document metadata, not the filesystem owner; treat with caution. filestat gives only numeric owner_uid, not a name. Effectively an honest no-source for the real owner. |

### owner_uid
| | |
|---|---|
| **sources** | **l2t_filestat → `owner_identifier`** (POSIX numeric UID) `plaso_linux.py:207`; NTFS owner SID (N6 — not mapped) |
| **actions** | create, delete, modify, read |
| **mapped?** | **YES (filestat POSIX only)**. |
| **confidence** | Strong on POSIX (verified: `owner_identifier: 0` = root; a 0 is a real id, not a blank). **GAP:** NTFS owner SID from `$MFT` security descriptor / `$Secure` → owner_uid/uid unmapped. |

### pid
| | |
|---|---|
| **sources** | Sysmon 11/23 → `ProcessId`; 4907 → `hex_int(ProcessId)`; piiat.files → `PID` (handle-holder) |
| **actions** | create, delete, acl_modify |
| **mapped?** | **YES (partial)** — host-telemetry + memory-handle only. |
| **confidence** | Medium. Files at rest (disk artefacts) have no acting pid — honest null. Sysmon also surfaces `owning_pid`/`owning_guid` (tier-1 process link). INERT audit family adds pid to 4663/4660/4670. |

### ppid
| | |
|---|---|
| **sources** | none direct; only via process-object enrichment (file.pid → its process → that process's ppid) |
| **actions** | — |
| **mapped?** | **NO** — no file event source carries the acting process's parent pid. |
| **confidence** | High-confidence no-source at map time. A cascade could inherit it from the linked process; never asserted on the file row today. Honest null. |

### previous_creation_time
| | |
|---|---|
| **sources** | **PIIAT-Mem mftscan** — SI birth vs FILE_NAME birth mismatch, filled at merge `enrich.py:186`; Sysmon EID 2 `PreviousCreationUtcTime` (N1, unmapped); disk $MFT $SI/$FN split (N5, unmapped) |
| **actions** | create (the DATA rides on a create row; the timestomp verdict is left to the analyst) |
| **mapped?** | **YES (memory mftscan only)**. |
| **confidence** | Medium, single-source. **This is the largest timestomp gap:** neither disk `$MFT` (l2t_mft doesn't compare $SI/$FN — one row per timestamp_desc) nor Sysmon EID 2 is mapped, so on-disk / host-telemetry timestomp evidence is invisible. |

### sha1_hash
| | |
|---|---|
| **sources** | filestat → `sha1_hash`; Sysmon 23 → `SHA1=`; zeek_files → `sha1`; **amcache_link_time → `sha1`** (the PROGRAM's SHA-1) `plaso_exec.py:259` |
| **actions** | create (filestat, amcache, zeek), delete (Sysmon 23) |
| **mapped?** | **YES** (4 sources). |
| **confidence** | Strong. Amcache is the notable disk source that ships a real program SHA-1 without on-image hashing. |

### sha256_hash
| | |
|---|---|
| **sources** | filestat → `sha256_hash`; Sysmon 23 → `SHA256=`; zeek_files → `sha256`; **pecoff → `sha256_hash`** (PE's own) `plaso_fs_extra.py:123`; **olecf → `sha256_hash`** (doc's own) `plaso_fs_extra.py:141` |
| **actions** | create (filestat/pecoff/olecf/zeek), delete (Sysmon 23), modify (olecf) |
| **mapped?** | **YES** (5 sources). |
| **confidence** | Strong. Caveat: shellitem/recyclebin/fseventsd carry a `sha256_hash` that is the ARTEFACT's own (the .lnk/hive/DB), deliberately kept as `artefact_sha256` native — never the target file's hash. |

### signature_valid
| | |
|---|---|
| **sources** | Sysmon EID 6/7 `SignatureStatus` (maps to **driver/module**.signature_valid, `sysmon.py:163` — never file); Authenticode verify (N9) |
| **actions** | modify (per MITRE coverage_map) |
| **mapped?** | **NO** for the file object. |
| **confidence** | High-confidence no-source. Would need Authenticode verification on a PE; no hasher/verify plugin exists in-repo (grep for hasher/yara/Authenticode: none). Honest null. |

### signer
| | |
|---|---|
| **sources** | Sysmon EID 6/7 `Signature` → **module/driver**.signer (`sysmon.py:246`, never file); PE Authenticode cert subject (N9) |
| **actions** | create, modify (per MITRE coverage_map) |
| **mapped?** | **NO** for the file object. |
| **confidence** | High-confidence no-source. Same as signature_valid. Honest null. |

### uid
| | |
|---|---|
| **sources** | 4907 `SubjectUserSid` (present but **unmapped** — `evtx_more.py` maps `user` only); INERT 4663/4660/4670/5140/5145 → `SubjectUserSid` (`evtx_audit.yml`); NTFS owner SID (N6) |
| **actions** | delete, acl_modify, read, write (per the audit spec) |
| **mapped?** | **NO** (active). Trivially groundable from 4907's own `SubjectUserSid`. |
| **confidence** | Medium. `owner_uid` (POSIX) is filled but is the *owner*, not the acting SID — different field. Quick win: add `uid` to the 4907 map. |

### user
| | |
|---|---|
| **sources** | filestat/mft/usn/lnk/recyclebin (`username`); Sysmon 11/23 (`User`); 4907 (`SubjectUserName`) |
| **actions** | create, delete, modify, read, acl_modify |
| **mapped?** | **YES** — broad. |
| **confidence** | Strong where the record fills it. Caveat: disk artefacts' `username` is the imaged-host context and is frequently `-` → honest null. jlecmd/shellitem/pecoff/zeek/filescan carry no user. |

---

## 3. Action coverage (which sources reach each canonical action)

| action | active sources | status |
|---|---|---|
| **create** | filestat, mft, usn(0x100), lnk, shellitem, pecoff, olecf, amcache_link, Sysmon 11, zeek_files, mftscan-mem | Well covered |
| **delete** | filestat(deletion desc), mft, usn(0x200), recyclebin, Sysmon 23 | Covered (INERT: 4660/4663; MISSING: Sysmon 26) |
| **modify** | filestat, mft, usn(default), shellitem, olecf, fseventsd | Covered |
| **read** | filestat, mft, lnk, shellitem, jlecmd | Covered (INERT: 4663/5140/5145/5058) |
| **acl_modify** | **4907** (single source) | Thin — one source (INERT: 4670) |
| **write** | **none** | **GAP — no active source.** USN "modify" is the nearest but is action=modify. Only INERT 4663/5140/5145 emit `write`. |
| **timestomp** | **none** | **GAP — no source emits action=timestomp.** mftscan-mem provides `previous_creation_time` DATA on a *create* row (verdict deferred to analyst), not the action. Canonical source is Sysmon EID 2 (unmapped) + $MFT $SI/$FN split (unmapped). |

---

## 4. Summary — coverage and ranked UNMAPPED gaps

**Coverage today.** The `file` object is the best-covered object in the engine — 15 active maps plus 3 memory maps span **18 producers** across disk (filestat/$MFT/$UsnJrnl/lnk/recyclebin/shellitem/PE/OLE/FSEvents/Amcache/jump-lists), host telemetry (Sysmon 11/23, Security 4907), network (Zeek files.log), and memory (mftscan/filescan/handle-enum). Path/name/extension, creation_time, the three hashes, POSIX mode/owner_uid/gid, hostname/user are all well grounded. **20 of 26 fields have at least one active source.**

**Fields with NO active source (6):** `company`, `content`, `group`, `ppid`, `signature_valid`, `signer`, plus effectively `owner` (only the weak OLE-author near-miss) and `uid` (present-but-unmapped in 4907). Actions `write` and `timestomp` have no active source at all.

**UNMAPPED gaps, ranked by value × groundedness:**

1. **`timestomp` action + `previous_creation_time` from disk & host telemetry — HIGHEST.** Only memory mftscan supplies it. Two clean, groundable sources are unused: **Sysmon EID 2** (`PreviousCreationUtcTime`/`CreationUtcTime` → the canonical timestomp event, N1) and the **disk `$MFT` $SI vs $FN birth mismatch** (plaso `mft` already emits per-attribute rows carrying `attribute_name` — the current l2t_mft map flattens them by timestamp_desc and never compares, N5). Highest anti-forensics value; both fully groundable.

2. **`write` action — HIGH.** No active source. The **inert Security 4663/5140/5145** audit family (`evtx_audit.yml`) is the ready-made spec (AccessMask→read/write/delete); promote once validated against an audit-enabled capture. Sysmon has no write event, so this is the only route.

3. **NTFS owner/uid/mode from the `$MFT` security descriptor / `$Secure` (N6) — HIGH.** Today `owner_uid`/`gid`/`mode` are POSIX-only (filestat). On Windows images these stay null even though the owner SID and DACL are on disk. `4907`/`4670` already carry `OldSd`/`NewSd` and mftscan carries `Permissions` — all kept native, never decoded into `mode`/`owner`.

4. **`uid` on Security 4907 — QUICK WIN.** `SubjectUserSid` is already in the record; the map emits `user` but not `uid` (`evtx_more.py:102`). One-line add; also unlocks uid across the inert audit family.

5. **Hashes/`content` on file-create host telemetry — MEDIUM.** **Sysmon EID 15** (FileCreateStreamHash, N2) would add `md5/sha1/sha256_hash` (and ADS `Contents`) to create events — currently only *delete* (EID 23) ships hashes on the host. **Sysmon EID 26** (FileDeleteDetected, N3) is the logged-not-archived delete, unmapped (only EID 23).

6. **`signer` / `signature_valid` / `company` — MEDIUM, needs new tooling.** No PE VERSIONINFO/Authenticode extractor exists in-repo (no hasher/verify plugin). Sysmon 6/7 signer data is spent on module/driver. Requires a PE-metadata/Authenticode step (or Autoruns ingest) — the only realistic route to these three "signed executable" fields.

7. **`mime_type` on host files — LOW.** Only Zeek supplies it (network). A libmagic pass over carved/dumped files, or Suricata fileinfo (N8), would extend it host-side.

8. **`group` (name), `content`, `ppid` — LOW / by design.** `group` needs a passwd/group join; `content` needs carving/dumpfiles wired into a CAR column (rarely appropriate); `ppid` is a cascade-inheritance concern, never a map-time file field. Honest nulls.

**Honest no-source (correctly left null):** `company`, `signer`, `signature_valid` (no signing extractor); `content` (no carving-to-CAR); `group` (no name resolution); `ppid` (no file source). These are not conservatism gaps — the producers do not exist in the pipeline.
