# CAR `registry` — FILESYSTEM/disk-hive provenance audit: what the pipeline HASN'T MINED

Deep-audit of the MITRE CAR **registry** object against the real Windows-10 **LoneWolf**
disk-registry evidence, focused on **hive content the pipeline drops** rather than the
per-field basics (those are in `../registry.md`). Every count
below is measured this pass over the actual plaso JSONL. READ-ONLY.

- **Evidence:** `data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl`
  (6.6 GB, 4,169,774 rows; **1,512,651** are `windows:registry:*`).
- **Maps under audit:** `byakugan/piiat_mitrecar/mappings/plaso_registry.py`
  (predicate `startswith("windows:registry:")`, action **key_edit**) and `recmd.py`
  (RECmd batch → **value_edit**). Routing: `piiat_mitrecar/pipeline.py` `ROUTES`.
- **Extraction lane:** `python/get_sybers_dxdfir/zimmerman.py` (`ARTIFACT_GROUPS` filter +
  per-tool argv) and `plaso.py`.
- **CAR registry fields:** `data, fqdn, hive, hostname, image_path, key, new_content, pid,
  type, user, value`; actions `add, key_edit, remove, value_edit`.

## 0. Headline — the pipeline extracts far more hive content than it mines

Two structural drops, both grounded:

1. **The Zimmerman lane RUNS `RECmd`, `SBECmd`, `AmcacheParser`, `AppCompatCacheParser`
   over every extracted hive (with `.LOG1/.LOG2` for dirty-hive replay) — but the CAR
   `ROUTES` table consumes only RECmd.** `sbecmd.json` (ShellBags), `amcache.csv`,
   `appcompatcache.csv` have **no route** → their output is written to
   `processed/zimmerman/<host>/` and silently dropped. Compute is spent; evidence is binned.
2. **plaso's generic `winreg/winreg_default` plugin produced 1,505,072 of 1,512,651
   registry rows (99.5%)** — i.e. almost the entire registry reaches CAR untyped, as a
   `key_edit` whose `value`/`data`/`type` are **trapped in a `values` LIST** the marker set
   cannot index. **1,351,741** of the 1,506,720 `key_value` rows carry a non-empty `values`
   list. That is 1.35M rows of on-disk registry content present in the record but absent from
   the CAR columns.

Note on state: there is currently **no Zimmerman/RECmd output in the store** (the lane has
not been run on this image — `data_store/processed/zimmerman/` holds only `.gitkeep`, and no
`recmd_batch.json`/`sbecmd.json`/`amcache.csv` exists anywhere on disk). So on the evidence
as it sits, the registry object is fed by plaso **only** (`plaso_registry` +
`plaso_exec_winreg` + `plaso_shellitem` off the `.L2tWinreg` route). The RECmd
value/data/type flattening and dirty-hive replay are wired but presently fire on nothing.

## 1. Corpus facts measured this pass

**By plaso winreg plugin (`parser`) — this is the real "typed vs generic" split:**

| parser (plugin) | rows | typed? |
|---|---|---|
| `winreg/winreg_default` | **1,505,072** | NO — generic key snapshot, value/data/type in `values` list |
| `winreg/amcache` | 2,215 | typed (exec inventory) |
| `winreg/windows_services` | 1,796 | typed |
| `winreg/appcompatcache` | 1,463 | typed |
| `winreg/windows_task_cache` | 1,454 | typed |
| `winreg/userassist` | 153 | typed |
| `winreg/msie_zone` | 108 | typed |
| `winreg/bam` | 76 | typed |
| `winreg/bagmru` | 62 | typed (but message = raw object repr, see §4) |
| `winreg/windows_usb_devices` | 30 | typed |
| `winreg/windows_run` | 27 | typed |
| `winreg/windows_sam_users` | 27 | typed |
| `winreg/mrulistex_*` (4 variants) | 65 | typed |
| `winreg/mrulist_string` | 17 | typed |
| `winreg/windows_typed_urls` | 15 | typed |
| `winreg/winlogon` | 12 | typed |
| `winreg/explorer_mountpoints2` | 12 | typed |
| `winreg/windows_usbstor_devices` | 9 | typed |
| `winreg/windows_version` | 9 | typed |
| `winreg/networks` | 6 | typed (payload DROPPED, §4) |
| `winreg/windows_boot_execute` / `windows_shutdown` | 6 / 6 | typed |
| `winreg/explorer_programscache` | 4 | typed |
| `winreg/diagnosed_applications` | 4 | typed |
| `winreg/windows_timezone` | 3 | typed |

- **Transaction-log records: `0`.** No plaso record has a `.LOG1/.LOG2` `display_name` — plaso
  does **not** parse or replay transaction logs; every registry row is the *base* hive.
- **SECURITY hive parsed:** 273 rows under `HKLM\Security\Policy` (incl. `Policy\Secrets`, 45).
- **SAM hive parsed:** 249 rows under `HKLM\SAM\SAM\Domains` (incl. `Account\Users`, 62).
- **Keys of interest (all via `winreg_default` unless noted):** Services subtree 10,156;
  Session Manager 1,529; USB Enum 1,233; Amcache driver/app 705/635; Winlogon subtree 391
  (typed `winlogon` only 12); Uninstall 258; USBSTOR 256 (typed); IFEO 234; Shellbags `\Bags\`
  180; LSA `\Control\Lsa` 177; App Paths 157; BagMRU 116; SAM bin users 62; **LSA Secrets 45**;
  Run subtree 36 (typed `run` 27); NetworkList Profiles 12 (typed `networks`); KnownDLLs 3;
  MountedDevices present; ComputerName present.

## 2. Per-field provenance — disk registry (grounded)

`plaso_registry` promotes only `key/hive/hostname` (+`image_path` on service rows); `recmd`
promotes `data/hive/key/new_content/type/user/value`. "hive/key → native field" is the plaso
source unless the RECmd column is noted.

| field | hive/key → native field | action | mined? | conf & caveats |
|---|---|---|---|---|
| **key** | `key_path` (plaso) / `KeyPath` (recmd) | key_edit / value_edit | **YES** 100% | High. plaso normalises per-user root to `HKEY_CURRENT_USER`; some rows keep the raw `\REGISTRY\MACHINE\...` form (app-package `Registry.dat` hives). |
| **hive** | `display_name` (plaso) / `HiveType` (recmd) | key_edit / value_edit | **YES** | plaso fills the hive **FILE PATH** (`...\config\SYSTEM`), not the logical root CAR wants (`HKEY_LOCAL_MACHINE`); the root is `key_path`'s first segment, unused. recmd fills it correctly. Semantic mismatch (from lonewolf audit). |
| **hostname** | `image_hostname` | key_edit | **YES** 100% | High; lane-stamped (`DESKTOP-PM6C56D`). |
| **value** | `values[].name` (plaso, LIST) / `ValueName` (recmd) | — / value_edit | **plaso NO; recmd YES** | plaso: present on **1,351,741** key_value rows but trapped in the `values` list, unindexable → native-only. recmd flattens one row per value → canonical. **Biggest single drop.** |
| **data** | `values[].data` (plaso, LIST) / `ValueData*` (recmd) | — / value_edit | **plaso NO; recmd YES** | Same trap. Binary values render as `"(224 bytes)"` (size only) — the bytes themselves are not carried even in native. |
| **type** | `values[].data_type` (plaso, LIST) / `ValueType` (recmd) | — / value_edit | **plaso NO; recmd YES** | Same trap. Real types present: REG_SZ/BINARY/DWORD_LE/EXPAND_SZ/MULTI_SZ/NONE/UNKNOWN. |
| **new_content** | — (plaso) / `ValueData*` snapshot (recmd) | — / value_edit | **plaso n/a; recmd YES** | A plaso key snapshot has no before/after. recmd sets new_content = current data (snapshot convention). |
| **user** | `\Users\<name>\` in `display_name`/`HivePath` | key_edit / value_edit | **plaso NO; recmd YES** | GAP-1 (lonewolf): plaso leaves `user` null on all 1.5M rows though `jcloudy` sits in 28,371 per-user hive paths; its `hive_user_sid` SID-regex matches 0. recmd's `regex(HivePath, Users/<name>)` is the proven fix. System hives → null (correct). |
| **image_path** | `image_path` (service rows only) | key_edit | **partial/misleading** | Present on the 1,796 `service` rows = the *configured* service binary, **not the writer**. Null on the other ~1.51M. Field-name collision. |
| **pid** | — | — | **NO (honest)** | A dead hive never records the writing process. 100% null correct. |
| **fqdn** | — | — | **NO (honest)** | Only bare NetBIOS `image_hostname`; no domain in the record. |

## 3. Pipeline routing reality — EZ-tool hive parsers produced then dropped

`pipeline.py` `ROUTES` (first-match-wins, filename-pattern → map keys). Registry-relevant:

| Zimmerman output (produced by zimmerman.py) | route pattern present? | consumed by | verdict |
|---|---|---|---|
| `recmd_batch.json` (RECmd, all hives, Kroll batch) | `_RECmd_Batch_`, `recmd_batch.json` | `recmd_batch` → registry/value_edit | **mined** (but no input in store yet) |
| `sbecmd.json` (SBECmd — UsrClass/NTUSER **ShellBags**) | **none** | — | **DROPPED.** Registry-hive folder-access evidence unmined. |
| `amcache.csv` (AmcacheParser — Amcache.hve) | **none** | — | **DROPPED.** SHA1/ProgramId/driver decode unmined; Amcache reaches CAR only via plaso. |
| `appcompatcache.csv` (AppCompatCacheParser — SYSTEM) | **none** | — | **DROPPED.** Shimcache reaches CAR only via plaso. |
| `rbcmd.csv`, `mftecmd.json`, `lecmd` | none / `[]` | — | dropped/raw (not registry). |

`_is_raw_l2t()` only catches unwrapped plaso `json_line` (top-level `data_type`, no `Record`)
— the EZ CSV/JSON shapes are not raw-l2t, so they are never picked up by the fallback either.
(SRUM's `srum.jsonl` IS raw-l2t and is consumed via `.L2tEsedb`→`l2t_srum` — the one EZ-lane
product that does reach CAR by the fallback.)

## 4. Unmined hive-content sweep (be exhaustive)

### 4a. The `values` LIST flattening — 1.35M rows of value/data/type (SEVERE, from lonewolf, re-quantified)
Every `winreg_default` key carries its values as a list; the marker set can't index a list, so
`value`/`data`/`type` never become columns. Confirmed rich payloads sitting in the list:
- `HKLM\System\MountedDevices` — `\DosDevices\C:`, `\??\Volume{GUID}` → REG_BINARY drive/volume
  mappings (device & USB correlation, disk signatures).
- `...\Session Manager\KnownDLLs` — REG_SZ DLL list (search-order-hijack surface).
- `...\ComputerName\ComputerName` — `DESKTOP-PM6C56D` (+ `mnmsrvc` default).
- `...\Uninstall\*`, `...\App Paths\*` — installed-software inventory.
- `...\Services\*` subkeys — `EventMessageFile`, `ProviderGuid`, `ImagePath`, `ServiceDll`.
- `Amcache.hve \Root\InventoryApplicationFile\*` — `FileId` (SHA1), `LowerCaseLongPath`,
  `LinkDate`, `BinFileVersion`, `BinaryType` (all in the values list — see §4d).
- Office registration product names, etc.
RECmd flattens all of this — but only for keys in the curated Kroll batch, and only if that
lane runs. Full-hive plaso value/data/type is unmined.

### 4b. Transaction logs (.LOG1/.LOG2 — unflushed writes)
- **plaso emits 0 rows from any `.LOG` file** → the base-hive rows are stale w.r.t. any writes
  still sitting in the transaction log (the most recent registry activity — often the most
  IR-relevant). The Zimmerman filter deliberately co-extracts `.LOG1/.LOG2` for **EZ dirty-hive
  replay**, so replayed values would reach CAR **only** through RECmd's flattened rows (a
  curated subset), never through the 1.5M plaso rows. The log entries themselves (dirty pages
  with their own sequence numbers / write times) are surfaced by no map.

### 4c. Hive slack / deleted keys & values (registry carving)
- `recmd.py` `recmd_is_value_record` requires `Deleted is not True`; `Deleted: true` records
  (recovered from unallocated) fall to `default: None` → **RAW, unmined**. plaso's winreg parser
  does not carve unallocated at all. So recovered/deleted registry content (a classic
  anti-forensics/persistence-cleanup signal) reaches **no CAR field** from either dead-hive map.
  The map's rationale (deletion *time* is unknowable → refuse to assert a time) is sound for the
  `remove` action, but the deleted key's **content** is still evidence and could be surfaced as
  a timeless/`add`-style record with a "recovered, time-unknown" caveat.

### 4d. Hives / keys with NO typed handler (all → `winreg_default`, value/data trapped)
- **LSA Secrets** — `HKLM\Security\Policy\Secrets\*` (45 rows: `DefaultPassword`, service-account
  creds, DPAPI machine keys, `NL$KM`). Present as key rows, but **encrypted** and the pipeline has
  **no SYSKEY/bootkey decryption** (no secretsdump-equivalent) → content unusable.
- **Cached domain creds** — `HKLM\Security\Cache` (3 rows) — same: encrypted, undecoded.
- **SAM F/V binary** — `HKLM\SAM\SAM\Domains\Account\Users\*` (62 rows): per-RID `F`/`V` blobs
  (password-hash presence, group membership, account flags, logon count/timestamps) undecoded.
  Only plaso's 27 typed `sam_users` rows surface `username/account_rid/login_count/fullname`. **No
  hash extraction** (no samdump/bootkey step).
- **IFEO** — `...\Image File Execution Options\*` (234 rows). Persistence/priv-esc (T1546.012).
  The `Debugger`/`GlobalFlag`/`VerifierDlls` payload rides in the values list; no handler flags a
  hijack, and value/data are dropped from CAR columns.
- **MountedDevices / KnownDLLs / ComputerName / Uninstall / App Paths / BootExecute** — see §4a;
  all generic, content in the values list.
- **Winlogon (partial)** — typed `winreg/winlogon` fired only 12×; the wider `\Winlogon` subtree
  (391 rows: `Notify`, `Shell`, `Userinit`, `Taskman`, per-user) falls to `winreg_default`, so
  Shell/Userinit/Notify **persistence** values are only in the untyped list.
- **Services (partial)** — typed `windows_services` = 1,796 (the service root config); the wider
  `\Services\` subtree (10,156 rows: `Parameters`, `Security`, per-service `ImagePath`/`ServiceDll`
  in subkeys) is `winreg_default`.

### 4e. `network` typed payload dropped (from lonewolf, re-confirmed)
The 6 `windows:registry:network` rows carry `ssid` ("Net 2.4"), `default_gateway_mac_address`
(`5c:8f:e0:2a:1c:68`), `dns_suffix`, `description`, `connection_type` **natively** — **none** are
on `plaso_registry`'s `native_extract` allowlist, so only `key/hive/hostname` survive; the wireless
profile + gateway MAC (T1016, network-geo/attribution) are lost.

### 4f. ShellBags (UsrClass) — best decoder unrouted
- plaso `windows:registry:bagmru` (62 rows) message is a raw Python object repr
  (`<...AttributeContainerIdentifier object at 0x...>`) — useless. Shell items only surface if
  plaso also emits `windows:shell_item:file_entry` (→ `plaso_shellitem` → **file**/access), and
  even then as `file`, not as a registry view.
- **SBECmd (`sbecmd.json`) — the tool that cleanly decodes UsrClass BagMRU into absolute folder
  paths, MRU slot positions, first/last-interacted times — is produced and UNROUTED (§3).**

## 5. Cross-object flags (typed keys that ALSO belong elsewhere)
Registry rows that are simultaneously evidence for another CAR object (already partly handled by
`plaso_exec_winreg`/`plaso_shellitem`, flagged so they aren't double-counted as "registry gaps"):
- `run`, `winlogon` `command`/`application` → **process/file** (persistence T1547.001/.004).
- **IFEO** `Debugger` → **process/file** (T1546.012) — currently neither registry-mined nor exec-mined.
- `service` `image_path`/`service_dll` → **process/module/service** (T1543.003).
- `usb`, `usbstor` → **device / host** (removable media, T1091); `MountedDevices` correlates volume↔drive↔signature.
- `mrulistex`, `mrulist`, `bagmru`/shellbags, `explorer_programscache` → **file** (access, T1083).
- `typedurls`, `msie_zone` → **http / url** (browsing).
- `mount_points2`, `network_drive` → **flow** (mapped shares, T1021); `networks` → host interface + flow.
- `sam_users` → **user**; `amcache`/`appcompatcache`/`userassist`/`bam` → **process/file** (execution — already dual-viewed by `plaso_exec_winreg`).

## 6. Ranked UNMINED opportunities (highest value first)
1. **Route the EZ-tool hive parsers that the lane already runs** — add `sbecmd.json` (ShellBags),
   `amcache.csv`, `appcompatcache.csv` to `pipeline.py` `ROUTES` + write their maps. Zero new
   extraction cost; recovers cleanly-decoded registry evidence currently binned. (SBECmd is the
   only good shellbag decoder; AmcacheParser's SHA1 is in the correct `0000`+40hex form.)
2. **Flatten plaso's `values` LIST → per-value `value_edit` rows** (or promote value/data/type).
   1,351,741 rows of on-disk value/data/type presently native-only; RECmd already proves the shape.
   Engine change (list explosion), largest payoff.
3. **Surface deleted/carved keys & values** (RECmd `Deleted:true`, §4c) as timeless "recovered,
   time-unknown" registry records instead of dropping to raw — persistence-cleanup evidence.
4. **Transaction-log unflushed writes** — either route RECmd's replayed output (so the most recent
   writes reach CAR) or note in the contract that plaso rows are pre-replay/stale (§4b).
5. **IFEO + full Winlogon/Services subtree persistence** — a typed handler (or a value-flatten) so
   `Debugger`/`Shell`/`Userinit`/`ServiceDll` become findable, not buried in `winreg_default` lists.
6. **`network` payload** — add `ssid`/`default_gateway_mac_address`/`dns_suffix`/`description`/
   `connection_type` to the `native_extract` allowlist (6 rows, high per-row value).
7. **LSA Secrets / SAM hashes** — genuine capability gap: no SYSKEY/bootkey decryption in the
   pipeline. The keys are present but encrypted; a secretsdump/samdump step (SECURITY+SYSTEM,
   SAM+SYSTEM) would be a new tool, not a map fix. Flag, don't pretend it's a one-liner.

## 7. Honest no-sources / correct nulls (do NOT "fix")
- **`pid`** — the writing process is never recorded in a dead hive. Null on 100% is correct.
- **`image_path` of the writer** — never recorded; the only `image_path` present is the *configured*
  service binary. Writer-image is a genuine no-source for dead hives.
- **`fqdn`** — record carries only bare NetBIOS.
- **`new_content` (plaso)** — a key snapshot has no after-state.
- **`add`/`remove`/`value_edit` from plaso** — a static snapshot can only assert `key_edit`; creation
  vs edit is indistinguishable, and a truly deleted key isn't in the base hive. Live-writer actions
  (Sysmon 12/13/14, Security 4657) remain the only legitimate source of `add`/`remove`/`value_edit`
  with a real time + writer `pid`/`user` — and those arrive via evtx, not the disk hive.
- **LSA/SAM secret *values*** — recoverable in principle, but only with a decryption step the
  pipeline doesn't have; present-but-encrypted is the truth of the evidence today.
