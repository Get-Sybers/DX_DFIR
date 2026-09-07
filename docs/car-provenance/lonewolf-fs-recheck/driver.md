# MITRE CAR `driver` — FILESYSTEM / disk provenance pass

**Object:** `driver` — "software that runs in the operating system kernel."
**Canonical fields (11):** `base_address`, `fqdn`, `hostname`, `image_path`, `md5_hash`, `module_name`, `pid`, `sha1_hash`, `sha256_hash`, `signature_valid`, `signer`
**Actions (2):** `load`, `unload`

**Scope of THIS pass.** The prior catalogue (`docs/car-provenance/driver.md`, LS24) proved the driver object is produced by only two mapped sources — **Sysmon EID 6** (identity + hashes + signature) and **memory `windows.modules`** (base_address + path + name) — and flagged disk `.sys` hashes as an *unwired enrichment*. This pass audits the **FILESYSTEM/disk** artefacts exhaustively, grounded in the real LoneWolf Win10 plaso timeline, to enumerate what a *dead disk alone* can put on the driver object.

**Grounded in:** `data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (LoneWolf `LoneWolf.E01`, 4,169,774 plaso events, incl. VSS shadow copies VSS1/VSS2). Engine maps: `piiat_mitrecar/mappings/plaso_registry.py`, `plaso_fs_extra.py`, `plaso_exec.py`, `sysmon.py`; sources `sources/plaso_*.yaml`.

> **Headline.** No filesystem source emits a `driver` object today — the ONLY producer of `object: driver` in the whole engine is `sysmon.py` (`sysmon_driver_load`, EID 6). Every disk `.sys` artefact that exists in the real image is currently routed to **`registry`**, **`file`** or a dropped **`process`** row, with the driver identity buried in `_native`. Yet the disk carries, for **352 unique kernel/FS drivers on this one image**, enough to fill **6 of 11** driver fields — `image_path, module_name, sha1_hash, sha256_hash, signer, signature_valid` — with *zero* Sysmon or memory evidence. This is the single largest unmined driver supply in the pipeline.

---

## Filesystem source universe (what a disk can produce for a `driver` row)

| Src | Artefact (disk) | Plaso parser → data_type | Real-data volume (LoneWolf) | Currently routed to | Driver object today |
|---|---|---|---|---|---|
| **D1** | **Amcache `\Root\InventoryDriverBinary\<path.sys>`** (`Amcache.hve`) | `winreg/amcache` → `windows:registry:key_value` | **702 subkeys → 352 UNIQUE `.sys`**; all carry DriverId(SHA1)+DriverSigned=1 | `registry`/key_edit (values in `_native`) **+** a null `process`/create (dropped) | **NO** |
| **D2** | **SYSTEM hive `…\Services\<name>` with `Type`=1 (kernel) / 2 (filesystem) driver** (`SYSTEM` hive) | `winreg/windows_services` → `windows:registry:service` | **1048 driver-type rows → 361 UNIQUE** (937 Type-1, 111 Type-2, dedup incl. ControlSet+VSS) | `registry`/key_edit (`image_path`/`service_type`/`start_type`/`name` in `_native`) | **NO** |
| **D3** | **PE `.sys` on disk** (`\System32\drivers`, `\WinSxS`, `\DriverStore`) | `pe` → `pe_coff:file` | **4643 `.sys` rows**; ALL have `sha256_hash`+`imphash`+`pe_type="Driver (SYS)"`; 1172 have `export_dll_name` | `file`/create (timestamp-less), `pe_type` kept native but **unused as a router** | **NO** |
| **D4** | **Amcache `InventoryApplicationFile` for app-bundled `.sys`** (Defender/NVIDIA installers) | `winreg/amcache` → `windows:registry:amcache` | ~36 `.sys` rows; `file_identifier`=SHA1, `company_name`, `file_version` | `file`/create (+ Link-Time entity) — but reads `Record.sha1` (null here) so SHA1 **lost** | **NO** |
| **D5** | **`$MFT` / filestat of `\drivers\*.sys`** | `filestat` → `fs:stat` | **4836 rows** (Creation/Content-Mod/Last-Access per `.sys`) | `file` (fs_stat lane) | **NO** (path+size+times only; no hash/signer) |
| **D6** | **Prefetch `mapped_files` naming `.sys`** (`DRVINST.EXE`→WUDFRD.SYS/TEEDRIVERW8X64.SYS; SMSS/CSRSS→WIN32K*.SYS) | `prefetch` → `windows:prefetch:execution` | present, sparse | `process`/create (`.sys` in `_native.mapped_files`) | **NO** (and correctly so — not a load) |
| **D7** | **Appcompat / shimcache of `.sys`** | `winreg/appcompatcache` → `windows:registry:appcompatcache` | **0 `.sys`** (1463 rows, all `.exe`) | `process`/create | **NO — empty on disk** |
| **D8** | **Catalog DB `.cat` (CatRoot) → true Authenticode `signature_valid`** | *no plaso parser* | — | — | **NO — no parser exists** |

All D1–D6 rows in this image are duplicated ×2–3 by VSS shadow copies (`VSS1:`/`VSS2:` display-name prefixes) and by `ControlSet001`/`ControlSet002` for Services — dedup on `.sys` path/basename is required downstream.

---

## Per-field provenance (FILESYSTEM sources)

Legend — **mined?**: does any FILESYSTEM source write this column to a **`driver`** row today. (All are **NO** — no disk source emits a driver object at all.)

| field | fs artefact → native field | action | mined? | confidence & caveats |
|---|---|---|---|---|
| **base_address** | **none** (runtime-only) | load | **NO — honest null** | High. A load address is a *runtime* fact (where the kernel mapped the image); the disk never records it. Memory `windows.modules` is the sole source (prior pass). Disk `driver` rows leave it null — correct. |
| **fqdn** | D1/D2/D3 → plaso `image_hostname` = `DESKTOP-PM6C56D` (NetBIOS, no dot) | load | **NO** | Med. The image identity is a bare NetBIOS name (`DESKTOP-PM6C56D`), not dotted → no honest FQDN. `fqdn` stays null from disk (never fake a dot). Same rule as the Sysmon `_FQDN` guard. |
| **hostname** | **D1/D2/D3/D5** → `image_hostname` (`DESKTOP-PM6C56D`), lane-stamped on every plaso row | load | **NO** (available, unrouted) | High. Every disk row already carries the host; a disk-driver row would stamp `hostname` trivially. Free the moment a driver object is emitted. |
| **image_path** | **D1** key_path tail `\Root\InventoryDriverBinary\c:/windows/system32/drivers/1394ohci.sys`; **D2** Service `image_path` `\SystemRoot\System32\drivers\iagpio.sys`; **D3** PE `display_name` `\Windows\System32\drivers\wfplwfs.sys`; D5 filestat path | load | **NO** | High. FOUR independent disk sources give the driver's own `.sys` full path. D2 also surfaces `\…\DriverStore\FileRepository\…\CompositeBus.sys`. Caveat: a handful of built-in kernel drivers have Service `image_path=None` (e.g. `Beep`) — honest null. |
| **md5_hash** | **none** | load | **NO — honest null** | High. Plaso `pe` emits `sha256` only (`md5_hash` null in data); amcache stores only SHA1 (DriverId). No disk artefact carries the driver's MD5 → Sysmon-only field. |
| **module_name** | **D1** `DriverName`=`1394ohci.sys` / `Service`=`1394ohci`; **D2** Service key `name`=`iagpio` (+`Service`); **D3** PE `export_dll_name` (internal name) / basename; D5 basename | load | **NO** | High. Multiple disk sources. D1 `Service` and D2 `name` are the SCM service/module name; PE `export_dll_name` is the binary's internal name — both are legitimate `module_name` fills (basename of `image_path` is the fallback). |
| **pid** | **none** | load / unload | **NO — honest no-source** | High. Kernel loads drivers, not a user process; no disk artefact records an initiating PID (matches Sysmon EID 6 and memory `windows.modules`, both PID-less). Structural null. |
| **sha1_hash** | **D1** `DriverId`=`0000cabc55b4…93f1` → strip 4-char `0000` prefix ⇒ SHA1; **D4** `file_identifier`=`00005a53…` (same encoding) | load | **NO** | High. **352 drivers carry a SHA1 on disk via amcache DriverId** — a hash with no Sysmon/memory needed. CAVEAT: current amcache map reads `Record.sha1` (NULL in this plaso build — the hash lives in `DriverId`/`file_identifier`), so the SHA1 is *lost even on the existing file object*. The `0000` prefix must be stripped. |
| **sha256_hash** | **D3** PE `sha256_hash` (the `pe` parser hashes every `.sys`; e.g. `wfplwfs.sys`=`bad5292a…9802`) | load | **NO** | High. **4643 `.sys` PE rows, all with sha256.** This is the disk's SHA-256 supply for drivers (Sysmon supplies it only where EID 6 fired). Join to D1/D2 on `.sys` basename to hydrate. `md5`/`signature` null from the PE parser. |
| **signature_valid** | **D1** `DriverSigned`=`1` (⇒ True) — 702/702 signed in this image | load | **NO** (proxy only) | Med. `DriverSigned=1` is amcache's *recorded* signed-state (catalog or embedded) at inventory time, **not** a fresh Authenticode verification like Sysmon `SignatureStatus=Valid`. Map to `True` only on `=1`, caveat native; never assert `False`. TRUE signature verification (**D8**, `.cat` CatRoot) has **no plaso parser** — real `signature_valid` from disk is unavailable. |
| **signer** | **D1** `DriverCompany`=`Microsoft Corporation` / `Intel Corporation` / `NVIDIA Corporation` (+`Product`); D4 `company_name` | load | **NO** (proxy) | Med. `DriverCompany` is the PE CompanyName / INF provider — a signer *proxy*, not the Authenticode signer subject CN that Sysmon's `Signature` gives. Reasonable fill with a caveat; distinct from the true signer. Distribution: Microsoft 584, Intel 26, Mellanox/Avago/NVIDIA/LSI/AMD/QLogic the rest. |

**Disk-only coverage:** 6/11 fields fillable from a dead disk — `image_path, module_name, sha1_hash, sha256_hash` (strong) + `signer, signature_valid` (proxy, caveated). `hostname`/`fqdn` are free host-identity. `base_address, pid, md5_hash` and **action `unload`** have **no disk source**.

---

## Per-action coverage (disk)

### `load`
The three primary disk sources are **complementary** and join on the `.sys` path/basename — together they out-cover either Sysmon or memory alone for identity+integrity (they lack only the runtime `base_address`):

- **D1 amcache InventoryDriverBinary** → `image_path, module_name, sha1_hash, signer(proxy), signature_valid(proxy)` + kernel-mode flag + version/compile-stamp (native). *The richest single disk source — 352 drivers.*
- **D2 SYSTEM Services (Type 1/2)** → `image_path, module_name` + the **load configuration itself**: `start_type` (0 boot / 1 system / 2 auto / 3 demand) and `service_type` (1 kernel / 2 filesystem). This is the persisted *instruction that the driver is to be loaded* — the closest a disk gets to a load event.
- **D3 PE `.sys` "Driver (SYS)"** → `sha256_hash` (+ imphash, export name). *The only disk SHA-256.*

**Action semantics.** None of these is a timestamped load *event* — the row stamps are key-write / PE compile-link / file-MFT times, i.e. *presence/recorded* times, never the moment the kernel mapped the driver. So the honest treatment mirrors the pipeline's existing amcache/appcompatcache convention (`native.execution_inferred=True`, `native.time_meaning=…`): action `load` under a **presence-implies-installed/loaded inference**, with the time labelled for what it is. A Services `Start`=0/1/2 (boot/system/auto) is stronger load evidence than `Start`=3 (demand).

### `unload`
**ZERO disk source** — same structural dead-end as the prior pass. A disk is a snapshot; it cannot witness an unload. `.sys` presence + Services registration prove installation/load-intent, never removal. Honest no-source (not merely unmapped).

---

## Cross-source join (the enrichment this pass unlocks)

All disk sources key on the driver's `.sys` **path/basename** (and D1/D3 also share **SHA1↔SHA256** once both are on one object). A single reconciled disk driver — e.g. `1394ohci.sys` — assembles:

- D2 Services → `image_path \SystemRoot\System32\drivers\1394ohci.sys`, `module_name 1394ohci`, `start_type 3`, `service_type 1` (kernel)
- D1 amcache → `sha1 cabc55b4b36a990e0a1f770aa82bf7727cd193f1`, `signer Microsoft Corporation`, `signature_valid True`, `DriverIsKernelMode 1`, `DriverVersion 10.0.16299.15`
- D3 PE → `sha256 …`, `imphash …`, `export_dll_name …`

`crosssource.py` already treats `driver ∈ _HASHED ∩ _IMAGED`, so once disk driver rows exist they converge with each other **and** with Sysmon/memory driver rows on hash or basename — the disk fills exactly the gaps Sysmon-less / memory-less evidence leaves (the prior pass's "enrichment join" recommendation, now with a concrete disk supply on a real image).

---

## Ranked UNMINED opportunities

1. **Amcache `InventoryDriverBinary` → a driver object from a dead disk (HIGH — biggest win).** `winreg/amcache` `key_value` rows under `\Root\InventoryDriverBinary\<path.sys>` give **352 unique drivers** with `image_path` (key tail), `module_name` (`DriverName`/`Service`), `sha1_hash` (`DriverId`, strip `0000`), `signer` (`DriverCompany`, proxy), `signature_valid` (`DriverSigned=1`, proxy), plus kernel-mode flag/version natively. Today these land only on `registry`/key_edit with everything buried in `_native.values`. A dedicated variant emitting `object: driver, action: load` (presence-inferred) is the single highest-value addition. **Bonus bug:** the *existing* amcache→file map reads `Record.sha1`, which is NULL in this plaso build — the SHA1 lives in `DriverId`/`file_identifier` (0000-prefixed); this hash is currently dropped even on the file object.

2. **SYSTEM `Services` Type=1/2 → the driver object from the install record (HIGH).** `winreg/windows_services` (`service_type` ∈ {1,2}) — **361 unique** — is the authoritative on-disk record that a kernel/filesystem driver is *installed to load*, carrying `image_path` (incl. DriverStore paths), `module_name` (`name`/`Service`) and the **load-order config** (`start_type`, `service_type`) that no other source has. Currently → `registry`/key_edit only. A driver-object emit (or a driver↔registry link on `service_type`∈{1,2}) recovers it. Note: this is a *different* source from the prior pass's 7045/20003 (those are event-log service installs → `service`); this is the dead-hive Services key.

3. **PE `pe_coff:file` where `pe_type="Driver (SYS)"` → sha256 for the driver object (MEDIUM-HIGH).** The `pe` parser already hashes **4643 `.sys`** with `sha256_hash`+`imphash`+`export_dll_name`, and already tags them `pe_type="Driver (SYS)"` — a ready-made router that the current map keeps *native but unused*. Either dual-emit a `driver` row from the "Driver (SYS)" PE, or (cheaper) let a `driver↔file` cross-source join on `.sys` basename hydrate `sha256` onto the driver object. This is the ONLY disk source of the driver SHA-256.

4. **amcache `InventoryApplicationFile` `.sys` (D4) — secondary hash source (LOW-MEDIUM).** ~36 app-bundled `.sys` (Defender `wdboot.sys`/`wdfilter.sys`, NVIDIA installer `.sys`) with `file_identifier`(SHA1)+`company_name`+`file_version`. Overlaps D1/D3; useful mainly for third-party drivers outside `\System32\drivers`. Same `file_identifier` SHA1-extraction fix applies.

5. **True Authenticode `signature_valid` from CatRoot `.cat` (LOW — needs a new parser).** D1's `DriverSigned`/`DriverCompany` are *proxies*. A real signature verdict + signer CN would require parsing `\Windows\System32\CatRoot\…\*.cat` catalogs (or Authenticode over each `.sys`) — **no plaso/EZ parser exists in the pipeline**, and plaso's `pe` parser leaves `signature`/`signature_status` null on every `.sys`. Genuine disk `signature_valid` is therefore currently unattainable; the amcache proxy is the honest best.

## Honest no-sources (disk)

- **`base_address`** — runtime-only; a disk never records where the kernel mapped an image. Memory-only (prior pass).
- **`pid`** — kernel-loaded; no initiating user process, and no disk artefact records one. Structural null on every source.
- **`md5_hash`** — plaso `pe` emits sha256 only; amcache stores only SHA1. No disk MD5. Sysmon-only.
- **action `unload`** — a disk snapshot cannot witness a removal; `.sys` presence + Services registration prove install/load-intent, never unload. Structural dead-end.
- **`appcompatcache`/shimcache of `.sys` (D7)** — exists but empty here: 0 of 1463 shimcache rows name a `.sys` (shimcache records executed `.exe`). Not a driver source on this image.

**Bottom line.** The disk holds a large, honest, currently-unmined driver supply: **352 drivers** identifiable from a dead LoneWolf image with `image_path + module_name + sha1 + sha256 + signer/signature (proxy)` — 6/11 fields, no live telemetry required — split today across `registry`, `file` and dropped `process` rows. The three ranked additions (amcache InventoryDriverBinary, SYSTEM Services Type 1/2, PE "Driver (SYS)") would let the pipeline reconstruct the driver object from disk alone and converge it (via existing `crosssource.py` hash/basename joins) with any Sysmon/memory driver rows. `base_address`, `pid`, `md5_hash` and `unload` remain genuine disk no-sources; true Authenticode `signature_valid` awaits a `.cat` catalog parser that does not yet exist.
