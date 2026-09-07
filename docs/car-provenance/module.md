# Property-Provenance Catalogue — MITRE CAR `module`

**Object:** `module` — "executable (and potentially non-executable) content, loaded as a contiguous region of memory into the address space of a process. Each process has the main image plus shared libraries (DLLs in Windows) and their dependencies."
**Actions:** `load`, `unload`
**Fields (12):** `base_address, fqdn, hostname, image_path, md5_hash, module_name, module_path, pid, sha1_hash, sha256_hash, signature_valid, signer, tid`

Grounding read:
- Semantics: `third_party/piiat-mitrecar/third_party/car/data_model/module.yaml`; `third_party/piiat-mitrecar/third_party/car/OSSEM-CDM/schemas/entities/module.yml` (fields: name, path, is_signed, signature, signature_status — no hashes, no base_address, no tid in the CDM either); `car_data_model.json` (object list).
- Engine maps: `third_party/piiat-mitrecar/piiat_mitrecar/mappings/sysmon.py` (EID 7), `.../mappings/evtx_more.py` (WMI 5857); sources `.../sources/evtx_sysmon.yaml`, `.../sources/evtx_more.yaml`, `.../sources/memory.yaml`.
- Memory maps (PIIAT-Mem, finished-CAR passthrough): `third_party/piiat-mem/piiat_mem/mappings.py`, plugin `third_party/piiat-mem/plugins/windows/piiat/modules.py`, enrichment `third_party/piiat-mem/piiat_mem/enrich.py`.
- Evidence: `data_store/processed/windows_logs/unspecified_host/log_EvtxECmd_Output.json`; `data_store/processed/volatility/memdump.mem/car.db`.

---

## 1. Currently-mapped source universe (module → CAR)

Three sources emit `module` events today. **All three emit only `action: load`. Nothing emits `unload`.**

| Source (sensor) | EID / plugin | → object/action | Map file | module fields it supplies |
|---|---|---|---|---|
| **Sysmon** `Microsoft-Windows-Sysmon/Operational` | **EID 7 ImageLoad** | module/load | `sysmon.py:389` (`sysmon_module_load`, EID==7) | module_path, module_name, image_path, pid, md5_hash, sha1_hash, sha256_hash, signer, signature_valid, hostname, fqdn — **11 of 12** (no base_address, no tid) |
| **WMI-Activity** `Microsoft-Windows-WMI-Activity/Operational` | **EID 5857** (provider DLL loaded) | module/load | `evtx_more.py:120` (`em_is_wmi_5857`) | module_path, module_name, image_path, pid, hostname, fqdn — **6 of 12** |
| **Memory / Volatility3** (PIIAT-Mem) | `windows.piiat.modules` (PEB load-order walk; == `windows.dlllist`) | module/load | `piiat-mem mappings.py:223` + `:275`; plugin `modules.py` | module_path(Path), module_name(Name), **base_address(Base)**, pid, + image_path/hostname/fqdn by enrichment — **7 of 12** |

The Sysmon EID 7 map is the only one the upstream `module.yaml coverage_map` records (as sensor `sysmon_13`). WMI-5857 and memory are wired in this repo's maps but not reflected in that upstream coverage stub.

**Live evidence caveat:** the current processed store contains **zero** module rows. The EvtxECmd export has only Sysmon EID 1 (45) and EID 5 (39) — no EID 7 — and the `memdump.mem/car.db` `module` table has 0 rows (the `windows.piiat.modules` plugin was not run in that capture; only pslist/processes/registry/sessions/mftscan/banners were). The `module` table schema in `car.db` does carry all 12 canonical columns + `base_address` + `tid`, so the pipe is complete; it just has no populated sample here.

---

## 2. Per-field provenance (EVERY field × EVERY source)

Native-field notation: `source → NativeField`. "Mapped?" = does the shipping engine assert this canonical field from that source today.

### base_address
| sources (source → native field) | action | currently mapped? | confidence & caveats |
|---|---|---|---|
| Memory `windows.piiat.modules`/`windows.dlllist` → `Base` (`DllBase` of `_LDR_DATA_TABLE_ENTRY`) | load | **YES** — piiat-mem `mappings.py:228,280` (`base_address: "Base"`) | **High.** Memory is the *only* source that has a base address — it is a runtime virtual-address concept. Point-in-time snapshot of currently-loaded state. |
| Sysmon EID 7 | load | NO | **No-source.** ImageLoad event carries no load address. |
| WMI 5857 / Plaso pe / amcache / prefetch | load | NO | **No-source.** None are runtime-memory views; none carry a VA. |

> `base_address` is a **memory-exclusive** field. Same for the parallel `driver` object (Volatility `windows.modules` → driver base).

### fqdn
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `Computer` (claimed only if it contains a dot) | load | **YES** — `sysmon.py:248` via `_FQDN` (`EVTX_FQDN`) | **High**, but null when `Computer` is a bare NetBIOS name (honest null, never faked). |
| WMI 5857 → `Computer` | load | **YES** — `evtx_more.py:129` (`_FQDN`) | High, same dot-guard caveat. |
| Memory `windows.piiat.modules` (inherited) | load | **YES (derived)** — `enrich.py:72` `_INHERIT` copies `fqdn` from the owning process | **Medium.** Present only if the owning process event itself carries fqdn (from `windows.info`); memory images often lack a real FQDN → null. |

### hostname
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `Computer` (first DNS label) | load | **YES** — `sysmon.py:248` (`_HOSTNAME`) | **High.** Always derivable from `Computer`. |
| WMI 5857 → `Computer` | load | **YES** — `evtx_more.py:129` (`_HOST`) | High. |
| Memory `windows.piiat.modules` (inherited) | load | **YES (derived)** — `enrich.py` `_INHERIT` | **Medium.** Inherited from owning process (from `windows.info` computer name); null if unavailable. |

### image_path  *(CAR: "the file system location of the **process** image" — i.e. the OWNING process, not the DLL)*
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `Image` (the loading process) | load | **YES** — `sysmon.py:396` (`image_path: payload("Image")`) | **High.** Directly the loader process image. Correct CAR semantics. |
| WMI 5857 → `HostProcess` | load | **YES** — `evtx_more.py:127` | **High.** `HostProcess` is the WMI host process image. |
| Memory `windows.piiat.modules` → owning `_EPROCESS` image (inherited) | load | **YES (derived)** — `enrich.py:340,380` `_inherit` fills `image_path` from the owner joined by `OwnerOffset` (definitive) or PID (heuristic) | **Medium-High.** Map deliberately leaves it null at extraction (`mappings.py` comment: module.image_path is the OWNING process's image; the DLL's own path is `module_path`), then enrichment fills it. Confidence tracks the join: definitive via OwnerOffset, heuristic via PID. |

### md5_hash
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `Hashes` (`MD5=…` substring) | load | **YES** — `sysmon.py:245` `_image_load_props` → `_hashes()` regex `MD5=` | **High**, *iff* Sysmon config has `<HashAlgorithms>MD5</HashAlgorithms>`. Sysmon default is SHA256 only → MD5 often absent (honest null). |
| Memory (dumpfiles + external hashing) | load | NO | **No-source (not implemented).** dlllist/PEB walk yields no hash; `windows.dumpfiles` + a hash step could produce it but PIIAT-Mem does not run it. |
| Plaso pe/pecoff | load | NO (pecoff emits **sha256 only**, and as a `file` object) | **No-source for md5.** See sha256 row. |
| amcache | load | NO (amcache emits **sha1 only**, as a `process` object) | **No-source for md5.** |
| WMI 5857 | load | NO | No-source. |

### module_name  *(basename on disk; internal lookup key)*
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `basename(ImageLoaded)` | load | **YES** — `sysmon.py:395` | **High.** |
| WMI 5857 → `basename(ProviderPath)` | load | **YES** — `evtx_more.py:126` | **High.** |
| Memory `windows.piiat.modules` → `Name` (`BaseDllName`) | load | **YES** — `mappings.py:228,280` | **High.** Native `BaseDllName` string; blank on unreadable entries → null. |

### module_path  *(full path to the DLL/EXE loaded into the process)*
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `ImageLoaded` | load | **YES** — `sysmon.py:394` | **High.** The definitive path of the loaded image. |
| WMI 5857 → `ProviderPath` (WMI provider DLL) | load | **YES** — `evtx_more.py:125` | **High**, but scope-limited: only WMI provider DLL loads, not general LoadLibrary. |
| Memory `windows.piiat.modules` → `Path` (`FullDllName`) | load | **YES** — `mappings.py:227,279` | **High**, occasionally blank/paged-out `FullDllName` → null. |

### pid  *(the process the module is loaded into)*
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `ProcessId` | load | **YES** — `sysmon.py:397` | **High.** |
| WMI 5857 → `ProcessID` | load | **YES** — `evtx_more.py:128` | **High.** |
| Memory `windows.piiat.modules` → `PID` (`UniqueProcessId` of the walked `_EPROCESS`) | load | **YES** — `mappings.py:228,280` | **High.** Also carries `OwnerOffset` (kernel pointer) for a definitive process link beyond the reusable PID. |

### sha1_hash
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `Hashes` (`SHA1=…`) | load | **YES** — `_hashes()` `sysmon.py:154` | **High** *iff* Sysmon config includes SHA1 (non-default) → often null. |
| amcache → `sha1` (program SHA-1) | load | NO — currently mapped to **process/create**, not module (`plaso_exec.py:286`) | **Potential enrich source.** amcache carries the file's SHA-1 but the DLL entries are folded into process rows, not exploded to module. Path-join enrichment could lift it. |
| Memory (dumpfiles+hash) / Plaso pe (sha256 only) / WMI 5857 | load | NO | No-source for sha1 (pe gives sha256, not sha1). |

### sha256_hash
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `Hashes` (`SHA256=…`) | load | **YES** — `_hashes()` `sysmon.py:155` | **High.** SHA256 is the Sysmon **default** algorithm → most reliable hash from EID 7. |
| Plaso pe/pecoff → `sha256_hash` (PE/COFF file hash) | load | NO — mapped to **file/create** entity, not module (`plaso_fs_extra.py:125`, source `plaso_pecoff.yaml` `data_model_coverage: file`) | **Potential enrich source.** Every on-disk PE (incl. DLLs) gets a sha256 as a `file` entity; joining by `module_path` could hydrate module.sha256. Also carries native `imphash`, `pe_type`, `compile_time`, `export_dll_name`. |
| Memory (dumpfiles+hash) | load | NO | No-source (not implemented). |
| WMI 5857 / amcache | load | NO | No-source (amcache = sha1). |

### signature_valid  *(bool: signature current & not revoked)*
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `SignatureStatus` (mapped `Valid → true`) | load | **YES** — `sysmon.py:163` `_SIGNATURE_VALID = map_value(SignatureStatus, {"Valid": True})` | **High, deliberately asymmetric.** Only the WinVerifyTrust `Valid` verdict asserts `true`; every other status (`Unavailable`, `Errors`, …) is left **null** (evidence of a problem, not proof of forgery) and kept native as `Signed`/`SignatureStatus`. Requires `CheckRevocation` in Sysmon config; absent → status `Unavailable` → null. |
| Memory / WMI 5857 / Plaso pe / amcache | load | NO | **No-source.** None run Authenticode verification. (A memory `dumpfiles` + external `WinVerifyTrust`/cert-parse could produce it but is not implemented.) |

### signer  *(organisation that signed the module)*
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| Sysmon EID 7 → `Signature` (the WHO) | load | **YES** — `sysmon.py:246` (`signer: payload("Signature")`) | **High** when `<Signature>`/hashing enabled; null otherwise. Note `Signature` = signer name; `SignatureStatus` = validity (kept separate). `Company`/`OriginalFileName` are **not** signer and stay native in Payload. |
| Memory / WMI 5857 / Plaso pe / amcache | load | NO | **No-source.** pe/pecoff extracts PE metadata but not the Authenticode signer cert subject. |

### tid  *(thread ID responsible for the load/unload)*
| sources | action | mapped? | confidence & caveats |
|---|---|---|---|
| — none — | load | **NO (honest no-source)** | **No artefact in this pipeline records the loading thread.** Sysmon EID 7 has no thread id; WMI 5857 has none; the memory PEB load-order walk (`_LDR_DATA_TABLE_ENTRY`) records no calling-thread. Only kernel ETW (`Microsoft-Windows-Kernel-Process` ImageLoad w/ thread context) would carry it, and that is not collected. The `car.db` `module` table has a `tid` column, but it is never populated. |

---

## 3. Action coverage

| action | mapped sources | notes |
|---|---|---|
| **load** | Sysmon EID 7, WMI 5857, Memory `windows.piiat.modules`/`dlllist` | All three sources emit only `load`. |
| **unload** | **NONE (honest no-source)** | No collected artefact emits a module-unload event. Sysmon has no unload EID; `FreeLibrary` is unlogged. Memory is a point-in-time snapshot of *currently-loaded* state (a load view, not an unload event). The upstream `coverage_map` also lists load only. |

---

## 4. Native fields available per source (reference — what's on the wire vs. what's mapped)

- **Sysmon EID 7 (ImageLoad):** `ImageLoaded`(→module_path), `Image`(→image_path), `ProcessId`(→pid), `ProcessGuid`(owner link), `Hashes`(MD5/SHA1/SHA256/**IMPHASH**), `Signed`, `Signature`(→signer), `SignatureStatus`(→signature_valid), `OriginalFileName`, `Company`, `Product`, `Description`, `FileVersion`, `User`, `Computer`(→hostname/fqdn), `UtcTime`, `RuleName`. **Kept native but NOT canonical:** IMPHASH, OriginalFileName, Company, Signed, raw SignatureStatus (`_KEEP` + Payload blob). No `base_address`, no thread id on the wire.
- **WMI-Activity 5857:** `ProviderPath`(→module_path), `ProviderName`(native), `HostProcess`(→image_path), `ProcessID`(→pid), `Code`(native), `Computer`. No hashes, signer, base_address, tid.
- **Memory `windows.piiat.modules`** (plugin `modules.py`): `OwnerOffset`(definitive owner link), `PID`(→pid), `ProcessName`(native), `Base`(→**base_address**), `Size`(native), `Name`(→module_name), `Path`(→module_path), `LoadTime`(→ts; Win≥6.1, zeroed for the EXE itself), `LoadCount`(native). No hash/signer/tid available from the PEB walk.

---

## 5. Coverage summary & UNMAPPED gaps (ranked)

**Coverage at a glance (12 fields × load):**

| field | Sysmon7 | WMI5857 | Memory | best today |
|---|:--:|:--:|:--:|---|
| base_address | – | – | ✅ | Memory only |
| fqdn | ✅ | ✅ | (inh) | High |
| hostname | ✅ | ✅ | (inh) | High |
| image_path | ✅ | ✅ | (inh) | High |
| md5_hash | ✅* | – | – | Sysmon7 (config-gated) |
| module_name | ✅ | ✅ | ✅ | High |
| module_path | ✅ | ✅ | ✅ | High |
| pid | ✅ | ✅ | ✅ | High |
| sha1_hash | ✅* | – | – | Sysmon7 (config-gated) |
| sha256_hash | ✅ | – | – | Sysmon7 (default algo) |
| signature_valid | ✅ | – | – | Sysmon7 only |
| signer | ✅ | – | – | Sysmon7 only |
| tid | – | – | – | **no-source** |

`✅* = present only if the Sysmon HashAlgorithms config enables that algorithm (default = SHA256).` `(inh) = filled by enrichment from the owning process, not native to the module row.`

**Well-covered:** identity fields (module_path/module_name/pid/image_path/hostname/fqdn) have 2–3 independent sources. Sysmon EID 7 is the single richest source (11/12). base_address is memory-exclusive and already mapped.

### UNMAPPED gaps — ranked

1. **Memory injection detection — `ldrmodules` / unlinked-module view (NOT IMPLEMENTED).** PIIAT-Mem walks only the PEB *load-order* list (`windows.piiat.modules` == `windows.dlllist`), so it sees only linked modules. There is **no `ldrmodules` plugin** cross-referencing the three PEB lists (load/init/mem order) to flag unlinked = injected/hidden DLLs. `malfind` exists but is a **trigger only** (timeline overlay, never stored as a module record — `piiat_mem/timeline.py`, `cli.py:71`). *Highest-value gap: injected-module detection is absent from the module object.* Would add nothing to the 12 canonical fields but a native `unlinked/injected` flag (no CAR home → native) plus base_address for hidden modules.

2. **Prefetch loaded-modules list (`mapped_files`) not exploded into module rows.** Plaso `windows:prefetch:execution` carries `mapped_files` — the DLL/file list the run touched — but it is kept **native on the process/create event** (`plaso_exec.py:231`), never decomposed into `module/load` rows. *High value, low cost:* each `mapped_files` entry → a `module/load` with `module_path`, `module_name`, and `pid`/`image_path` from the owning process event. Caveat: prefetch has no per-module load time, no base_address, no hash (path only), and mixes DLLs with data files.

3. **Hash hydration by path-join (sha256 from pe, sha1 from amcache).** Two on-disk sources carry file hashes today but attach them to the wrong object:
   - Plaso **pe/pecoff** → `sha256_hash` on a **file** entity (`plaso_pecoff.yaml`), + native `imphash`/`pe_type`/`compile_time`.
   - **amcache** → `sha1` on a **process** event (`plaso_exec.py:286`).
   A cross-source enrichment joining `module.module_path` to these `file`/entity rows would hydrate `sha256_hash`/`sha1_hash`/`md5_hash` for modules that Sysmon logged without hashing (or that only memory/prefetch saw). Not wired.

4. **Memory module hashing (`dumpfiles` + hash) — NOT IMPLEMENTED.** Would give md5/sha1/sha256 for a module seen only in memory (incl. injected ones from gap #1). PIIAT-Mem does not run `windows.dumpfiles` or hash dumped regions.

5. **Signer/signature_valid limited to Sysmon EID 7.** Any module seen only via WMI/memory/prefetch/pe has null signer & signature_valid. No Authenticode verification runs outside Sysmon's own WinVerifyTrust stamp. (EZ-Tools/PECmd/AmcacheParser are not wired as module sources — Plaso covers those artefact classes.)

6. **`tid` — genuine no-source.** No collected artefact records the loading thread ID; only uncollected kernel ETW would. Column exists, permanently null. Honest.

7. **`unload` action — genuine no-source.** No artefact emits module unloads; all three sources are load-only / snapshot. Honest.
