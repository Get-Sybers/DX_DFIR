# MITRE CAR `driver` — Property-Provenance Catalogue

**Object:** `driver` — "software that runs in the operating system kernel."
**Canonical fields (11):** `base_address`, `fqdn`, `hostname`, `image_path`, `md5_hash`, `module_name`, `pid`, `sha1_hash`, `sha256_hash`, `signature_valid`, `signer`
**Actions (2):** `load`, `unload`

Grounding: `third_party/piiat-mitrecar/third_party/car/data_model/driver.yaml`, `car_data_model.json` (object index 5), CAR sensor `third_party/piiat-mitrecar/third_party/car/sensors/sysmon_13.yaml`.

> **Authority note.** The bundled `driver.yaml` `coverage_map` is **stale** and is NOT the source of truth. It lists `sysmon_13 → {fqdn, image_path, pid, sha256, signature_valid, signer}` — but that map (a) omits `hostname`, `md5_hash`, `sha1_hash` which the shipped engine *does* extract, and (b) asserts `pid` which the engine correctly does **not** extract (Sysmon EID 6 carries no `ProcessId`). The authoritative "currently mapped" state is the executable engine map `third_party/piiat-mitrecar/piiat_mitrecar/mappings/sysmon.py` (`sysmon_driver_load` variant) and PIIAT-Mem `third_party/piiat-mem/piiat_mem/mappings.py` (`windows.modules`), reflected in generated source files `sources/evtx_sysmon.yaml` and `sources/memory.yaml`.

---

## Source universe (what can produce a `driver` row)

| Src key | Artefact / tool | Event / plugin | Emits object | In pipeline? | File |
|---|---|---|---|---|---|
| **S1** | Sysmon (EvtxECmd, `Microsoft-Windows-Sysmon/Operational`) | **EID 6 DriverLoad** | `driver`/`load` | **YES (mapped)** | `mappings/sysmon.py:432` |
| **S2** | Memory image, Volatility 3 (PIIAT-Mem) | **`windows.modules`** (PsActiveModuleList walk) | `driver`/`load` | **YES (mapped)** | `piiat-mem/piiat_mem/mappings.py:286`; plugin driver `python/get_sybers_dxdfir/volatility.py:58` |
| S3 | Memory image, Volatility 3 | `windows.dumpfiles` / `moddump` + hasher | (would feed driver hashes) | **NO** (not in `DEFAULT_PLUGINS`) | — |
| S4 | Windows Event Log | **System 7045** (SCM service install, kernel-mode driver) | currently `service`/`create` | mapped as **service, not driver** | `mappings/evtx_windows.py:180` (`_SVC_*`), `sources/evtx_services.yaml` |
| S5 | Windows Event Log | **System 20003** (UserPnp driver-service registration, `DriverFileName`) | currently `service`/`create` | mapped as **service, not driver** | `mappings/evtx_more.py` (header §20003) |
| S6 | Disk image, Plaso `pe` (PE/COFF) | `.sys` PE metadata | currently `file`/`create` | mapped as **file, not driver** | `mappings/plaso_exec.py:250`, `sources/plaso_pecoff.yaml` |
| S7 | Disk image, Plaso `winreg` **Amcache** (`InventoryDriverBinary`/`AppFile`) | `.sys` amcache entry | currently `file`+`process` | mapped as **file, not driver** | `sources/plaso_exec_winreg.yaml` |
| S8 | EZ Tools AmcacheParser / PECmd / MFTECmd, YARA over `.sys`, Windows CodeIntegrity/Kernel-PnP | driver `.sys` identity/hash/signature | — | **NO map exists** (evidence dirs empty) | — |

`crosssource.py` treats `driver` as both a **hashed** (`_HASHED`) and **imaged** (`_IMAGED`) object (`mappings/crosssource.py:47-49`), so S1 and S2 driver rows converge across sources on content-hash or `.sys` basename — see §Cross-source.

---

## Per-field provenance

Legend for "currently mapped?": **YES** = shipped engine writes this canonical column for a `driver` row; **NO** = no artefact in the pipeline writes it to the `driver` object (even where the raw datum exists elsewhere).

| field | sources (source → native field) | action(s) | currently mapped? (yes+where / NO) | confidence & caveats |
|---|---|---|---|---|
| **base_address** | **S2** memory `windows.modules` → `Base` (kernel virtual load addr) | load | **YES** — `piiat-mem mappings.py:286` (`base_address:"Base"`); `driver.base_address` col in `car.db` | High. **Memory is the ONLY source.** Sysmon EID 6, 7045, PE, amcache carry no runtime load address (disk/log artefacts never observe where the kernel mapped it). S1 leaves it null. |
| **fqdn** | **S1** Sysmon EID 6 → `Computer` (only if dotted) | load | **YES** — `sysmon.py` `_image_load_props()` via `_FQDN` | High. Inferred: claimed only when `Computer` contains a dot; a NetBIOS name is not faked into an FQDN. S2 (memory) does not stamp fqdn on the driver plugin row → null there. |
| **hostname** | **S1** Sysmon EID 6 → `Computer` (first DNS label) | load | **YES** — `sysmon.py` via `_HOSTNAME` | High. (The stale `driver.yaml` coverage_map omits this — engine does map it.) S2 windows.modules yields no hostname on the row (kernel-global); memory host lives in `image_context`, not the driver row. |
| **image_path** | **S1** Sysmon EID 6 → `ImageLoaded`; **S2** memory `windows.modules` → `Path` (FullDllName). *Potential (unmapped-as-driver): S4 7045 `ImagePath`, S5 20003 `DriverFileName`, S6 PE `display_name`, S7 amcache `full_path`.* | load | **YES** — S1 `sysmon.py:432`; S2 `mappings.py:286` | High. A driver loads into the kernel with no module_path, so `ImageLoaded`/`Path` **is** the driver's own file path (note in `sysmon.py:429`). Two independent mapped sources. |
| **md5_hash** | **S1** Sysmon EID 6 → `Hashes` (`MD5=…`). *Potential: S3 memory dump+hash.* | load | **YES** — `sysmon.py` `_hashes()` (`regex1 MD5=`) | High for S1. **Only Sysmon** currently supplies it. Memory driver rows are hash-less (S2 does no hashing); S3 (dumpfiles+hash) is not wired. IMPHASH from the same blob has no CAR home → stays native. |
| **module_name** | **S1** Sysmon EID 6 → `basename(ImageLoaded)`; **S2** memory `windows.modules` → `Name` (BaseDllName). *Potential: S4 `ServiceName`, S5 driver-service name.* | load | **YES** — S1 `sysmon.py:432`; S2 `mappings.py:286` | High. Two mapped sources. |
| **pid** | **none** | load / unload | **NO — honest no-source** | High confidence there is NO source. Sysmon EID 6 (DriverLoad) has no `ProcessId` field — the kernel loads the driver, not a user process (`sysmon.py:429-431`). Memory `windows.modules` is kernel-global (`owning_pid: None`, `mappings.py:286`). The field exists in the model but **no host/memory artefact populates it for `driver`**. The `driver.yaml` coverage_map's `pid:[sysmon_13]` claim is **wrong/stale**. |
| **sha1_hash** | **S1** Sysmon EID 6 → `Hashes` (`SHA1=…`). *Potential: S7 amcache `sha1` (as file), S3 memory dump+hash.* | load | **YES** — `sysmon.py` `_hashes()` | High for S1. **Only Sysmon** supplies it to the driver object. Amcache carries `.sys` SHA-1 but lands on the `file` object, never `driver` (S7). |
| **sha256_hash** | **S1** Sysmon EID 6 → `Hashes` (`SHA256=…`). *Potential: S6 PE `sha256_hash` (as file), S3 memory dump+hash.* | load | **YES** — `sysmon.py` `_hashes()` | High for S1. **Only Sysmon** to the driver object. Plaso PE carries `.sys` SHA-256 but emits a `file` row (S6). |
| **signature_valid** | **S1** Sysmon EID 6 → `SignatureStatus` (`Valid`→True only). *Potential: Windows CodeIntegrity (S8).* | load | **YES** — `sysmon.py:159` `_SIGNATURE_VALID = map_value(SignatureStatus,{Valid:True})` | High. Asserts True **only** on `Valid`; every other status (Unavailable/Errors/…) is a problem-signal kept native, never faked to False. Memory/PE/amcache do not verify signatures → null there. |
| **signer** | **S1** Sysmon EID 6 → `Signature`. *Potential: CodeIntegrity/authenticode (S8).* | load | **YES** — `sysmon.py` `_image_load_props()` (`signer: Signature`) | High. `Signature` = who signed; the verdict is `signature_valid`. Only Sysmon supplies it. |

---

## Per-action coverage

### `load`
Two **complementary** mapped sources whose field coverage barely overlaps:

- **S1 Sysmon EID 6** → identity + integrity: `module_name, image_path, md5/sha1/sha256, signer, signature_valid, hostname, fqdn`. **No `base_address`, no `pid`.**
- **S2 Memory `windows.modules`** → runtime identity: `base_address, image_path, module_name`. **No hashes, no signer, no signature_valid, no pid, no host.**

**Union of mapped sources covers 10 of 11 fields** — everything except `pid` (which has no source at all). `base_address` comes *only* from memory; hashes + signature come *only* from Sysmon. Neither source alone is complete; together (via cross-source join, below) they reconcile.

### `unload`
**ZERO coverage — no source anywhere.** The `driver.yaml` coverage_map's `unload` row is empty, and no artefact in the repo emits a driver-unload event:
- Sysmon has **no** DriverUnload event (EID 6 is load-only).
- Memory `windows.modules` is a **load-state snapshot** (a module present in `PsLoadedModuleList`), not an unload observation; ts is `None`/store-only.
This is an **honest structural no-source**, not merely an unmapped one.

---

## Cross-source convergence (wired, report-layer)

`third_party/piiat-mitrecar/piiat_mitrecar/crosssource.py` converges per-source `car.db` stores. Because `driver ∈ _HASHED` (line 47) and `driver ∈ _IMAGED` (line 49), a Sysmon EID 6 driver row and a memory `windows.modules` driver row for the **same `.sys`** converge:
- at **DEFINITIVE_CONTENT** tier if a shared content hash exists (only if the memory row were hashed — currently it is not), or
- at **HEURISTIC_IMAGE** tier on the `image_path` **basename** (this is the realistic join today).

`_merge_properties()` (line 138) **unions** the group's canonical columns, recording each property's source. So the converged view of a driver carries `base_address` (from memory) **and** `md5/sha1/sha256/signer/signature_valid` (from Sysmon) together — the two partial sources reconcile into near-complete coverage. Caveat: this is a **convergence report** (`crosssource.jsonl`), not a write-back into the per-source `driver` rows; consumers must read the merged view.

---

## Evidence-store reality check (`data_store/processed`)

The current light test set (LS24) exercises **no** driver evidence:
- `windows_logs/unspecified_host/log_EvtxECmd_Output.json`: **0** Sysmon EID 6 records, **0** System 7045.
- `volatility/memdump.mem/plugins/`: only `banners, mftscan, piiat.processes, piiat.registry, piiat.sessions, pslist` ran — **`windows.modules` did not run / produced nothing**, so `car.db` `driver` table = **0 rows** (the table + full 11-column schema exist and are correct).

So the maps are in place and correct, but there is **no grounded driver output in the processed store** to validate against yet. A memory image with kernel modules, or a Sysmon-6-bearing evtx, is needed to exercise the driver lane end-to-end.

---

## Summary

**Coverage of `driver`:**
- **load:** strong. 10/11 fields covered across two mapped sources (Sysmon EID 6 + memory `windows.modules`); `base_address` memory-only, hashes/signature Sysmon-only, and they reconcile via cross-source image-path join.
- **unload:** 0/11 — no source exists anywhere (structural, not a mere gap).
- **`pid`:** 0 sources on either action — a model field nothing populates for drivers (kernel loads them).

**Unmapped gaps, ranked by value:**

1. **Hash/signature enrichment of memory driver rows (MEDIUM).** `windows.modules` gives `base_address`+path+name but **no hashes/signer/signature_valid**. Fixable by (a) wiring S3 `windows.dumpfiles`/`moddump` + hashing of dumped `.sys`, or (b) relying on the existing cross-source image-path join to inherit Sysmon/PE/amcache hashes. Enables allow/deny-listing on memory-only evidence.
2. **Disk `.sys` hashes never reach the driver object (MEDIUM).** Plaso PE (`sha256`, S6), amcache (`sha1`, S7) parse driver `.sys` files but emit `file`/`process` rows — the `driver` object never sees them. A `driver↔file` cross-source join on `image_path` (basename) would let a driver inherit disk-derived hashes + compile_time. Not wired for the driver object today.
3. **`base_address` absent on Sysmon driver rows (LOW-MEDIUM).** Only memory observes the load address; a memory↔Sysmon join on `image_path`+host (already available via `crosssource.py`) is the remedy — no new source needed, just consume the merged view.
4. **Kernel-mode-service installs modelled as `service`, not `driver` (LOW / debatable).** System 7045 (with kernel `ServiceType`) and 20003 (`DriverFileName`) are genuine driver-registration events carrying `module_name`+`image_path`, but land on `service`. Dual-emit or driver-link is possible; the `service` modelling is defensible, so this is a note, not a hard gap. No hashes/base_address available from these anyway.
5. **`driver/unload` (NONE feasible).** No telemetry source exists in scope (Sysmon has no unload event; memory is a load snapshot). Honest no-source — not actionable without a new sensor.
6. **`pid` on driver (NONE feasible).** No artefact carries it; kernel-loaded drivers have no initiating user process. Honest no-source.

**Bottom line:** the driver `load` lane is well-built and honest — Sysmon and memory each supply exactly what their vantage point can prove, `base_address`/hashes/signature never faked onto the wrong source, and cross-source convergence reconciles the two. The real opportunities are enrichment joins (memory driver ← disk/Sysmon hashes), not new primary sources. `unload` and `pid` are genuine structural dead-ends.
