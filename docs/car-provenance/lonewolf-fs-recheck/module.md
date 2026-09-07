# FILESYSTEM/disk provenance pass — MITRE CAR `module`

**Object:** `module` — executable/loadable content (DLLs, shared libs) mapped into a
process address space. **Actions:** `load`, `unload`.
**Fields (13):** `base_address, fqdn, hostname, image_path, md5_hash, module_name,
module_path, pid, sha1_hash, sha256_hash, signature_valid, signer, tid`.

**Scope of THIS pass:** disk/filesystem artefacts only. The prior pass
(`docs/car-provenance/module.md`, LS24) covered the three *live* producers —
Sysmon EID 7, WMI 5857, memory `windows.piiat.modules` — and already flagged
prefetch `mapped_files` (backlog Tier-1 #7) and hash-hydration (Tier-2 #6) as
gaps. This pass grounds those in **real disk evidence** and sweeps every other
filesystem source exhaustively.

**Grounding data (REAL):** LoneWolf Win10 plaso timeline
`data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (6.6 GB, 4,169,774
events). Counts below are measured from it.

**Engine maps read:** `piiat_mitrecar/mappings/plaso_exec.py` (prefetch/amcache/
shimcache → process), `plaso_fs_extra.py` (`pe_coff:file` → file), `sysmon.py`
(EID 7, the only rich module producer), `evtx_more.py` (WMI 5857). Convergence:
`piiat_mitrecar/crosssource.py`; STIX projection `stix.py`.

**Headline:** the disk holds a *huge* module population that the pipeline parses
but never turns into `module` rows. Only `sysmon.py` and `evtx_more.py` emit
`object: module` (verified — no plaso/registry/PE map does). Concretely on
LoneWolf: **150,708 `pe_coff:file` rows** (137,979 DLLs) carry
path + SHA-256 + imphash, mapped to **`file`**, never `module`; **1,312 prefetch
rows** carry a `mapped_files` DLL list kept **native on `process/create`**, never
exploded into `module/load`. Both are the #1/#2 unmined levers. Amcache, shimcache
and WER are **honest non-sources for `module`** in this real data (no DLL rows /
no parser).

---

## 1. Filesystem source inventory (measured on LoneWolf) — what each could give `module`

| fs artefact | plaso data_type | rows | today maps to | module content it holds | emits `module`? |
|---|---|---:|---|---|---|
| **PE files on disk** | `pe_coff:file` | **150,708** | `file/create` (`plaso_fs_extra.py:188` `_pe_map`, time-free entity) | `display_name`→path, `sha256_hash`, `imphash`, `pe_type` (DLL/EXE/SYS), `section_names`, `export_dll_name` | **NO** |
| **Prefetch loaded-module list** | `windows:prefetch:execution` | **1,312** | `process/create`; `mapped_files` kept **native only** (`plaso_exec.py:231`) | `mapped_files[]` (every DLL/file the run touched), `path_hints[0]`+`executable` (the owning process) | **NO** |
| **Amcache** | `windows:registry:amcache` | 604 | `process/create` (exe) / `file/create` (link-time) | `full_path`, `file_identifier`(SHA-1), `sha256_hash`, `company_name`, `product_name`, `file_version` | **NO** — and **no DLL rows** (see §3) |
| **Shimcache / AppCompatCache** | `windows:registry:appcompatcache` | 1,463 | `process/create` (`plaso_exec.py:335`) | `path`, `sha256_hash` | **NO** — **no DLL rows** (exe/appx only) |
| **WER crash reports** | *(none)* | 0 | — | would carry a loaded-modules list | **NO** — plaso emits no WER data_type |
| **KnownDLLs (SYSTEM hive)** | `windows:registry:key_value` (raw) | — | raw only | list of always-mapped DLL names | **NO** — config list, no pid/load event |

---

## 2. Per-field provenance — FILESYSTEM sources (`fs artefact → native field`)

Notation matches the house tables. "Mined?" = does a shipping map assert this
canonical `module` field from the disk artefact today (**all NO** — no fs source
produces a `module` row at all).

### base_address
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| — none — | load | **NO (honest no-source)** | **Runtime-only field.** A load VA exists only in a live/memory view. No disk artefact (PE, prefetch, amcache, shimcache) records where a module was mapped. Memory `windows.piiat.modules`→`Base` is the sole producer (prior pass). Permanent null from disk. |

### fqdn / hostname
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| PE / prefetch / amcache / shimcache → `image_hostname` (lane-stamped) | load | NO (fs→module not wired) | **Would be High if wired.** Every plaso row already carries `image_hostname` (the imaged host), used verbatim by the process/file maps. A prefetch- or PE-derived `module/load` would inherit it directly. `fqdn` only when the stamped host is dotted (dot-guard, same as elsewhere) — usually a bare NetBIOS name → honest null. |

### image_path  *(CAR = the OWNING PROCESS image, not the DLL)*
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| **Prefetch → `path_hints[0]` / `executable`** | load | **NO** | **Medium-High.** Prefetch is the ONE disk source that pairs a module list with its owning process: each `mapped_files` entry belongs to the process named by `executable` (bare name, always present) / `path_hints[0]` (full path — but a plaso **list** the marker set can't index today; same limitation the process map hit, `plaso_exec.py:218`). So a prefetch `module/load` gets correct `image_path` when path_hints is non-empty, else the bare name in a native field + honest null. |
| PE / amcache / shimcache | load | NO | **No-source.** A PE on disk has no owning process; amcache/shimcache index the executable itself, not a load-into-process relationship. |

### module_name  *(DLL basename)*
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| **Prefetch → `basename(mapped_files[i])`** | load | **NO** | **High.** e.g. `\VOLUME{…}\WINDOWS\SYSTEM32\NTDLL.DLL` → `NTDLL.DLL`. Free from the path. |
| **PE → `basename(display_name)`** | load (presence) | **NO** | **High.** `NTFS:\Windows\System32\<x>.dll` → `<x>.dll`. But PE has no load event — presence on disk, not a load into a process (§3). |
| amcache/shimcache → `basename(full_path/path)` | — | NO | Only exe/sys/cpl paths here → not module basenames (§3). |
| PE version-resource `OriginalFileName` | — | **NO (no-source)** | **Plaso's `pe` parser extracts NO VERSIONINFO** — 0 of 150,708 rows carry `original_file_name`/`company_name`/`file_version`/`product_name` (measured). The "OriginalFileName → module_name" idea needs a new PE-resource reader; not in the pipeline. |

### module_path  *(full path of the loaded DLL)*
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| **Prefetch → `mapped_files[i]`** | load | **NO — #1 gap** | **High** for the path itself. Full NT path per entry, e.g. `\VOLUME{01d3c5cc91d8a333-aa920881}\WINDOWS\SYSTEM32\NTDLL.DLL`. Caveats: **volume-GUID prefix** (`\VOLUME{…}`) needs stripping/normalising to join other sources; the list **mixes DLLs with data files** (saw `LOCALE.NLS` alongside DLLs) — filter by extension/`pe_type`; **no per-module load time, no base_address, no hash, no runtime pid**. Sample run (`TASKHOSTW.EXE`) had **54** mapped files. |
| **PE → `display_name` path** (`_PATH` strips the `VSS/NTFS:` volume prefix, `plaso_fs_extra.py:55`) | load (presence) | **NO — #2 gap** | **High** for the path. `\Windows\System32\*.dll` (23,779), `\Windows\SysWOW64\*.dll` (14,689), `\Windows\WinSxS\*` (66,234, incl. SxS side-by-side + `.mui`). Covers live NTFS **and** VSS1/VSS2 shadow copies. Presence, not a load. |

### md5_hash
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| — none — | load | **NO (no-source)** | No disk PE source emits MD5. Plaso `pe` hashes SHA-256 only; amcache carries SHA-1. |

### sha1_hash
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| **Amcache → `file_identifier`** (SHA-1) | load | **NO** | **Low relevance for module here.** `file_identifier` is the SHA-1 (44 chars = plaso's `0000` prefix + 40 hex) — present on all 604 rows. BUT amcache has **zero DLL rows** on LoneWolf (566 exe / 36 sys / 2 cpl — §3), so it hydrates `process`/`driver`, not `module`. **Bonus bug:** the amcache map reads `sha1=_R("sha1")` (`plaso_exec.py:286`), a field **absent** in this plaso build — the real SHA-1 is `file_identifier`, so amcache SHA-1 is currently NOT captured at all (a field-name mismatch, affects process/file rows). |
| PE / prefetch / shimcache | load | NO | No SHA-1 (PE=sha256, prefetch/shimcache no module hash). |

### sha256_hash
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| **PE → `sha256_hash`** (the `pe` parser hashes the file) | load | **NO — #2 gap** | **High** as a disk-file hash: present on 100 % of 150,708 `pe_coff:file` rows, incl. all 137,979 DLLs, keyed by disk path. This is the natural `module.sha256_hash` hydration source (join module_path→PE path). Caveat: it is the **on-disk** file's hash — matches a loaded module only if the loaded copy equals the disk copy (true for clean loads; a packed/hollowed in-memory image will differ — that discrepancy is itself signal). Also carries native `imphash`, `pe_type`, `section_names`. |
| amcache → `sha256_hash` | load | NO | Present, but no DLL rows (§3) → hydrates process/driver, not module. |
| shimcache → `sha256_hash` | load | NO | Present, but exe/appx only (§3). |

### signature_valid / signer
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| — none — | load | **NO (honest no-source from disk)** | **Plaso extracts NO Authenticode/catalog signer and runs NO WinVerifyTrust.** 0 of 150,708 PE rows carry a signer/signature field (measured). Amcache's `company_name`/`product_name` are **version-resource strings, NOT the signer** (and are dropped by the map anyway). Getting `signer`/`signature_valid` from disk needs a new step: parse the PE Authenticode cert **or** the `\Windows\System32\catroot` security-catalog for the file's hash, then verify — not wired. Today only Sysmon EID 7's own `Signature`/`SignatureStatus` supplies these. |

### pid
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| — none — | load | **NO (honest no-source from disk)** | Prefetch is per-**executable** (aggregates runs), never records a runtime PID; PE/amcache/shimcache are disk files. `module.pid` from any fs source is a permanent null (only Sysmon7/WMI/memory give it). |

### tid
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| — none — | load | **NO (honest no-source)** | No artefact in the whole pipeline records the loading thread; disk least of all. Permanent null. |

---

## 3. Honest non-sources (measured, so the negatives are grounded)

- **Amcache is NOT a `module` source on this image.** All 604 rows are exe (566),
  sys (36), cpl (2) — **zero `.dll`**. Plaso's amcache parser surfaces the
  `InventoryApplicationFile`/legacy-`File` "primary file" of installed programs
  (mostly EXEs) + drivers (`.sys` → `driver`). The DLL-per-application detail the
  brief hoped for is not present. So amcache's SHA-1/version fields feed
  `process`/`driver`, never `module`, here.
- **Shimcache is NOT a `module` source.** 1,030 exe + UWP appx package paths, 8
  cpl, 136 extension-less — **zero `.dll`**. AppCompatCache indexes executables.
- **WER: no parser.** No WER/Windows-Error-Reporting data_type exists in the
  timeline (only `WerFault.exe.mui` as a PE file). Plaso does not parse `.wer`
  crash reports, so their "loaded modules" list is unreachable — genuine
  no-source (would need a dedicated WER report parser).
- **KnownDLLs (SYSTEM hive):** only appears as WinSxS *manifest* `fs:stat` rows;
  the `…\Session Manager\KnownDLLs` key would land as raw `windows:registry:
  key_value`. It is a *configuration list* of always-mapped DLL names — no
  process, no pid, no base, no load event. Weak: could seed `module_name`/
  `module_path` for a fixed set of system DLLs but asserts no load. Effectively
  no-source for a `module/load`.
- **DLL search-order-hijack candidates (app-dir DLLs):** an *analytic derivation*
  over the PE/prefetch populations (a non-system DLL sitting beside an EXE in its
  app dir), not a native provenance field. Out of scope as a source; belongs in an
  analytic once PE/prefetch feed `module`.
- **`base_address`, `pid`, `tid`:** runtime-only — honest permanent nulls from disk.
- **`unload` action:** no disk artefact records a `FreeLibrary`/unload. Every
  filesystem source is a *presence/load* snapshot. Honest no-source.

---

## 4. The convergence gap — why hashes don't reach `module` even today (code-grounded)

`crosssource.py` is the right vehicle (it already unions properties across
sources by content hash and image path), **but as keyed it cannot hydrate
`module` hashes from disk PEs:**

1. **Content-hash bucket is object-scoped.** `_keys()` builds the definitive
   content key as `(obj if obj != "process" else "file", *hash)`
   (`crosssource.py:130`). Only `process` collapses into the `file` bucket;
   **`module` and `driver` keep their own object tag**. So a `pe_coff` **file**
   row (`("file", sha256, …)`) never converges with a **module** row
   (`("module", sha256, …)`) even when the bytes are identical. A *hashed*
   Sysmon-7 module does **not** pick up the disk PE's metadata.
2. **The image/path key never uses `module_path`.** `_image_key()` =
   `basename(image_path or exe)` (`crosssource.py:112`). For a `module`,
   `image_path` is the **owning process** image (CAR semantics), not the DLL — and
   module rows have no `exe`. So the heuristic-image join keys a module by its
   *host process's* name, never by the DLL's own name/path. `module_path`/
   `module_name` participate in **no** convergence key.

Net: even if prefetch `mapped_files` were exploded into `module/load` rows (giving
`module_path` + `module_name`, no hash), the existing convergence could not attach
the on-disk PE's SHA-256 to them. Hydration needs one of: (a) add `module`/`driver`
to the `process→file` hash-bucket collapse, and/or (b) a new key on
`(host, normalised module_path | module_name)` ↔ file `file_path`/`file_name`.

**STIX note:** at export, `_b_module` (`stix.py:934`) already projects a module to
a `file_instance(host, module_path, module_name, hashes, "module", …)`, and
`file_instance` is path-keyed (`stix.py:529,641`). So a module SCO and a `pe_coff`
file SCO *at the same exact path string* would merge downstream — but only in STIX
output, only on an exact path match, and the path forms differ across sources
(prefetch `\VOLUME{…}\…`, PE `\Windows\…`, Sysmon `C:\Windows\…`, amcache
`c:\…` lowercase) so they won't coincide without normalisation. It does not
back-fill `car.db`.

---

## 5. Ranked UNMINED opportunities (filesystem)

1. **Explode prefetch `mapped_files` → `module/load` rows.** *Highest value,
   lowest cost — the data is already parsed and sitting native
   (`plaso_exec.py:231`).* Per entry: `module_path` = the mapped path,
   `module_name` = its basename, `image_path` = owning `path_hints[0]`/`executable`,
   `hostname`/`fqdn` from `image_hostname`. 1,312 prefetch rows on LoneWolf.
   Caveats: strip `\VOLUME{…}` prefix; filter data files (`.nls`, `.dat`) from real
   modules by extension/`pe_type`; no hash/base/pid/tid/load-time. Confidence:
   High for path+name identity, this is a *loaded-into-process* relationship (the
   correct `module/load` semantics), not mere disk presence.

2. **Map `pe_coff:file` (DLLs) → `module` (or a disk-module hash table) + join.**
   150,708 rows / 137,979 DLLs carry `sha256_hash` + `imphash` + `pe_type` keyed
   by path — the definitive on-disk module-hash source (System32, SysWOW64,
   WinSxS, live + VSS). Either emit disk-`module` presence rows, or (better) fix
   the convergence keying (§4) so this hash hydrates `module.sha256_hash` for
   modules seen hashless via prefetch/memory. Confidence: High for the hash/path;
   the caveat is disk-copy ≠ in-memory-image for tampered loads (a signal, not a
   defect).

3. **Cross-object hash hydration — extend `crosssource.py` to `module`/`driver`.**
   Add module/driver to the content-hash collapse and/or a `module_path`↔`file_path`
   key with path normalisation. Turns opportunities 1+2 into a real
   `module.sha256_hash`/`sha1_hash` fill. This is the same `crosssource.py`
   machinery the backlog Tier-2 #6 already names; this pass pins the exact keying
   fix required.

4. **(Bonus, adjacent) Fix the amcache SHA-1 field name** (`sha1` → `file_identifier`)
   in `plaso_exec.py:286` so amcache's SHA-1 is actually captured — helps
   `process`/`driver` hydration (not `module`, since amcache has no DLLs here).

**Not worth wiring for `module`:** amcache/shimcache (no DLL rows), WER (no
parser), KnownDLLs (config list, no load event), PE version-resource signer/name
(plaso extracts none — needs a new parser). Signer/signature_valid from disk needs
Authenticode/catroot verification that the pipeline does not perform — Sysmon EID 7
remains the only signer source.

---

## 6. Coverage at a glance — filesystem sources vs `module` (13 fields)

| field | Prefetch `mapped_files` | PE `pe_coff:file` | Amcache | Shimcache | best fs today |
|---|:--:|:--:|:--:|:--:|---|
| base_address | – | – | – | – | **no-source (runtime)** |
| fqdn | (avail) | (avail) | (avail) | (avail) | inherit `image_hostname` |
| hostname | (avail) | (avail) | (avail) | (avail) | inherit `image_hostname` |
| image_path | ✅(owning) | – | – | – | prefetch only |
| md5_hash | – | – | – | – | no-source |
| module_name | ✅ | ✅ | (no DLLs) | (no DLLs) | prefetch / PE |
| module_path | ✅ | ✅ | (no DLLs) | (no DLLs) | prefetch / PE |
| pid | – | – | – | – | **no-source (disk)** |
| sha1_hash | – | – | (exe/sys only) | – | none for module |
| sha256_hash | – | ✅(disk) | (exe/sys only) | (exe only) | PE (disk copy) |
| signature_valid | – | – | – | – | no-source (no verify) |
| signer | – | – | (company≠signer) | – | no-source |
| tid | – | – | – | – | **no-source** |

`(avail)` = the row carries `image_hostname`, free to inherit if fs→module is
wired. **Every ✅ is currently UNMINED** — no filesystem source produces a
`module` row today; the entire column is opportunity, gated on wiring
prefetch/PE into the object (opportunities 1–3).
