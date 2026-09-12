# FILESYSTEM Property-Provenance Audit — MITRE CAR `service`

Deep-audit of **disk/filesystem** artefacts that could fill the CAR `service` object but
which the DX_DFIR pipeline has **not mined into a service object yet**. Companion to the
LS24 memory/live catalogue (`docs/car-provenance/service.md`); this pass is disk-only,
grounded in the **real LoneWolf Win10 plaso timeline**.

- **Object** `service`: fields `command_line, exe, fqdn, hostname, image_path, name, pid, ppid, uid, user`; actions `create, delete, pause, start, stop` (`car_data_model.json`).
- **Ground truth**: `data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl`
  (LoneWolf.E01, host `DESKTOP-PM6C56D`), 4.17M rows. Numbers below are counted from it.
- **Maps in play**: `byakugan/piiat_mitrecar/mappings/plaso_registry.py`
  (F), `.../recmd.py` (G), `.../plaso_exec.py` (prefetch/amcache), `.../plaso_fs_extra.py`
  (filestat/PE = $MFT).

---

## HEADLINE (the #1 opportunity)

The SYSTEM hive `...\Services` key is **already fully parsed** — plaso's
`winreg/windows_services` parser emits **1,796** `windows:registry:service` rows in the real
LoneWolf timeline (**618 distinct services**; 608 live on `/p4`, the rest VSS/shadow-only) —
but `plaso_registry.py` maps every `windows:registry:*` row to CAR **`registry` /
`key_edit`**. **A dead-disk image therefore yields ZERO `service` objects today.** The whole
object is sitting in the evidence, parsed, mis-classified as registry.

The service definition is carried on the plaso record itself (verified top-level field
presence over the 1,796 rows):

| plaso field (top-level) | present | → CAR `service` field |
|---|---|---|
| `name` (Services subkey name) | 1796/1796 | `name` [direct] |
| `image_path` (ImagePath, args intact) | 1760/1796 | `command_line` verbatim; `image_path`/`exe` after parse |
| `object_name` (run-as ObjectName) | **718/1796** | `user` [direct] |
| `service_dll` (svchost hosted DLL) | **591/1796** | the REAL binary (native today) |
| `service_type` / `start_type` / `error_control` | 1796/1796 | driver-vs-win32 / autostart (native) |

`object_name` and `service_dll` are **already extracted into `_native`** by `plaso_registry.py`
(`native_extract` lines 72–73) — so the reconstruction inputs are literally already in the DB,
just hung on the wrong object. **The fix is a service-reconstruction map (or an enrichment
pass over the registry native): one `service/create` per live Services subkey.** That single
change lights up ~608 service objects per LoneWolf-class disk image, from data already parsed.

---

## Per-field table (Services-key / other fs artefact → native field)

`mined?` column: **registry YES** = the fact reaches the DB but on a `registry` object;
**service NO** = no `service` object is emitted from disk today.

| field | Services-key / other fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|---|
| **name** | Services subkey name → plaso `name` (1796); RECmd subkey/ValueName | create | registry YES / service **NO** | HIGH. Verbatim key name. The one field on every row. |
| **image_path** | ImagePath → plaso `image_path` (1760/1796) → parse bare exe | create | registry YES (as `registry.image_path`) / service **NO** | HIGH. Env-vars stay literal (`%SystemRoot%\System32\svchost.exe`) — the exe_path parse must expand `%SystemRoot%`. For the **205 svchost-hosted** live services the exe is svchost.exe; the *real* binary is `service_dll` (below). |
| **exe** | `basename(image_path)` | create | service **NO** | HIGH, derived. Inherits svchost caveat (basename = `svchost.exe`, not the DLL). |
| **command_line** | ImagePath **verbatim incl. args** → plaso `image_path` (221/608 live carry args/switches, e.g. `svchost.exe -k netsvcs -p`) | create | registry YES (native) / service **NO** | HIGH. Distinct from image_path: keeps the `-k <group> -p` args. Env-vars literal. |
| **user** | **ObjectName → plaso `object_name`** (718/1796): LocalSystem 454, NT AUTHORITY\LocalService 198, NetworkService 63, \Driver\WudfRd 3 | create | registry YES (native) / service **NO** | MEDIUM-HIGH. Run-as **name**, not SID. Casing/prefix variants (`localSystem`, `NT Authority\` vs `NT AUTHORITY\`) need normalising. Null on the ~1078 driver rows (kernel drivers have no ObjectName → honest null). |
| **hostname** | `image_hostname` = `DESKTOP-PM6C56D` (1796/1796) | create | registry YES (as `registry.hostname`) / service **NO** | HIGH. Already the host-label on the registry object; trivially carried to a service object. |
| **fqdn** | `image_hostname` iff dotted | create | service **NO** | N/A here. `DESKTOP-PM6C56D` is NetBIOS, not dotted → honest null. Only populated if the machine name is an FQDN. |
| **pid** | — (Services key is static config) | — | **NO source (fs)** | **Honest null.** A dead hive records configuration, not a running instance. pid exists only from memory `svcscan` (see companion). |
| **ppid** | — | — | **NO source** | **Honest null.** No disk artefact records a service's parent PID. Structural. |
| **uid** | — (`object_name` is a NAME; hive `username`=`-` for SYSTEM hive) | — | **NO source (fs)** | **Honest null.** The Services key names the run-as identity as a string (fills `user`), never a SID. SYSTEM-hive owner is `-`. No clean `uid`. |

---

## Corroborating fs artefacts (fill OTHER objects; link to the service via binary path at enrichment — NOT service fields)

These do not populate a `service` field, but they corroborate `image_path`/`service_dll` and
supply the missing *runtime/plant-time* dimension the static Services key cannot. Counts from
the real timeline:

| artefact | rows (LoneWolf) | maps to (today) | what it adds for a service |
|---|---|---|---|
| **Prefetch** `windows:prefetch:execution` | 1,312 | `plaso_exec.py` → **process/create** | The service **exe actually RAN** = de-facto `start` evidence — but only for **exe-hosted** services; svchost-hosted (205) share `svchost.exe`'s prefetch → ambiguous, cannot attribute a start to one service. |
| **Amcache** `windows:registry:amcache` | 604 | `plaso_exec.py` → **process/create** + **file/create** (PE link time) | Service **binary presence + SHA1 + PE compile time** (when it was planted/built). Keyed on binary path, not service name. |
| **$MFT / filestat** `fs:stat` | 1,968,065 | `plaso_fs_extra.py` → **file** (create/modify) | Service binary / `service_dll` **existence + NTFS creation time** = when the binary was dropped on disk. Corroborates image_path; joins by path. |
| **PE metadata** `parser:pe` | 150,852 | `plaso_fs_extra.py` → **file** | Signer / compile-stamp of the service binary (signature_valid, signer on the `file` object). |
| **USN journal** `parser:usnjrnl` | 359,999 | (fs) | Create/rename of the service binary — plant-time even after the $MFT entry is reused. |
| **Scheduled Tasks** `...:task_cache:entry` | 1,454 | `plaso_registry.py` → **registry** (swept as `windows:registry:*`) | Service-**like** persistence but a *different* object; CAR has **no task object**, and a task is not an SCM service. Out of `service` scope by design. |

**Takeaway:** every one of these is a *binary-centric* corroboration joined to the service by
`image_path`/`service_dll` at the enrichment end-stage — none is a native `service` field and
none changes the field table above.

---

## Actions from a dead disk

The Services key is a **static snapshot at its key LastWrite time** (all 1,796 rows are
`timestamp_desc = "Content Modification Time"` — one timestamp per key). That supports exactly
one action:

| action | fs source | verdict |
|---|---|---|
| **create** | Services subkey exists @ key LastWrite | **THE reconstruction target.** LastWrite is the install/config-time proxy. |
| **start** | prefetch of exe-hosted service (indirect) | Not a service action today; would over-assert if promoted (and blind for svchost DLLs). |
| **stop / pause** | — | **No fs source.** A static config key cannot record a stop/pause. |
| **delete** | **shadow diff**: keys in VSS but absent live | **Weak/noisy signal, unmined.** Only 10 shadow-only names in LoneWolf, and they are transient per-user (`*_18279b`: CDPUserSvc, OneSyncSvc…) + a Defender temp scanner (`MpKsl4f881ef9`) — not real deletions. Not worth wiring as a delete source; note it, don't trust it. |

---

## Honest no-sources (disk)

- **pid, ppid, uid** — structurally absent from a static hive (config ≠ runtime; run-as is a
  name not a SID; SYSTEM-hive owner is `-`). pid exists only from memory `svcscan`.
- **fqdn** — only if the recorded machine name is dotted; NetBIOS here → null (not faked).
- **stop / pause** actions — no disk artefact records them.
- **Autoruns** — CAR's canonical service create/delete sensor is still not wired (empty grep
  in `piiat_mitrecar/` and `python/`), consistent with the companion catalogue.

---

## Grounding / file index

- Real data: `data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` — 1,796
  `windows:registry:service` rows (`parser: winreg/windows_services`), 618 distinct services;
  top-level `object_name` 718, `service_dll` 591, `image_path` 1,760.
- Mis-classified map (the gap): `byakugan/piiat_mitrecar/mappings/plaso_registry.py`
  (object=registry, action=key_edit; `native_extract` already pulls `object_name`,
  `service_dll`, `start_type`, `service_type`, `error_control`, `name`, `values`).
- Value-granular disk map: `.../mappings/recmd.py` (registry/value_edit; real but not
  materialised in this store — `data_store/processed/zimmerman/` is empty).
- Corroboration maps: `.../mappings/plaso_exec.py` (prefetch/amcache → process/file),
  `.../mappings/plaso_fs_extra.py` (filestat/PE → file).
- No disk `car.db` exists yet (`data_store/processed/.../car.db` is the **memory** run only) —
  so the "zero service objects from disk" gap is confirmed by the map logic, not yet by a DB.
- Semantics: `byakugan/third_party/car/data_model/service.yaml`; schema
  `car_data_model.json`.

### service_type / start_type reference (observed distributions)
- `service_type`: 1 Kernel driver (937), 2 FS driver (111), 8 recognizer (3) → ~1,051 **driver**
  rows (overlap CAR `driver`); 16 Win32-own (154), 32 Win32-shared (528), +interactive/
  per-user flags (96/224/272/288) → the true **service**-object subset (~745 rows /≈248 distinct).
- `start_type`: 0 Boot (257), 1 System (74), 2 Auto (225), 3 Manual (1,201), 4 Disabled (39).
  Autostart (0/1/2 = 556) is the persistence-relevant slice.
