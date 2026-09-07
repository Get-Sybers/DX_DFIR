# Property-Provenance Catalogue — MITRE CAR `service`

Authoritative, exhaustive map of every canonical `service` field to every artefact/source
that can supply it, in the **DX_DFIR** pipeline. "Find once, done." Grounded in the repo
files cited; honest about no-source.

- **Object semantics**: `third_party/piiat-mitrecar/third_party/car/data_model/service.yaml`
- **Canonical schema**: `car_data_model.json` (object `service`) — confirmed by the `service`
  table in `data_store/processed/volatility/memdump.mem/car.db`.
- **Canonical fields (10)**: `command_line, exe, fqdn, hostname, image_path, name, pid, ppid, uid, user`
- **Canonical actions (5)**: `create, delete, pause, start, stop`

`car.db` `service` table columns (real, verified): the 10 canonical fields + provenance
columns (`event_id, timestamp, car_action, guid, owning_pid, owning_offset, owning_guid,
parent_pid, parent_guid, link_confidence, source_plugin, source_image, native`).

---

## 1. Source universe (who emits a `service` object, and who *could*)

| # | Source (event/artefact) | Extractor / map | CAR object emitted | Action | Wired? |
|---|---|---|---|---|---|
| A | **System 7045** (SCM ServiceInstall) | EvtxECmd → `evtx_services` (`evtx_windows.py`) | **service** | create | YES |
| B | **Security 4697** (service installed, audited) | EvtxECmd → `evtx_services` (`evtx_windows.py`) | **service** | create | YES |
| C | **System 20003** (UserPnp — driver-service registration) | EvtxECmd → `evtx_more` (`evtx_more.py`) | **service** | create | YES |
| D | **System 7034** (SCM — service crashed) | EvtxECmd → `evtx_more` (`evtx_more.py`) | **service** | stop | YES |
| E | **Volatility3 `windows.svcscan`** (memory) | PIIAT-Mem → `windows.svcscan` (`piiat-mem/.../mappings.py`) | **service** | *None* (store-only snapshot, no ts) | YES |
| F | **Registry `HKLM\SYSTEM\...\Services`** (Plaso winreg) | Plaso → `plaso_registry` (`plaso_registry.py`) | **registry** (NOT service) | key_edit | YES — but wrong object |
| G | **Registry Services key** (RECmd/EZ-Tools batch) | RECmd → `recmd_batch` (`recmd.py`) | **registry** (NOT service) | value_edit | YES — but wrong object |
| H | **Autoruns 13.98** (auto-start services) | CAR upstream sensor only | service | create, delete | **NO** (not in engine) |

Notes:
- **F/G are the big structural point.** Both parse the on-disk **Services** key (the complete
  service definition — `ImagePath`, `Start`, `Type`, `ObjectName`, `DisplayName`, `ServiceDll`),
  but the maps emit a **registry** object (key_edit/value_edit). The service facts survive only
  in `_native` (see §3). **On a dead-disk image the pipeline therefore emits zero `service`
  objects today** — the whole object is present in the evidence but not reconstructed.
- **H Autoruns is NOT wired**: `grep autoruns` over `piiat_mitrecar/` and `python/` is empty.
  The `coverage_map` in `service.yaml` (`create`/`delete` → `["autoruns_13.98"]`) and
  `sensors/autoruns_13.98.yaml` are **upstream CAR references**, not working sources here.
- **Sysmon / osquery**: CAR's own `sensors/sysmon_*.yaml` and `sensors/osquery_*.yaml` carry
  **no** `service` coverage; the repo's `sysmon.py` emits no service object. Sysmon EID 6 is a
  driver load → `driver` object, not `service`.
- **amcache**: consumed by `plaso_exec_winreg` as *process/execution* evidence, not service.

---

## 2. Per-field provenance (EVERY field × EVERY source)

Legend for native field → canonical: `[direct]` verbatim · `[derived]`/`[parsed]`
transformed (basename/exe_path/host_label) · `[coalesced]` first-non-empty of several ·
`[inferred]` conditional (fqdn only if dotted).

### `name`
| sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|
| 7045 → `ServiceName`; 4697 → `ServiceName`; 20003 → `ServiceName`; 7034 → `param1`; svcscan → `Name`; registry(F) → `name` *(native only)*; RECmd(G) → subkey/`ValueName` *(native only)*; autoruns → name *(upstream)* | create (A/B/C), stop (D), snapshot (E) | **YES** — A/B `evtx_services`, C/D `evtx_more`, E `windows.svcscan` all set canonical `name` [direct]. F/G carry it but as registry native, not a `service.name`. | HIGH. The one field every emitter fills. 7034 `param1` is the *display name*, not always the registry key name (near-match caveat). |

### `image_path`
| sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|
| 7045/4697 → `ImagePath`/`ServiceFileName` (parsed via `exe_path`); 20003 → `DriverFileName`; svcscan → `Binary` \| `Binary (Registry)` (parsed); registry(F) → `image_path` *(promoted to registry.image_path, not service)*; RECmd(G) → ImagePath value *(native)*; autoruns *(upstream)* | create (A/B/C), snapshot (E) | **YES** — A/B/C/E set canonical `image_path` [parsed/direct]. F sets it on the **registry** object. | HIGH. `exe_path()` splits the executable out of an ImagePath that embeds args (`svchost.exe -k …`) — a parse, not a guess. svcscan `Binary` is null for STOPPED services → falls back to `Binary (Registry)`. |

### `exe`
| sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|
| Derived `basename(image_path)` for every image_path source: 7045/4697, 20003, svcscan; autoruns *(upstream)* | create (A/B/C), snapshot (E) | **YES** — A/B/C/E. | HIGH, fully derived. Inherits the STOPPED-service fallback caveat from `image_path`. No independent artefact carries `exe` alone. |

### `command_line`
| sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|
| 7045/4697 → `ImagePath`/`ServiceFileName` **verbatim** (incl. args); svcscan → `Binary (Registry)` [direct]; registry(F/G) → ImagePath value *(native only)*; autoruns *(upstream)* | create (A/B), snapshot (E) | **YES** — A/B (`_SVC_RAW`), E (`command_line: "Binary (Registry)"`). | HIGH. **Distinct from `image_path`**: `command_line` keeps the raw ImagePath *with* trailing args; `image_path`/`exe` parse the bare path out. **NOT** carried by 20003 (C) or 7034 (D) — honest null there. |

### `user`
| sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|
| 7045 → `AccountName`; 4697 → `ServiceAccount` (fallback `UserName`); registry(F) → `object_name`/`ObjectName` *(native only)*; autoruns *(upstream)* | create (A/B) | **YES** — A/B only (`user: first(AccountName, ServiceAccount, UserName)`). | MEDIUM-HIGH. This is the **run-as** account (LocalSystem, NT AUTHORITY\…), usually a *name* not a SID. 4697 `SubjectUserName` (who *installed*) is a different entity and is deliberately **not** coalesced here. **NOT** from svcscan/20003/7034. Registry `ObjectName` is the same run-as value but sits in registry native — an unmapped opportunity. |

### `hostname`
| sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|
| 7045/4697/20003/7034 → `Computer` (first DNS label, `host_label`); registry(F) → `image_hostname` *(on registry object)* | create (A/B/C), stop (D) | **YES** — A/B/C/D [derived]. | HIGH for evtx. **svcscan (E) sets NO hostname** — the memory service map has no host label (honest null; enrichment/`image_context` supplies host at store level). |

### `fqdn`
| sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|
| 7045/4697/20003/7034 → `Computer` **iff dotted** (`regex1` `^(.+\..+)$`) | create (A/B/C), stop (D) | **YES** — A/B/C/D [inferred]. | MEDIUM. Only populated when `Computer` actually is an FQDN; a bare NetBIOS name is left null rather than faked. **NOT** from svcscan/registry. |

### `pid`
| sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|
| **svcscan → `PID`** [direct] | snapshot (E) | **YES — svcscan ONLY** | HIGH but single-source. **This is the field only a running-state source can supply.** 7045/4697 do **not**: an install is not a run, and their `ProcessId` column is the *event writer* (services.exe/lsass), not the service — deliberately left null. 7036 (state=Running) *could* carry it but is unmapped (§4). `pid` here is the running host process (often a shared svchost). |

### `ppid`
| sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|
| — none — | — | **NO — no source** | **Honest no-source.** No wired artefact records a service's parent PID as a service field. (svcscan yields `pid` but not a parent; the SCM `services.exe` is the conceptual parent but no map asserts it.) Structural null. |

### `uid`
| sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|
| *(candidates, all unmapped)*: 4697 `SubjectUserSid` (installer, native); 7045 `UserId` (writer's SID, native); registry(F) `hive_user_sid` (hive owner, not run-as) | — | **NO — no mapped source** | **Honest near-no-source.** `service.uid` per the model = SID of the user who *acted on* the service (e.g. `S-1-5-18`). The only SIDs in the evidence are the *installer* (4697 Subject) or the *record writer* (7045 UserId) — both deliberately kept native, never promoted, because neither is the run-as identity that `user` names. No source cleanly fills `uid`. |

---

## 3. What the registry sources hold but do NOT emit as `service` (the reconstruction gap)

`plaso_registry` (F) surfaces these into `_native` on a **registry/key_edit** row for each
`windows:registry:service` key — the complete service definition, unused as a service object:

- `name` (service key name), `object_name` (= run-as `ObjectName`), `image_path` (the binary),
  `start_type` (`Start`), `service_type` (`Type`), `service_dll` (svchost `ServiceDll`),
  `error_control`, plus the `values` list and `hive_user_sid`.

`recmd_batch` (G) emits one **registry/value_edit** per matched Services value
(`ValueName`/`ValueData`) — same facts, value-granular, also not a service object.

→ Everything needed for a `service/create` **from a dead disk** (name, image_path,
command_line via ImagePath, user via ObjectName, start_type, service_dll) is present here but
lives under the wrong object.

---

## 4. Action coverage & deliberate refusals

| action | mapped source(s) | gap |
|---|---|---|
| **create** | 7045 (A), 4697 (B), 20003 (C) | Covered for live/audited installs. Missing dead-disk create (registry F/G) + autoruns (H). |
| **stop** | 7034 (D) — *crash only* (involuntary) | No *clean/voluntary* stop source (7036 stop-state unmapped). |
| **delete** | — none — | **No source.** autoruns (upstream) does delete via diff; registry-key-removal is not detected. |
| **pause** | — none — | **No source anywhere.** No artefact records a service pause. |
| **start** | — none — | **No mapped source.** 7036 (state → Running) and svcscan `State=Running` are *snapshots*, not start events; deliberately not turned into a `start`. |

**Deliberately NOT mapped (documented honest refusals in the code):**
- **7040** (start-type changed) — the `service` object has no `modify`/config action, so it
  stays raw (`evtx_extra.py` header).
- **7036** (service entered Running/Stopped state) — "no canonical action here"
  (`evtx_windows.py:290`); mapping a state report to start/stop would over-assert.
- **svcscan** is `action=None` (store-only): its `State`/`Start`/`Type` native fields carry
  live status but are **not** promoted to a start/stop action.
- 7009/7011/7031/7042/7000/4698 — not mapped.

---

## 5. Coverage summary + UNMAPPED gaps (ranked)

**Field coverage of the 10 canonical fields (as `service` objects, today):**

| field | emitted by | verdict |
|---|---|---|
| name | A,B,C,D,E | full |
| image_path | A,B,C,E | full |
| exe | A,B,C,E | full (derived) |
| command_line | A,B,E | good (not C/D) |
| user | A,B | evtx-install only (run-as) |
| hostname | A,B,C,D | evtx only (not memory) |
| fqdn | A,B,C,D | evtx only, conditional |
| **pid** | **E only** | single-source |
| **ppid** | — | **no source** |
| **uid** | — | **no mapped source** |

8/10 fields have at least one live source; `ppid` and `uid` are structural no-sources.
Actions: `create` + (crash-only) `stop` mapped; `delete`/`pause`/`start` unmapped.
Real-evidence note: the light test set (`car.db`, EvtxECmd `unspecified_host`) contains **0**
service rows — the `windows.svcscan` plugin wasn't run in the memory image, and the EvtxECmd
sample carries none of the service EventIds. The maps are real; this evidence set is thin.

**UNMAPPED gaps, ranked by impact:**

1. **Registry `Services` key → the whole `service` object from a dead disk.** *Highest impact.*
   `plaso_registry` (F) and `recmd_batch` (G) already parse HKLM\...\Services and hold every
   field in `_native` (name, image_path, command_line, user/ObjectName, start_type,
   service_type, service_dll) — but emit **registry** objects. A dead-disk image yields **zero**
   `service` objects. A service-reconstruction map (or an enrichment pass over the registry
   native) would light up create for offline images.

2. **memory `svcscan` → running state → `start`/`stop` actions (and it is the sole `pid`).**
   svcscan is store-only (`action=None`). Its `State` (Running/Stopped) and `Start`
   (Auto/Demand/Disabled) are captured in native but not turned into an action, and it is the
   **only** source of `service.pid`. Deriving a `start` (or a live `stop`) from `State`, and
   propagating `pid`, would fill the running-instance gaps that evtx installs cannot.

3. **`delete` / `pause` actions — no source at all.** delete needs autoruns-diff or
   registry-key-removal detection; pause has no artefact. Genuine coverage holes.

4. **Autoruns (H) not wired.** CAR's canonical service create/delete sensor is absent from the
   engine; wiring an autoruns adapter would add the only current path to `service/delete`.

5. **`user` from registry `ObjectName`, and `uid`/`ppid`.** The registry run-as `ObjectName`
   is captured in native (F) but not promoted to `user`; `uid` and `ppid` have no clean source
   in any wired artefact (honest structural nulls).

---

## 6. File index (grounding)

- Semantics: `third_party/piiat-mitrecar/third_party/car/data_model/service.yaml`
- Canonical schema: `car_data_model.json` (object `service`); live `car.db` `service` table
- Maps (emit service): `third_party/piiat-mitrecar/piiat_mitrecar/mappings/evtx_windows.py`
  (7045/4697), `.../evtx_more.py` (20003, 7034); `third_party/piiat-mem/piiat_mem/mappings.py`
  (`windows.svcscan`)
- Maps (hold service facts, emit registry): `.../mappings/plaso_registry.py`, `.../mappings/recmd.py`
- Refusals: `.../mappings/evtx_extra.py` (7040), `evtx_windows.py:290` (7036)
- Sources (generated coverage): `sources/evtx_services.yaml`, `sources/evtx_more.yaml`,
  `sources/memory.yaml`
- Upstream (not wired): `.../car/sensors/autoruns_13.98.yaml`
- Relations/analytics: `docs/CAR-Relations.md` (R7 service→process, 20003/7034 counts);
  `.../car/analytics/CAR-2021-05-012.yaml` (Service:create, image_path),
  `CAR-2021-02-002.yaml` (service/create/command_line)
