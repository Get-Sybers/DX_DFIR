# CAR `registry` — Property-Provenance Catalogue

Authoritative, exhaustive map of **every canonical `registry` field → every artefact/source that can supply it** in the DX_DFIR pipeline. "Find once, done." Grounded in repo source, honest about gaps and honest nulls. READ-ONLY analysis.

- Object model (authoritative): `car_data_model.json` → `registry` fields = `data, fqdn, hive, hostname, image_path, key, new_content, pid, type, user, value`; actions = `add, key_edit, remove, value_edit`.
- Semantics: `third_party/piiat-mitrecar/third_party/car/data_model/registry.yaml`, `.../docs/data_model/registry.md`, OSSEM-CDM `.../OSSEM-CDM/schemas/entities/registry.yml`.

---

## 1. Field & action semantics (grounded)

| Field | CAR meaning (registry.yaml) | OSSEM-CDM analogue |
|---|---|---|
| `key` | The registry key path (folder-like). `HKLM\SYSTEM\CurrentControlSet\services\RpcSs` | `key_path` |
| `value` | Descriptive **name** of the data being stored. `InstalledVersion` | `value_name` |
| `data` | The **content** of `value`, typically a text string. | `value_data` |
| `type` | The data type of `value` (`REG_BINARY`, `REG_SZ`, `REG_DWORD`, …). | `value_type` |
| `hive` | The logical group of keys/subkeys/values. `HKEY_CURRENT_USER` | `hive_path` / `root_key` |
| `new_content` | Data within the new value, **or** the new name of a key, **after an edit**. | `value_data_modified` / `key_path_modified` |
| `image_path` | *Inherited from the process that made the access* — the WRITER's binary. | — |
| `pid` | *Inherited from the process that made the access* — the WRITER's pid. | — |
| `user` | The user in the context of the process that performed the action. | — |
| `hostname` | Host short name (no domain). | — |
| `fqdn` | Fully-qualified host name. | — |

**Action semantics** — `add` (create key/value), `remove` (delete), `value_edit` (edit a value's content), `key_edit` (edit a key's **name**; also used in this repo as the "snapshot" action for a whole-key state). MITRE has no `read` action for registry (a registry read event has **no canonical home** → raw).

**The load-bearing honesty rule** (`docs/CAR-Relations.md`, `car-store` §3, and every map's docstring): `image_path` / `pid` / `user` describe *the process that performed the write*. That process is recorded **only by a live event source** (Sysmon EID 12/13/14; Security 4657). A **dead hive** (Plaso winreg, RECmd, memory hive state) records the *resulting key/value state* but **not who wrote it** → `image_path`/`pid` are **honest nulls** on those sources; `user` is only recoverable as the **hive owner** (from an `NTUSER.DAT`/`UsrClass.dat` path), which is a different semantic (whose hive, not who wrote).

---

## 2. Source universe (every registry-capable source in the repo)

| Code | Source → CAR route | Map file | Actions produced | Status |
|---|---|---|---|---|
| **SYS12** | Sysmon EID 12 *RegistryEvent (Object create/delete)* via EvtxECmd `evtx_sysmon` | `piiat-mitrecar/piiat_mitrecar/mappings/sysmon.py` | `add` (Create\*), `remove` (Delete\*) | **ACTIVE** |
| **SYS13** | Sysmon EID 13 *RegistryEvent (Value Set)* | `sysmon.py` | `value_edit` | **ACTIVE** |
| **SYS14** | Sysmon EID 14 *RegistryEvent (Key/Value Rename)* | `sysmon.py` | `key_edit` | **ACTIVE** |
| **SEC4657** | Security **4657** *registry value modified* | `piiat-mitrecar/to-be-validated/evtx_audit.yml` (spec) | `add`/`value_edit`/`remove` (by `OperationType`) | **QUARANTINED — NOT active** |
| **PLREG** | Plaso `winreg` (all `windows:registry:*` key/value plugins: run, services, userassist, bam, amcache, shellbags, usb, sam, typedpaths, MRU, …) `plaso_registry` | `plaso_registry.py` | `key_edit` (whole-key snapshot) | **ACTIVE** |
| **RECMD** | EZ-Tools **RECmd** batch (`--json`) `recmd_batch` | `recmd.py` | `value_edit` (live records; `Deleted:true` → raw) | **ACTIVE** |
| **MEM** | Volatility3 `windows.piiat.registry` (printkey + hivelist, RECmd-style target list) → PIIAT-Mem CAR passthrough | plugin `piiat-mem/plugins/windows/piiat/registry.py`; map `piiat-mem/piiat_mem/mappings.py` | `value_edit` | **ACTIVE** |
| **AUTORUNS** | Sysinternals Autoruns (`autoruns_13.98`) | — | (MITRE lists add/key_edit/value_edit) | **NO SOURCE in repo** (honest no-source) |
| **REGRIPPER** | RegRipper | — | — | **NO SOURCE in repo** (honest no-source) |
| **SEC4663/4660** | Security 4663 (Key access) / 4660 (object deleted) | 4663-File only in `evtx_audit.yml`; Key path → raw | none for registry | **NO registry mapping** (honest — see §5) |

Notes carried from source:
- **PLREG value/data/type live in a `values` LIST** the declarative marker set cannot index → they stay in `_native.values`; only `key`/`hive`/`image_path`/`hostname` are canonical columns. So PLREG cannot populate `value`/`data`/`type` as columns even though the data is present.
- **PLREG `image_path`** = the winreg record's `image_path` (present on **service** rows: the configured `svchost`/service binary). This is the *configured* binary, **not** the process that wrote the key — a field-name near-collision; see caveats.
- **PLREG `key_edit`** is a **semantic overload**: a registry snapshot = the key as it exists at its `LastWrite`, mapped to `key_edit` (not a literal rename). SYS14 `key_edit` *is* a literal rename.
- **MEM** host identity: PIIAT-Mem's CAR layer stamps `hostname`/`fqdn` from the in-memory `ComputerName` (and `Tcpip\Parameters`) registry values — the plugin deliberately captures those; the memory registry rows themselves carry `Hive/Key/ValueName/ValueType/ValueData/LastWrite` only.
- **Evidence grounding**: memory sample `data_store/processed/volatility/memdump.mem/plugins/windows.piiat.registry.jsonl` confirms native fields `Hive, Key, ValueName, ValueType, ValueData, LastWrite`. (No live Sysmon-13 / plaso-winreg registry rows in the current sampled processed corpus — field names below are grounded in map code + generated `sources/*.yaml`, which are introspected from the maps.)

---

## 3. Per-field provenance (the catalogue)

Legend: **Mapped?** = yes (+map location) / NO. **Conf** = confidence the field is faithfully populated.

### `key` — the registry key path (the universal strongest field; every source supplies it)

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| SYS12 → `TargetObject` | add, remove | yes — `sysmon.py:_registry_props` (`key: payload("TargetObject")`) | High — full path. |
| SYS13 → `TargetObject` | value_edit | yes — `sysmon.py:_registry_props` | High, **caveat**: for a value event the path **includes the value-name segment** (KQL shape kept); the bare value is split into `value`. |
| SYS14 → `TargetObject` | key_edit | yes — `sysmon.py` | High. |
| SEC4657 → `ObjectName` | add, value_edit, remove | **NO** (quarantined `evtx_audit.yml`) | High once audit enabled. |
| PLREG → `key_path` | key_edit | yes — `plaso_registry.py` (`key: _R("key_path")`) | High. |
| RECMD → `KeyPath` | value_edit | yes — `recmd.py` | High. |
| MEM → `Key` | value_edit | yes — `mappings.py:windows.piiat.registry` | High — in-memory path (may be `\REGISTRY\MACHINE\SYSTEM\…` NT form). |

### `value` — the value name (value-level sources only)

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| SYS13 → `basename(TargetObject)` | value_edit | yes — `sysmon.py` (`with_value=True`) | Med-High — derived by taking the last path segment; EID 13 is always a value so the split is safe. |
| SEC4657 → `ObjectValueName` | add, value_edit, remove | **NO** (quarantined) | High. |
| RECMD → `ValueName` | value_edit | yes — `recmd.py` | High. |
| MEM → `ValueName` | value_edit | yes — `mappings.py` | High — `""` (default value) is a legitimate identity component. |
| PLREG → in `values` LIST → `_native.values` | key_edit | **NO** (native only) | Honest null-as-column — data present but the marker set can't index a list; not promoted. |
| SYS12 / SYS14 | — | n/a | Key-level events carry no value. |
| AUTORUNS → (value) | add/key_edit/value_edit | **NO SOURCE** | MITRE lists Autoruns for `value`; not ingested here. |

### `data` — the content of the value

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| SYS13 → `Details` | value_edit | yes — `sysmon.py` (`with_data=True`) | High. |
| SEC4657 → `NewValue` | add, value_edit, remove | **NO** (quarantined) | High. |
| RECMD → `first(ValueData, ValueData2, ValueData3)` | value_edit | yes — `recmd.py` | High — coalesces RECmd's multi-slot value rendering. |
| MEM → `ValueData` | value_edit | yes — `mappings.py` | High — bytes rendered hex; **truncated to 2048 chars** in the plugin. |
| PLREG → in `values` LIST → `_native.values` | key_edit | **NO** (native only) | Honest null-as-column (list, unindexable). |
| SYS12 / SYS14 | — | n/a | No value content on key events. |

### `type` — the value data type (REG_SZ, REG_DWORD, …)

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| RECMD → `ValueType` | value_edit | yes — `recmd.py` (promoted to canonical column) | High. |
| MEM → `ValueType` | value_edit | yes — `mappings.py` | High. |
| SEC4657 → `NewValueType` | add, value_edit | **NO** (quarantined) | High. |
| PLREG → in `values` LIST → `_native.values` | key_edit | **NO** (native only) | Honest null-as-column. |
| SYS13 | — | **NO** | **Honest no-source** — Sysmon carries no value type (map comment: "type/hive: Sysmon gives neither"). |
| SYS12 / SYS14 | — | n/a | — |

### `hive` — the logical hive

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| RECMD → `HiveType` | value_edit | yes — `recmd.py` | High — RECmd's normalized hive designation. |
| MEM → `Hive` | value_edit | yes — `mappings.py` | High — NT form `\REGISTRY\MACHINE\SYSTEM`. |
| PLREG → `display_name` | key_edit | yes — `plaso_registry.py` | **Med** — this is the **hive FILE path** (Plaso `display_name`), i.e. the containing hive rendered as a file path, not the `HKEY_*` root symbol. |
| SEC4657 | — | **NO** (quarantined) | 4657's `ObjectName` embeds the root but no separate hive field; quarantine spec does not set `hive` → honest null. |
| SYS12 / SYS13 / SYS14 | — | **NO** | **Honest no-source** — Sysmon gives no hive (map: `""` placeholder → null). |

### `new_content` — data/key-name after an edit

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| SYS13 → `Details` | value_edit | yes — `sysmon.py` (`new_content = Details`) | High — the row IS the value_edit; `Details` is the written data = exactly `new_content`. |
| SEC4657 → `NewValue` | value_edit, add | **NO** (quarantined) | High — 4657 explicitly carries `OldValue`→native + `NewValue`→`new_content`. |
| RECMD → `first(ValueData, ValueData2, ValueData3)` | value_edit | yes — `recmd.py` | Med — snapshot convention: the value's *current* content is treated as `new_content` (parity w/ Sysmon map); "which value changed last is not per-value attributable" caveat rides with the action. |
| MEM → `ValueData` | value_edit | yes — `mappings.py` | Med — same snapshot convention (resident data = content after the last edit). |
| SYS14 → `NewName` | key_edit | **NO** (kept **native**, not mapped to `new_content`) | **GAP** — `NewName` is literally the new key name after a rename = the `new_content` key-name semantic; currently surfaced only in `native_extract`. Promotable. |
| PLREG | — | n/a | Snapshot has no "after" state (no prior value recorded). |

### `image_path` — the WRITER's binary (live-event sources only)

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| SYS12 / SYS13 / SYS14 → `Image` | add, remove, value_edit, key_edit | yes — `sysmon.py:_registry_props` (`image_path: payload("Image")`) | High — the true process that made the registry access. |
| SEC4657 → `ProcessName` | add, value_edit, remove | **NO** (quarantined) | High — the writer process image. |
| PLREG → `image_path` | key_edit | yes — `plaso_registry.py` | **LOW / semantic caveat** — populated only on **service** rows, and it is the **configured** service binary (`svchost`/ImagePath value), **NOT** the process that wrote the key. A field-name near-collision; treat as key content, not writer provenance. |
| RECMD | — | **NO** | **Honest no-source** — dead hive; writer not recorded. |
| MEM | — | **NO** | **Honest no-source** — in-memory hive state; writer not recorded. |

### `pid` — the WRITER's pid (live-event sources only)

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| SYS12 / SYS13 / SYS14 → `ProcessId` | add, remove, value_edit, key_edit | yes — `sysmon.py` | High. (Also surfaced as `owning_pid`/`owning_guid` tier-1 link.) |
| SEC4657 → `hex_int(ProcessId)` | add, value_edit, remove | **NO** (quarantined) | High — 4657's ProcessId is hex; quarantine spec converts. |
| PLREG | — | **NO** | **Honest no-source** — dead hive. |
| RECMD | — | **NO** | **Honest no-source** — dead hive. |
| MEM | — | **NO** | **Honest no-source** — memory hive state (no writer). |

### `user` — user context of the writing process

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| SYS12 / SYS13 / SYS14 → `User` | add, remove, value_edit, key_edit | yes — `sysmon.py` | Med-High — **absent pre-v11 Sysmon** on registry events → honest null then. |
| SEC4657 → `SubjectUserName` | add, value_edit, remove | **NO** (quarantined) | High — the writer's account. |
| RECMD → the `<name>` captured from the hive's `...\Users\<name>\...` path | value_edit | yes — `recmd.py` | **Med** — the **hive owner** from a per-user hive path (`Users/<name>`); **system hives → null**. Owner ≠ necessarily the writer. |
| MEM → `user_from_hive(Hive)` | value_edit | yes — `mappings.py` | **Med** — hive owner from `NTUSER.DAT`/`UsrClass.dat`; system hives → null. Same owner≠writer caveat. |
| PLREG → `username` / `hive_user_sid` (regex `S-1-5-21-…`) surfaced **native** | key_edit | **NO** (native only) | **GAP-ish** — SID/username are recovered into `_native` for the end-stage user-attribution join, but the canonical `user` column stays null. Promotable via the hive-owner convention. |

### `hostname`

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| SYS12 / SYS13 / SYS14 → `Computer` (first DNS label) | all | yes — `sysmon.py` (`_HOSTNAME`) | High. |
| SEC4657 → `host_label(Computer)` | — | **NO** (quarantined) | High once enabled. |
| PLREG → `image_hostname` | key_edit | yes — `plaso_registry.py` (`hostname: _R("image_hostname")`) | High — image identity stamped by the lane. |
| MEM → in-memory `ComputerName` (PIIAT-Mem CAR layer) | value_edit | yes (passthrough) | Med — sole memory-native host source; depends on the `ComputerName` key being resident (the plugin targets it explicitly). |
| RECMD | — | **NO** | **GAP / honest null** — `recmd.py` sets no `hostname`; the RECmd record carries no host stamp (would need out-of-band image context). |

### `fqdn`

| Source → native field | Action(s) | Mapped? | Conf & caveats |
|---|---|---|---|
| SYS12 / SYS13 / SYS14 → `Computer` (only if it contains a dot) | all | yes — `sysmon.py` (`_FQDN`) | Med — claimed **only** when `Computer` is genuinely an FQDN; a bare NetBIOS name → honest null (never faked). |
| SEC4657 → the label of `Computer` up to the first dot | — | **NO** (quarantined) | Med — same discipline. |
| MEM → `Tcpip\Parameters` Hostname/Domain/DhcpDomain (PIIAT-Mem CAR layer) | value_edit | yes (passthrough, tool-defined) | Med/unknown — the plugin captures `Tcpip\Parameters` for fqdn; whether the CAR layer emits `fqdn` is defined by PIIAT-Mem (passthrough source). |
| PLREG | — | **NO** | **Honest no-source** — `image_hostname` is a bare name; no domain recorded. |
| RECMD | — | **NO** | **Honest no-source.** |

---

## 4. Coverage matrix — source × action (which sources fire which action)

| Action | SYS12 | SYS13 | SYS14 | SEC4657 | PLREG | RECMD | MEM |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| `add` | ✅ | — | — | ⛔quar | — | — | — |
| `remove` | ✅ | — | — | ⛔quar | — | ⛔(Deleted→raw) | — |
| `key_edit` | — | — | ✅(rename) | — | ✅(snapshot) | — | — |
| `value_edit` | — | ✅ | — | ⛔quar | — | ✅ | ✅ |

✅ = active mapped · ⛔quar = spec exists but quarantined/inactive · ⛔ = deliberately raw · — = source cannot produce that action.

**Best-covered field**: `key` (all 6 active/quarantined sources). **Thinnest actions**: `add` and `remove` — each has exactly **one active source** (SYS12) plus the quarantined 4657.

---

## 5. Honest no-source / deliberately-raw (not gaps to "fix")

- **Registry `read`** — MITRE has no read action for registry. Security **4663 (ObjectType=Key)** and **4656/4658** key-access events therefore have **no canonical home → raw** (the `evtx_audit.yml` 4663 map is gated `ObjectType=='File'`; a Key access falls through). This is correct, not a gap.
- **4660 (object deleted) for a registry key** — 4660 carries no `ObjectName` (path lives in the paired 4656/4663 by `HandleId`); the quarantine maps 4660 → **file/delete** only. Recovering a registry `remove` from 4660+4663-Key correlation is **not implemented** (and would need the audit subcategory anyway).
- **RECmd `Deleted:true`** records (recovered from unallocated) → **raw**: the deletion happened but its *time* is unknowable, so `remove` at the key's last-write would assert a time the evidence lacks.
- **Autoruns / RegRipper** — MITRE's own `registry.yaml` coverage_map credits `autoruns_13.98` for add/key_edit/value_edit, but **neither tool is ingested in DX_DFIR** → honest no-source here.
- **PLREG value/data/type as columns** — present in evidence but structurally unindexable (`values` list) → native-only by design.

---

## 6. Summary — coverage & ranked UNMAPPED gaps

**Active coverage (what works today):**
- Live writer events: **SYS12/13/14** give the full live picture including the WRITER (`image_path`/`pid`/`user`) — the only sources that do. SYS13 is the richest single row (`key`,`value`,`data`,`new_content`,`image_path`,`pid`,`user`,`hostname`,`fqdn`).
- Dead-hive state: **PLREG** (every `windows:registry:*` → `key_edit`, hundreds of thousands of rows on M57), **RECMD** and **MEM** (per-value → `value_edit` with `hive`/`value`/`data`/`type`/`new_content`/`user`).
- Every field has ≥1 active source **except** those that are honest no-sources per source.

**Ranked UNMAPPED gaps (highest value first):**

1. **Security 4657 (registry value modified) — QUARANTINED, not active.** The single biggest gap. It is the **only non-Sysmon LIVE source of a registry write**, and it supplies the full high-value set with true writer provenance: `key`←ObjectName, `value`←ObjectValueName, `data`/`new_content`←NewValue, `type`←NewValueType, `image_path`←ProcessName, `pid`←ProcessId, `user`←SubjectUserName, and — via `OperationType` 1904/1905/1906 — **`add`/`value_edit`/`remove`** (would more than double `add`/`remove` source coverage). Multiple CAR analytics (CAR-2021-11-002, CAR-2021-11-001, CAR-2022-03-001, CAR-2021-12-002) key on 4657 `ObjectValueName`/`ObjectName`. Blocker: needs a real audit-enabled capture to validate the `OperationType`→action decisions. Spec is complete in `to-be-validated/evtx_audit.yml`. **Promote when validated.**

2. **SYS14 `NewName` → `new_content` (key rename).** Trivial, live, high-confidence. The rename target is already extracted (native `NewName`) but not promoted to the canonical `new_content` column — the exact key-name-after-edit semantic the field is defined for. One-line map change; no new evidence needed.

3. **PLREG `value` / `data` / `type` trapped in the `values` list.** These populate three canonical columns for the largest registry corpus (disk hives), currently native-only because the declarative marker can't index a list. Would require an engine change (list-flattening / per-value row explosion), but the payoff is large (value/data/type columns across all disk registry state).

4. **PLREG `user`** — `hive_user_sid`/`username` are recovered into native but the canonical `user` column stays null. Promotable via the same hive-owner convention RECMD/MEM already use (honest "hive owner, not writer" caveat).

5. **RECMD `hostname`** — null (no host stamp in the RECmd record). Minor; would need image-context injection at ingest, not derivable from the record alone.

6. **`add`/`remove` breadth.** Even with everything above, `add` and `remove` remain **live-event-only** actions (SYS12 active; 4657 once promoted). No dead-hive source can legitimately produce them (a snapshot cannot distinguish creation from edit; a deleted key isn't in the hive). This is a truth of the evidence, not a fixable gap — worth stating so nobody tries to synthesise `add`/`remove` from Plaso/RECmd/memory.

**No-source (correct, do not "fix"):** registry `read` (no CAR action), 4663/4656/4660-Key for registry, Autoruns/RegRipper (not ingested), RECmd `Deleted` records.
