# GUID cross-artefact linkage hunt — DX_DFIR processed dataset

READ-ONLY scan (rg / python sqlite3). Repo `/opt/github/DX_DFIR`, tree `data_store/processed/`.

## Dataset reality: three distinct hosts (linkage is WITHIN a host)
The processed tree mixes three unrelated images. A GUID converges *inside* one host's
artefacts; it does not (and should not) cross between them.

| host / identity | lane(s) | anchor evidence |
|---|---|---|
| **LoneWolf disk `DESKTOP-PM6C56D`** (user `jcloudy`) | `log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (6.6 GB, plaso) | MachineGuid `8b9b9f31-6016-4b10-83ef-324b62a37898`; Dropbox tasks "Scheduled by DESKTOP-PM6C56D\jcloudy" |
| **Sysmon host `DESKTOP-M913391`** (user `JDH`, Korean locale) | `windows_logs/unspecified_host/log_EvtxECmd_Output.json`; `signatures/hayabusa/timeline.jsonl` | Sysmon ProcessGuid prefix `a7738ffd-…`; Chrome |
| **Memory host** (SID base `S-1-5-21-2899045035-919344695-3383792992`, RIDs 500/1000/1001) | `volatility/memdump.mem/plugins/*.jsonl` + `car.db` | FTK Imager 4.7.1 run from `Temp\{787A8B0F-B810-41D6-BA41-4289DB167E05}` |
| **Linux `5g-webui`** | `log2timeline/jsonl/5g-webui.jsonl` (7.8 GB) | 679 app/5G-NF UUIDs only |

Confirmed isolation: LoneWolf MachineGuid + volume GUID appear **0** times in the memory lane.

## The platform's GUID model (what IS and ISN'T normalised)

**CAR is the normalisation target.** `car.db` (the volatility lane) has 14 CAR tables, every
one sharing the header `guid, owning_guid, parent_guid` (process adds `target_guid`) plus a
`native` blob. Per `detect/rules/car-detections/join-keys.yml`, the CAR `guid` is the ONE join
key: it travels to Elastic as ECS `event.id` on every object and as `process.entity_id` on
process/its children, and `LOOKUP JOIN car-detections ON event.id|process.entity_id` is the
whole cross-source convergence contract.

**Decisive finding — the CAR GUID columns hold ZERO canonical GUIDs.** Of **44,327** non-null
values across `guid/owning_guid/parent_guid/target_guid`, **none** are `{8-4-4-4-12}` shaped.
Every value is a minted synthetic entity id:

- `proc-800acda8c040` (process, from memory offset), parent link `parent_guid = proc-800ad4095200`
- `file-…`, `registry-…`, `user_session-…` prefixes for the other objects.

So the only GUIDs the engine *normalises/joins on* are the ones it **mints itself** (offset/uuid5
entity ids; STIX side uses `uuid5(DX_NAMESPACE 518ade0c-8157-5d44-a810-9563a8af74ef,…)` and the
SCO namespace `00abedb4-…`). Every **native** canonical GUID — MachineGuid, volume, CLSID,
interface, task, and even Sysmon ProcessGuid — survives ONLY inside `native`/`value`/`data`/
`message` text and is invisible to any CAR join. That is the unmined surface.

Worse, the existing `owning_guid` linkage is barely populated in this data: `user_session`
resolves 9/9 to a process, but **registry (12,171 rows) and file (31,828 rows) carry NO
owning_guid at all** (`link_confidence = NULL`). So a registry hive value and the process that
wrote it are not linked even by the synthetic key — and the canonical GUID that could bridge
them is thrown away too.

## High-value GUID classes

| guid class | example value (real) | artefacts it links (lanes / data_types) | normalised to a CAR field? | convergence opportunity |
|---|---|---|---|---|
| **MachineGuid** (host identity) | `8b9b9f31-6016-4b10-83ef-324b62a37898` (LoneWolf, `HKLM\Software\Microsoft\Cryptography`) | plaso `windows:registry:key_value` (3) + `windows:evtx:record` (52) + `fs:stat` (48 — a `\Windows\System32\restore\MachineGuid.txt` was dropped on disk) = **3 data_types** | **No** — only in registry value / evtx payload / filename text | The single per-host join key; should be lifted to `host.id` and stamped on every CAR row for that image |
| **Volume GUID** (`\\?\Volume{…}`) | `{09931f21-7faf-44a9-81d8-1e73c14b9eaf}` (2,208×, main sys volume; note mixed-case `09931F21…`) | plaso `windows:evtx:record` (1082) + `windows:registry:key_value` (34) + `fs:ntfs:usn_change` (14) + `fs:stat` (12) + `google_drive_sync_log:entry` (5) + `windows:registry:mount_points2` (2) = **6 data_types** | **No** | Best cross-source key on the box — ties USN journal ↔ event log ↔ registry ↔ cloud-sync ↔ mount table. MountPoints2 (`{3869c27a-31b8-11e8-9b12-ecf4bb487fed}`) binds it to HKCU (user) + drive letter + USB |
| **DLT birth-droid** (LNK object/volume id, v1) | `5c2307d9-3369-11e2-be70-001cc42df40b` (node = MAC **00:1C:C4:2D:F4:0B**) | plaso `windows:lnk:link` (96) + `windows:distributed_link_tracking:creation` (32) = **2 data_types** | Partly — plaso keeps its own `uuid` field, but not into CAR, and the **embedded MAC is never extracted** | File-access provenance: which volume/machine a LNK's target was born on; the v1 node leaks the origin NIC MAC |
| **Sysmon ProcessGuid** | `a7738ffd-09de-65aa-9f08-000000004900` | EvtxECmd `windows:evtx:record` — links Sysmon EID1↔EID5 (and EID3/7/11/22 in fuller logs); host-boot prefix `a7738ffd` shared by all 50 on `DESKTOP-M913391` | **No** (no evtx→CAR lane here; and CAR process `guid` is the memory `proc-<offset>`, a different id-space) | The native process-lineage key; if an evtx→CAR projection existed it should map ProcessGuid→`process.entity_id`, giving memory↔evtx process identity |
| **Sysmon ParentProcessGuid** | `a7738ffd-ba54-65a9-0703-000000004900` (Chrome parent → many renderer children) | EvtxECmd EID1 (45) | **No** | Direct analogue of CAR `parent_guid`; native parent/child tree that CAR leaves un-lifted |
| **Sysmon LogonGuid** | present on 45 EID1 records | EvtxECmd | **No** | Ties a process to its logon session (Security EID4624) — the user_session bridge CAR wants |
| **Network interface GUID** | `{0397C57D-9E0C-4051-896B-F9C998129138}` (`…\Tcpip\Parameters\Interfaces\{…}`) | plaso registry (Tcpip, DHCP) ↔ NetworkList profiles/signatures | **No** | Binds a NIC/IP/DHCP-lease/SSID-profile together; a network-identity join key |
| **Scheduled-task GUID** | `{0319D346-9E60-4CE2-B937-EF6C981CC0F1}` (`…\Schedule\TaskCache\Tasks\{…}`) | plaso registry `TaskCache\Tasks` ↔ `TaskCache\Tree` (name→GUID) | **No** | Persistence: links a task's definition, tree entry and action; pairs with the `windows:tasks:job` action rows (Dropbox jobs) |
| **CLSID / interface IID / TypeLib / AppID** (COM) | `f750e6c3-38ee-11d1-85e5-00c04fc295ee` (118k×); OLE `…-c000-000000000046` family = 1,623 distinct | plaso `pe_coff:file`, `REG_SZ`, `windows:registry:key_value`, `olecf:*` | No | **Background noise** — ubiquitous on every Windows box; suppress from linkage, use only for tool/version fingerprinting |
| **CAR minted entity id** (already the join key) | `proc-800acda8c040`; `parent_guid=proc-800ad4095200` | `car.db` all tables → ECS `event.id`/`process.entity_id` | **Yes (this IS the CAR guid)** | Working; but registry/file rows lack `owning_guid`, so the tree is incomplete |
| **Analysis-tool GUID** | `{787A8B0F-B810-41D6-BA41-4289DB167E05}` (FTK Imager 4.7.1 temp dir, memory host BAM) | memory `car.db` registry `native` | No | Anti-forensic / examiner-activity marker; flag but exclude from evidentiary linkage |
| **Linux app / 5G-NF UUIDs** | `f3050758-9f78-493d-a53f-89ec5ecd6b3c` (92k×) | `5g-webui.jsonl` only (679 distinct) | No (no Linux→CAR lane) | Request/session correlation within the webui; not cross-artefact |

## Top cross-artefact links found on REAL data (the wins)

1. **Volume `{09931f21-7faf-44a9-81d8-1e73c14b9eaf}` → 6 data_types.** Same volume id in the USN
   change journal, event log, registry, filesystem stat, **Google Drive sync log** (5 rows), and
   MountPoints2. One `LOOKUP … ON volume_id` would fuse disk activity, cloud exfil-sync and the
   Windows logs for the LoneWolf case. *No CAR field carries it.*
2. **MachineGuid `8b9b9f31-…` → registry + evtx + a `MachineGuid.txt` file on disk.** The host
   identity is provably the same across three artefact types; ideal `host.id` seed.
3. **DLT droid `5c2307d9-3369-11e2-be70-001cc42df40b` → LNK ↔ DLT.** 96 LNK rows + 32 DLT
   creations share the id; its v1 node **leaks NIC MAC 00:1C:C4:2D:F4:0B** — origin-machine
   attribution for files opened via those shortcuts (Windows PowerShell.lnk, …).
4. **Sysmon ProcessGuid `a7738ffd-…` chains EID1↔EID5**, and ParentProcessGuid
   `a7738ffd-ba54-65a9-0703-000000004900` is a Chrome parent fanning out to ~dozen renderer
   children — a native process tree that never reaches CAR. **hayabusa drops ProcessGuid
   entirely** (0 hits for `a7738ffd` in `timeline.jsonl`) → normalised-away linkage.
5. **v1 volume GUID `{3869c27a-31b8-11e8-9b12-ecf4bb487fed}` leaks a real Dell MAC
   `EC:F4:BB:48:7F:ED`**; sibling `{5c3108bb-31c0-11e8-9b10-806e6f6e6963}` uses the synthetic
   `80:6E:6F:6E:69:63` placeholder — MAC recovery straight from the GUID node.
6. **SanDisk Extreme USB** (serials `AA010215170355310594`, `AA010603160707470215`) occur **2,470×**
   across USBSTOR / MountedDevices / EMDMgmt, tying the device to volume GUIDs (device-instance
   id, not GUID-shaped — the USB↔volume bridge is a serial, and it too is un-normalised).

## Unmined GUIDs (present in raw/native, promoted to NO CAR field)

- **Every canonical GUID class above** — MachineGuid, volume, DLT, ProcessGuid/Parent/Logon,
  interface, task, CLSID. Confirmed: 44,327 CAR guid-column values, 0 canonical.
- **1,280 registry rows in `car.db`** carry canonical GUIDs only in `key`/`value`/`data` text
  (WppRecorder TraceGuids, BFE provider GUIDs, VideoID `{4614AA7F-A256-11ED-…}`, BthAvctp
  profile GUIDs) — none lifted, and those registry rows also have no `owning_guid`.
- **LoneWolf plaso**: 60,957 distinct GUIDs / 2.9M occurrences (v4 33,593 · v3 10,293 · v5 6,932 ·
  **v1 6,218 = the MAC-bearing set** · nil family 12,216 occ). Only the minted `proc-*` ids are
  queryable; the rest are lexical.
- **The MAC embedded in every v1 GUID** (DLT + `…-11e2-`/`-11e8-` volume/interface GUIDs) — never
  decoded into a `mac_address`-style field except in the one DLT data_type.
- **Linux 5g-webui**: all 679 UUIDs unmined (no Linux CAR lane at all).

## YARA rule stubs (systematically flag these across future datasets)

```yara
rule GUID_MachineGuid_HostIdentity {
    meta:
        desc = "HKLM\\Software\\Microsoft\\Cryptography MachineGuid — per-host identity join key"
        author = "dxdfir car-crosslink"
    strings:
        $k  = "Microsoft\\Cryptography" nocase
        $v  = "MachineGuid" nocase
        $re = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/
    condition:
        $k and $v and $re
}

rule GUID_Volume_MountKey {
    meta: desc = "\\?\\Volume{GUID} / MountedDevices / MountPoints2 volume identity (case-insensitive)"
    strings:
        $vol = /Volume\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}/ nocase
        $mp2 = "MountPoints2" nocase
        $md  = "MountedDevices" nocase
    condition:
        $vol and ($mp2 or $md or #vol > 1)
}

rule GUID_V1_MAC_Embedded {
    meta: desc = "Version-1 (time/MAC) GUID — node bytes leak originating NIC MAC (DLT birth-droid, v1 volume/interface GUIDs)"
    strings:
        // 3rd group starts with 1 (v1); excludes the c000-...-46 COM family and the 806e6f6e6963 placeholder
        $v1 = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-1[0-9a-fA-F]{3}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/
    condition:
        $v1 and not ($v1 matches /-c000-000000000046/)   // pseudo; in practice post-filter node != 806e6f6e6963
}

rule GUID_Sysmon_ProcessLineage {
    meta: desc = "Sysmon ProcessGuid / ParentProcessGuid / LogonGuid — native process+logon lineage (map to process.entity_id)"
    strings:
        $pg  = "ProcessGuid" nocase
        $ppg = "ParentProcessGuid" nocase
        $lg  = "LogonGuid" nocase
        $re  = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/
    condition:
        any of ($pg,$ppg,$lg) and $re
}

rule GUID_ScheduledTask_Persistence {
    meta: desc = "TaskCache\\Tasks|Tree {GUID} — scheduled-task persistence linkage"
    strings:
        $tc = "TaskCache" nocase
        $g  = /\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}/
    condition:
        $tc and $g
}

rule GUID_NetworkInterface_Identity {
    meta: desc = "Tcpip\\Parameters\\Interfaces\\{GUID} / NetworkList profile GUID — NIC/IP/SSID join key"
    strings:
        $if = "Tcpip\\Parameters\\Interfaces" nocase
        $nl = "NetworkList\\Profiles" nocase
        $g  = /\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}/
    condition:
        ($if or $nl) and $g
}

rule GUID_AntiForensic_ImagingTool {
    meta: desc = "Forensic/imaging tool artefacts (FTK Imager temp GUID dir, examiner activity)"
    strings:
        $ftk = "FTK_Imager" nocase
        $ad  = "AccessData" nocase
        $tmp = /Temp\\\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}/ nocase
    condition:
        ($ftk or $ad) and $tmp
}

// Case-specific HUNT rule — pin the concrete LoneWolf identifiers for retro-sweep across any future acquisition
rule HUNT_LoneWolf_DESKTOP_PM6C56D {
    meta: desc = "LoneWolf host DESKTOP-PM6C56D / jcloudy identity constants"
    strings:
        $machine = "8b9b9f31-6016-4b10-83ef-324b62a37898" nocase
        $vol     = "09931f21-7faf-44a9-81d8-1e73c14b9eaf" nocase
        $droid   = "5c2307d9-3369-11e2-be70-001cc42df40b" nocase
        $mac     = { 00 1C C4 2D F4 0B }
        $host    = "DESKTOP-PM6C56D" nocase
    condition:
        any of them
}
```

### Concrete recommendations for the pipeline
1. Lift **MachineGuid → `host.id`** and stamp it on every CAR row of that image (the missing
   per-host anchor).
2. Add a **volume-GUID join key** (`\\?\Volume{…}`, case-folded) as a first-class CAR field — it
   already converges 6 data_types on real data.
3. In any evtx→CAR projection, map **Sysmon ProcessGuid→`process.entity_id`,
   ParentProcessGuid→`parent_guid`, LogonGuid→a user_session key** (mirrors what CAR already does
   with minted ids) — and stop hayabusa from dropping ProcessGuid.
4. **Decode the v1-GUID node into a `mac_address` field** for DLT/volume/interface GUIDs.
5. Populate **`owning_guid` on registry/file CAR rows** (currently NULL) so the synthetic tree is
   whole; the canonical GUIDs inside those rows are the bridge material.
