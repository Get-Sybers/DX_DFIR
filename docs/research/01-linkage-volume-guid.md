# Step 01 — Volume GUID as a first-class join key (B1)

> Part of the CAR cross-source linkage & detection research arc — see [README](README.md) for the full map.

**Status:** merged (PIIAT-MitreCar#57, PIIAT-MitreCar#58/#59)

## The gap

CAR's `guid` is the one cross-source join key: it travels to Elastic as ECS
`event.id` on every object and `process.entity_id` on process rows, and
`LOOKUP JOIN car-detections ON event.id|process.entity_id` is the entire
convergence contract (`detect/rules/car-detections/join-keys.yml`).

The cross-dataset value hunt ([`../car-provenance/crosslink/`](../car-provenance/crosslink/))
found that key holds **nothing real**. Of **44,327** non-null values across the
CAR `guid`/`owning_guid`/`parent_guid`/`target_guid` columns, **zero** are
canonical `{8-4-4-4-12}` GUIDs — every value is a synthetic id the engine mints
itself (`proc-…`, `file-…`). So no MachineGuid, no volume GUID, no Sysmon
ProcessGuid is ever promoted to a queryable field; the real cross-source keys
survive only as text inside `native`. The single strongest such key on a disk
image is the volume GUID (`\\?\Volume{GUID}`), and it was entirely un-mined.

## What we found

One volume id — `{09931f21-7faf-44a9-81d8-1e73c14b9eaf}`, the LoneWolf main
system volume, seen **2,208×** — ties **6 data_types** together on real data
(see [`crosslink/guids.md`](../car-provenance/crosslink/guids.md)):

| data_type | rows |
|---|---:|
| `windows:evtx:record` (event log) | 1082 |
| `windows:registry:key_value` | 34 |
| `fs:ntfs:usn_change` (USN change journal) | 14 |
| `fs:stat` | 12 |
| `google_drive_sync_log:entry` (cloud-sync) | 5 |
| `windows:registry:mount_points2` | 2 |

One `LOOKUP … ON volume_id` fuses disk activity, the Windows logs, the mount
table and cloud exfil-sync for the case — but no CAR field carried it. The catch:
the value appears mixed-case in the wild (`09931F21…` / `09931f21…`), and a naive
GUID grab would drown in the ubiquitous COM CLSID / interface-IID GUIDs
(e.g. `f750e6c3-…` at 118k× — pure linkage noise present on every Windows box).

## The fix

**PR PIIAT-MitreCar#57** added a `definitive_native_id` convergence tier in `crosssource.py`
that mines `Volume{GUID}` out of `native`. It is token-gated so the COM
CLSID/interface GUID families are never picked up, case-folded so the real
mixed-case values collapse to one key, and host- and object-independent.

**PR PIIAT-MitreCar#58/#59** promoted `volume_guid` to a first-class **nullable header column**
on every CAR object:
- a shared extractor lives in `native_ids.py`;
- `enrich` lifts it **fill-only-null** (never overwrites an existing value);
- the CAR model snapshot was regenerated to include the new header;
- it projects to a custom `car.volume_guid` field — ECS 8.11 has no
  volume-GUID field (verified), so the cross-object key homes in the custom
  namespace.

## What it enables

The volume GUID is now both a **queryable column** and a **cross-source join
key**. A registry mount entry, a USN change-journal record and an event-log row
that name the same volume converge on one key — the best bridge available on a
disk image, previously thrown away.

## Follow-ups

The rest of B1 remains open (tracked in
[`crosslink/SUMMARY.md`](../car-provenance/crosslink/SUMMARY.md)):
- lift **MachineGuid → `host.id`** and stamp it on every CAR row of the image;
- in an evtx→CAR projection, map Sysmon **ProcessGuid → `process.entity_id`**
  and **ParentProcessGuid → `parent_guid`**;
- populate **`owning_guid` on registry and file rows** — currently NULL on all
  12,171 registry and 31,828 file rows, so the synthetic tree is still
  incomplete.

The sibling MAC key from the same value hunt is covered in
[Step 02](02-linkage-mac.md).
