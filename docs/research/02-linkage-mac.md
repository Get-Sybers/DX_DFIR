# Step 02 — MAC address from v1 GUIDs (B3)

> Part of the CAR cross-source linkage & detection research arc — see [README](README.md) for the full map.

**Status:** merged (#60)

## The gap

A version-1 GUID (the RFC 4122 time+MAC variant) carries the originating NIC's
MAC address verbatim in its node bytes. The cross-dataset value hunt
([`../car-provenance/crosslink/`](../car-provenance/crosslink/)) counted
**~6,218** MAC-bearing v1 GUIDs in the LoneWolf image alone: the DLT birth-droid
stamped into every LNK shortcut, and the `-11e2-` / `-11e8-` volume and network-
interface GUIDs. On top of those sit literal MAC strings, such as the NetworkList
gateway MAC.

None of that was ever lifted into a CAR field — no `mac_address` column existed
anywhere in the model. So a file opened through a shortcut could not be tied back
to the machine that created it: the attribution key was sitting inside the GUID
and being thrown away.

## What we found

The node decodes cleanly to real hardware MACs (see
[`crosslink/guids.md`](../car-provenance/crosslink/guids.md)):

- **`5c2307d9-3369-11e2-be70-001cc42df40b` → `00:1c:c4:2d:f4:0b`** — the DLT
  birth-droid shared by 96 `windows:lnk:link` rows and 32
  `windows:distributed_link_tracking:creation` rows: which volume/machine a
  shortcut's target was born on.
- **`{3869c27a-31b8-11e8-9b12-ecf4bb487fed}` → `EC:F4:BB:48:7F:ED`** — a real
  Dell MAC leaked by the MountPoints2 volume GUID.

Not every v1-shaped node is a hardware MAC, so three families are excluded:
- the OLE/COM node `000000000046` (the `…-c000-000000000046` family);
- the RFC synthetic placeholder `806e6f6e6963` (e.g.
  `{5c3108bb-31c0-11e8-9b10-806e6f6e6963}` — an `80:6e:6f:6e:69:63` non-address);
- any node whose first octet has the multicast / I-G bit set — an RFC-random,
  non-hardware id rather than a burned-in NIC address.

## The fix

**PR #60** added `native_ids.mac_from_v1_guid`, which decodes a v1 GUID's node
into a hardware MAC and applies the three exclusions above.
`native_ids.mac_addresses` additionally gathers literal `xx:xx:xx:xx:xx:xx`
strings out of `native`.

`mac_address` became the **3rd non-MITRE header column** (after `owning_guid`
and the `volume_guid` from [Step 01](01-linkage-volume-guid.md)):
- `enrich` lifts it onto every object;
- `crosssource` converges rows on a `mac` class;
- it projects to a custom `car.mac_address` field — ECS's MAC fields are
  role-specific (`source.mac` / `destination.mac` / `host.mac`), so a
  cross-object header key belongs in the custom namespace, not any one role.

## What it enables

A LNK's DLT birth-droid and a NetworkList entry that share a NIC MAC now join on
one key — device-linkage the pipeline entirely lacked. The MAC becomes both a
queryable column and a convergence class, alongside the volume GUID from
[Step 01](01-linkage-volume-guid.md).

## Follow-ups

Two device-linkage gaps from the same hunt remain (see
[`crosslink/SUMMARY.md`](../car-provenance/crosslink/SUMMARY.md)):
- **B4 · plaso data loss** — `MountedDevices` / `DefaultGatewayMac` / device
  bytes are emitted only as `(6 bytes)` / `(224 bytes)` summaries, so the raw
  MAC/serial is dropped by the parser before any normalisation could recover it
  (a lane/parser-config fix, upstream of this decoder).
- a **device-serial** CAR field still does not exist, though USB iSerials and
  USBSTOR/MountedDevices bind USB devices to volume GUIDs (e.g. the SanDisk
  Extreme serials seen 2,470× across the disk host).
