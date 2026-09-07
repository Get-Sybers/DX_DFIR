# Cross-dataset value hunt — synthesis (GUIDs, SIDs/users, hosts/IPs, cmdlines, ports/serials)

Grepped unambiguous values across the whole `data_store/processed/` tree to reveal
(a) the same value in ≥2 artefacts = a convergence key, and (b) values in raw/native
no CAR field lifted = unmined. Per-class detail: `guids.md`, `identity.md`,
`host_ip.md`, `cmdlines.md`, `ports_serials.md`.

## Framing fact (all five agents independently)
`data_store/processed/` is **not one host** — it's a grab-bag of **~5 independent
images/scenarios**: LoneWolf disk `DESKTOP-PM6C56D` (user jcloudy), Linux `5g-webui`,
memory `BGP-WS1-CONF` (its own machine SID), evtx+hayabusa `DESKTOP-M913391` (user JDH),
and Zeek pcaps of the `10.27.33.x` subnet. So cross-**host** convergence is naturally
absent; real convergence lives **within** each host + at the **network-infra** level.
(This is why a whole-tree cross-source run finds few host bridges — it's evidence
hygiene, not a bug. A single-collection run is where convergence pays off.)

## The decisive normalisation finding — the `guid` join key is synthetic-only
CAR's `guid` is *the* cross-source join key (→ ECS `event.id`/`process.entity_id`,
per `detect/rules/car-detections/join-keys.yml`). But of **44,327** non-null
`guid/owning_guid/parent_guid/target_guid` values, **zero are canonical `{8-4-4-4-12}`
GUIDs** — all are minted synthetic ids (`proc-…`, `file-…`). So **no MachineGuid,
volume GUID, Sysmon ProcessGuid, task/interface GUID is ever promoted to a queryable
CAR field** — the natural cross-source keys survive only as text in `native`. And
`owning_guid` is populated only for `user_session` (registry/file rows NULL).

## Real convergence keys found (all unmined)
- **Volume GUID `{09931f21-…}`** → 6 data_types (USN, evtx, registry, fs:stat, Google-Drive sync log, MountPoints2) — the single best key on the disk.
- **`jcloudy` = RID 1001** — the identity spine across ~20 disk data_types + 42k evtx SID refs, while plaso native `username` = `"-"` on **99.999%** of rows.
- **CloudLog exfil USB** (volume serial `4C36-F4AC`, holds `D:\key.txt`) → LNK ↔ shellbags; **SanDisk USB iSerials** → USBSTOR+setupapi+DeviceClasses (2,470×).
- **MACs leak from v1 GUIDs** (DLT birth-droids / volume GUID nodes → `ec:f4:bb:48:7f:ed`, `00:1c:c4:2d:f4:0b`) and NetworkList gateway MAC — no MAC field exists anywhere.
- **Network-infra bridges**: DNS `100.95.95.4` (memory-registry ↔ Zeek), `berylia.org` (5g-webui cert ↔ Zeek), the DNS→IP→flow **C2 chain** (`scoring-c2.berylia.org`→`100.101.0.42`, masscan UA), an SSH-22 pivot chain.
- **Cross-host pivot**: user `gt` on both the memory Windows host and the 5G Linux host.
- **S3 Browser exfil tool** seen 6 ways on the disk host; obfuscated `cmd /c` triangulated Sysmon↔Hayabusa and **decoded to a CTF flag**.

## Added backlog (beyond the A-class FS-unmined items)
- **B1 · promote canonical GUIDs to the CAR `guid`/`host.id` space** — MachineGuid→`host.id`, add a volume-GUID field, map Sysmon Process/Parent/Logon GUID in the evtx→CAR projection (today only synthetic ids fill `guid`), and populate `owning_guid` on registry/file rows. Without this the *one* cross-source join key can't use the real GUIDs.
- **B2 · normalise network identity** — Zeek (conn/dns/ssl/x509/http) is entirely raw here and memory's static IP config lives only in raw registry strings; lift IPs/domains/SNI/certs into `flow`/`http`, and reconcile the memory host's IP with its name.
- **B3 · decode v1-GUID node → `mac_address`** (6,218 MAC-bearing GUIDs in LoneWolf) and add **MAC + device-serial CAR fields** (none exist) fed by NetworkList/DLT/USBSTOR/LNK — these are strong device-linkage keys.
- **B4 · plaso data-loss**: `MountedDevices`/`DefaultGatewayMac`/device bytes are emitted only as `(6 bytes)`/`(224 bytes)` summaries — the raw serial/MAC is dropped before any normalisation could recover it (a lane/parser-config fix).
- **B5 · a reusable YARA "unnormalised-value" ruleset** — the agents produced ~30 YARA stubs (SID, `\Users\<name>\`, MachineGuid/volume/ProcessGuid/task GUID classes, v1-GUID-embedded MAC, IPv4/IPv6/MAC, volume/USB serial, port, DOSfuscation/C2/LOLBin patterns). Consolidate into one ruleset that flags distinctive values present-but-unnormalised across any future dataset — the user's "use YARA to limit missing non-normalised data", operationalised.

## Through-line
Two orthogonal gaps: (1) the disk/evtx/zeek lanes don't build CAR here at all (only memory has a `car.db`), and (2) even where CAR is built, the join key is synthetic-only and every natural cross-source key (GUID, MAC, serial, IP, domain) is unnormalised. The A-class PR fixes the per-field disk squeeze; B1–B5 fix the *linkage* layer so the cross-source convergence stage actually has real keys to join on.
