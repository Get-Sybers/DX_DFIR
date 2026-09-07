# Ports & Serials as Cross-Artefact Linkage Keys — DX_DFIR processed dataset

**Scope:** READ-ONLY hunt across `data_store/processed/` for serial numbers (volume/USB/disk), MAC
addresses, and port numbers usable as cross-artefact device/flow linkage keys, plus an audit of which
of these reach a normalised CAR field.

**Key structural finding first:** the processed dataset is **heterogeneous — several independent source
images**, not one host. This bounds what "convergence" can mean:

| Source image | Artefact(s) | Host / user |
|---|---|---|
| LoneWolf.E01 (disk) | `log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (6.6 GB) | DESKTOP-PM6C56D / jcloudy |
| 5g-image-1 (disk) | `log2timeline/jsonl/5g-webui.jsonl` (7.8 GB) | Linux 5G-core VM |
| memory dump | `volatility/memdump.mem/plugins/*.jsonl` + **`car.db`** | BGP-WS1-CONF |
| pcaps | `zeek/*/{conn,ssh,...}.json` | 10.27.33.x subnet |
| evtx / hayabusa | `windows_logs/.../log_EvtxECmd_Output.json`, `signatures/hayabusa/timeline.jsonl` | DESKTOP-M913391 / JDH |

Because these are different machines, **the strongest genuine device convergences are WITHIN the LoneWolf
image** (a device seen across its LNK + shellbag + registry). Cross-image port matches (22, 53, 135, 443…)
are shared-service coincidences, not the same host.

**CAR normalisation state (the headline gap):** `car.db` is built **only from the memory dump**
(`windows.mftscan`, `windows.piiat.registry/processes/sessions`). It **never ingests** plaso LNK/shellbags,
zeek, or evtx. Its `socket(local_port,remote_port)` and `flow(src_port,dest_port)` columns exist but are
**empty (0 rows)** — no netscan plugin was run. `file` has **no serial column**; there is **no MAC column
anywhere** in the schema. Verified: LoneWolf USB serials, volume serials, and MACs are **absent** from CAR
(the only `USBSTOR`/`SanDisk` hits in the CAR registry table are the memory host's *service* key
`\...\Services\USBSTOR` and a storahci device-compat string — no device serial; `4C36`/`74EE` "file" hits
are coincidental SHA-1 substrings). **Every serial/MAC below, and every port below, is un-normalised today.**

---

## Master linkage table

`| value (serial/port/MAC) | artefacts | normalised? | link / device-convergence use |`

| value | artefacts (source) | normalised into CAR? | link / device use |
|---|---|---|---|
| **Vol serial `4C36-F4AC`** (dec `1278669996`, LE bytes `AC F4 36 4C`), label **CloudLog**, drive_type **2 = REMOVABLE** | LNK `drive_serial_number` (LoneWolf) ×18; same device's file `D:\key.txt` in **shellbags** ×12 | **No** — no CAR serial field | **CONVERGENCE.** The removable "CloudLog" USB volume holding `key.txt`, seen across BOTH access artefacts (LNK carries the serial; shellbag carries the same `D:\key.txt` path). Strongest device chain. |
| **Vol serial `AA92-0881`** (dec `2861697153`, LE `81 08 92 AA`), drive_type 3 = FIXED (C:) | LNK `drive_serial_number` (LoneWolf) ×637 | **No** | C: system-volume serial; links all C:-resident LNK targets (rootkey.csv, DemGun.jpg, DemLogic.jpg, Cloudy thoughts…docx) to one volume. |
| **Vol serial `74EE-2D73`** (dec `1961766259`, LE `73 2D EE 74`), label **OSDisk**, drive_type 3 | LNK `drive_serial_number` (LoneWolf) ×96 | **No** | Second C:/OSDisk volume serial (PowerShell LNKs). |
| **USB serial `AA010215170355310594`** (SanDisk Extreme) | **USBSTOR** instance key, **setupapi** device-install (`WPDBUSENUM\...USBSTOR#Disk&Ven_SanDisk&Prod_Extreme#AA0102...`), **DeviceClasses / WPDBUSENUM** — 1104 combined refs w/ its twin | **No** — CAR has no serial column | **CONVERGENCE.** Physical USB stick seen across device-enum (USBSTOR) + install-log (setupapi) + device-interface classes. iSerialNumber-style unique key. |
| **USB serial `AA010603160707470215`** (SanDisk Extreme) | same as above (USBSTOR / setupapi / DeviceClasses) | **No** | Second SanDisk Extreme unit (or re-enumeration) — same convergence pattern. |
| **Volume GUID `{3869c27a-31b8-11e8-9b12-ecf4bb487fed}`** (node = MAC `ec:f4:bb:48:7f:ed`) | **MountedDevices** (`\DosDevices\D:` = 224 B, matches this GUID) + DeviceClasses volume class | **No** | Ties drive-letter **D:** → the removable volume; GUID node embeds a host NIC MAC (see below). |
| **MAC `ec:f4:bb:48:7f:ed`** | **distributed_link_tracking:creation** `mac_address` (98 recs) **AND** MountedDevices volume-GUID node `...ecf4bb487fed` | plaso normalises `mac_address` on DLT; **CAR: No MAC field** | **CONVERGENCE.** Same NIC MAC appears in file-creation ObjectIDs (DLT) and in the volume-GUID minted by that host — links created files to the physical machine. |
| **MAC `28:e3:47:01:77:77`** | distributed_link_tracking `mac_address` (117 recs) | plaso: yes; CAR: **No** | Most-frequent creator MAC in LNK/ObjectID droids. |
| **MAC `00:1c:c4:2d:f4:0b`** | distributed_link_tracking (32) — PowerShell.lnk etc., uuid `5c2307d9-3369-11e2-be70-001cc42df40b` | plaso: yes; CAR: **No** | Creator NIC MAC of PowerShell shortcuts. |
| **MAC `ec:0e:c4:20:7f:0e`** | distributed_link_tracking (7) | plaso: yes; CAR: **No** | Additional creator NIC MAC. |
| **Gateway MAC `5c:8f:e0:2a:1c:68`** | `windows:registry:network` — NetworkList profile (Wireless), rendered in message; DefaultGatewayMac REG_BINARY (6 B, truncated) | **No** | Links LoneWolf host to a specific Wi-Fi gateway; the network the machine joined. |
| **MACs `00:50:56:89:b3:ff`, `00:50:56:89:34:cf`** (VMware OUI) | 5g-webui.jsonl (5G-core Linux VM) | **No** | VM NIC MACs for the 5G image. |
| **Port 22 (SSH)** | zeek `conn.json` (19) + `ssh.json` | schema has `flow.src/dest_port`, `socket` — **empty, so No** | **CONVERGENCE (flow).** SSH pivot chain: `10.27.33.11` (OpenSSH_for_Windows_8.1 / Renci.SshNet) → `10.27.33.61:22` (Ubuntu) → `100.101.0.42:22` (Debian, Go client), auth_success=true. Links conn↔ssh logs. |
| **Port 53 / 80 / 135 / 443** | zeek conn.json (53=7726, 80=17, 135=3, 443=12) | **No** (empty flow/socket) | DNS/HTTP/RPC/TLS service flows. |
| **Firewall ports 3702,1900,2177,2869,135,445,3540,5355,5357-8,137-8,23554-6,9955,68/67,546/547** | LoneWolf registry `FirewallPolicy\FirewallRules` REG_SZ (9 rule-bearing records; pipe-delimited `|LPort=/|RPort=`) | **No** — buried inside a REG_SZ string, no CAR port field | Host firewall posture; ports embedded in rule strings, invisible to any structured port field. |

---

## Best device-linkage chains (real LoneWolf values)

### Chain A — the removable "CloudLog" USB and `key.txt` (volume-serial convergence)
```
LNK      : local_path "D:\key.txt"  drive_serial_number 1278669996 (0x4C36F4AC → 4C36-F4AC)
           drive_type 2 (DRIVE_REMOVABLE)  volume_label "CloudLog"      [windows:lnk:link]
shellbag : shell_item_path "<My Computer> D:\key.txt"                   [windows:shell_item:file_entry]  ×12
MountedDv: \DosDevices\D:  → 224-byte binary == Volume{3869c27a-...-ecf4bb487fed}
```
=> One removable volume (serial **4C36-F4AC**, label **CloudLog**) proven across **access-by-shortcut (LNK)**
and **folder-browse (shellbag)**; the serial is the only field that names the *device* — the shellbag alone
would just say "D:". This is the classic "the exfil/keying file lived on this specific stick" convergence.

### Chain B — SanDisk Extreme USB stick (USB-serial convergence across 3 registry/log artefacts)
```
setupapi     : "Device Install (Hardware initiated) - SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_SanDisk&
                Prod_Extreme&Rev_0001#AA010215170355310594&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b} - SUCCESS"
USBSTOR key  : HKLM\System\ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Extreme&Rev_0001\AA010215170355310594&0
DeviceClasses/WPDBUSENUM: same serial across GUID_DEVINTERFACE_DISK / WPD interfaces  (1104 refs w/ twin AA010603160707470215)
```
=> USB iSerialNumber **AA010215170355310594** (and **AA010603160707470215**) is the device key tying the
first-insert timeline (setupapi) to the enumerated device (USBSTOR) to the device-interface registrations.

### Chain C — creator-host NIC MAC (MAC convergence: DLT ObjectID ↔ volume GUID)
```
DLT      : mac_address ec:f4:bb:48:7f:ed  (distributed_link_tracking:creation, 98 recs)
MountedDv: \??\Volume{3869c27a-31b8-11e8-9b12-ecf4bb487fed}   (node = ec f4 bb 48 7f ed)
```
=> The MAC baked into file-creation ObjectIDs is the *same* MAC used to mint the D: volume GUID — links
created files to a physical NIC and to the drive-letter mapping.

---

## Serials / ports / MACs present in raw/native that NO CAR field normalises (quantified)

| class | value(s) | native location | count | why unnormalised |
|---|---|---|---|---|
| Volume serial | 4C36-F4AC, AA92-0881, 74EE-2D73 | LNK `drive_serial_number` (int) | 751 LNK recs | `file`/`registry` CAR tables have no serial column |
| USB iSerial | AA010215170355310594, AA010603160707470215 | USBSTOR key path, setupapi msg, DeviceClasses | 6 USBSTOR-instance recs, 6 setupapi installs, 1104 total refs | no CAR device/serial field |
| Creator MAC | ec:f4:bb:48:7f:ed, 28:e3:47:01:77:77, 00:1c:c4:2d:f4:0b, ec:0e:c4:20:7f:0e | DLT `mac_address`; also GUID nodes | 254 DLT recs | no CAR MAC column |
| Gateway MAC | 5c:8f:e0:2a:1c:68 | `windows:registry:network` NetworkList / DefaultGatewayMac (REG_BINARY, truncated to "(6 bytes)") | 6 network recs | no CAR MAC column; **binary itself dropped** to a byte-count |
| MountedDevices binary | volume-serial/disk-signature bytes for `\DosDevices\{C,D,E}:` | registry REG_BINARY | 3 letters | plaso emits only "(224 bytes)" — **raw hex not preserved**, so serial is un-extractable downstream |
| Firewall ports | 3702,1900,135,445,5355,23554-6,9955,68/67,… | REG_SZ `FirewallRules` string `|LPort=/|RPort=` | 9 records | ports inside an opaque pipe-delimited string; `socket`/`flow` empty |
| Zeek flow ports | 22,53,80,135,443 (+ full 5-tuple) | zeek conn/ssh JSON | conn 7821 recs | zeek not ingested into CAR; `flow`/`socket` = 0 rows |

Two secondary gaps worth flagging: (1) **NetworkList DefaultGatewayMac** and (2) **MountedDevices** device
bytes are emitted by plaso only as `(N bytes)` summaries — even the raw value is lost before any
normalisation could occur, so the on-disk volume serial in MountedDevices can't be recovered from the JSONL.

---

## YARA rule stubs (hunt these raw values in images / carved artefacts)

```yara
rule DXDFIR_LoneWolf_VolumeSerial_CloudLog
{
    // Removable "CloudLog" volume serial 0x4C36F4AC, holding key.txt
    meta:
        author = "DX_DFIR car-crosslink"
        desc   = "NTFS/FAT volume serial 4C36-F4AC (removable CloudLog) — LNK + shellbag + MountedDevices"
    strings:
        $le   = { AC F4 36 4C }              // little-endian 4-byte serial as stored in LNK/registry binary
        $ascii1 = "4C36-F4AC" nocase          // human/tool rendering
        $ascii2 = "CloudLog" wide ascii        // volume label co-marker
        $dec  = "1278669996"                   // plaso decimal rendering (JSONL/CSV)
    condition:
        $le or $ascii1 or ($ascii2 and any of ($dec,$le))
}

rule DXDFIR_LoneWolf_VolumeSerials_Fixed
{
    strings:
        $s1_le = { 81 08 92 AA }   $s1_a = "AA92-0881"  $s1_d = "2861697153"   // C: AA92-0881
        $s2_le = { 73 2D EE 74 }   $s2_a = "74EE-2D73"  $s2_d = "1961766259"   // OSDisk 74EE-2D73
    condition:
        any of them
}

rule DXDFIR_LoneWolf_USB_SanDisk_Serial
{
    // SanDisk Extreme USB iSerialNumbers — USBSTOR / setupapi / DeviceClasses
    strings:
        $u1 = "AA010215170355310594" ascii wide nocase
        $u2 = "AA010603160707470215" ascii wide nocase
        $ven = "Ven_SanDisk&Prod_Extreme" ascii wide nocase
    condition:
        any of ($u*) or ($ven and any of ($u*))
}

rule DXDFIR_LoneWolf_Creator_and_Gateway_MAC
{
    // MACs from DLT ObjectIDs, volume GUID nodes, and NetworkList gateway
    strings:
        $m1_txt = "ec:f4:bb:48:7f:ed" nocase   $m1_raw = { EC F4 BB 48 7F ED }
        $m2_txt = "28:e3:47:01:77:77" nocase   $m2_raw = { 28 E3 47 01 77 77 }
        $m3_txt = "00:1c:c4:2d:f4:0b" nocase    $m3_raw = { 00 1C C4 2D F4 0B }
        $m4_txt = "ec:0e:c4:20:7f:0e" nocase    $m4_raw = { EC 0E C4 20 7F 0E }
        $gw_txt = "5c:8f:e0:2a:1c:68" nocase    $gw_raw = { 5C 8F E0 2A 1C 68 }  // NetworkList gateway
        $volguid = "3869c27a-31b8-11e8-9b12-ecf4bb487fed" ascii wide nocase
    condition:
        any of them
}

rule DXDFIR_Firewall_and_Flow_Ports
{
    // Un-normalised ports: firewall REG_SZ rule strings + notable flow ports
    strings:
        $fw_l = /\|LPort=(3702|1900|2177|2869|135|445|3540|5355|5357|5358|23554|23555|23556|9955)\b/
        $fw_r = /\|RPort=(1900|2177|2869|3702|137|138|547|67)\b/
        $ssh  = ":22" ascii            // SSH pivot 10.27.33.11 -> .61:22 -> 100.101.0.42:22
    condition:
        $fw_l or $fw_r or $ssh
}
```

*(MAC raw byte order: DLT/volume-GUID nodes store the MAC big-endian as the trailing 6 bytes of the GUID, so
the `{ EC F4 BB 48 7F ED }` form matches both the GUID node and a raw NetworkList/DHCP MAC blob.)*
