# CAR `flow` — FILESYSTEM / DISK Provenance Audit (dead-box, no pcap)

**Object:** `flow` — *"A sequence of packets from a source computer to a destination… may be captured at network or host level."*
**Actions:** `start`, `message`, `end`.
**Fields audited (26 + image_path):** application_protocol, content, dest_fqdn, dest_hostname, dest_ip, dest_port, end_time, exe, fqdn, hostname, (image_path), in_bytes, network_direction, out_bytes, packet_count, pid, ppid, proto_info, src_fqdn, src_hostname, src_ip, src_port, start_time, tcp_flags, transport_protocol, uid, user.

**Scope of THIS pass:** filesystem/disk artefacts only. The prior pass (`docs/car-provenance/flow.md` / LS24) covered the network + host-telemetry vantages — Zeek conn (S1), Sysmon EID 3 (S2), memory netscan (S3), SMB30803 (S4), and SRUM-as-mapped (S5). This pass asks: **on a dead disk (no live capture), what filesystem artefacts could fill flow — and which has the pipeline not mined?**

**Grounded in real data:** the full LoneWolf Win10 plaso timeline
`data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (4,169,774 events, 6.6 GB) — every data_type / parser tallied (`_datatypes.txt`), flow-relevant artefacts sampled directly.

---

## The central fact for `flow` on a dead disk

> **A dead-box filesystem has essentially no honest source for the flow 5-tuple.** `src_ip`/`dest_ip`/`src_port`/`dest_port`/`transport_protocol`/`application_protocol`/`tcp_flags`/`packet_count`/`content`/`proto_info` all require a *live* vantage (pcap, Zeek, Sysmon3, WFP audit, memory netscan). None is recoverable from files at rest. The **only** disk artefact that maps to CAR flow at all is **SRUM `network_usage`** — an hourly per-app **byte aggregate with no endpoints** — and it currently yields **0 rows everywhere in the processed store.** The one disk artefact that *would* carry a real 5-tuple + allow/block (the **Windows Firewall log, `pfirewall.log`**) is **not parsed and not present**. So filesystem flow coverage is: one mapped-but-empty aggregate source, one honest-but-absent 5-tuple source, and a set of download/network-profile artefacts that are near-misses for flow (they belong to `http`/`registry`).

---

## Filesystem source universe (what the LoneWolf disk actually produced)

| # | Disk artefact | data_type (parser) | rows in LoneWolf | Maps to flow today? | Flow value |
|---|---|---|---|---|---|
| **FS1** | **SRUM `SruDb`** (SRUDB.dat, ESE) | `windows:srum:network_usage` (`esedb/srum`) | **0** (see gap #1) | **MAPPED** → flow/message (`plaso_srum.py:73`) | in_bytes/out_bytes + exe/image_path/uid — **no endpoints**. Empty. |
| **FS2** | **NetworkList profiles** (SOFTWARE hive) | `windows:registry:network` (`winreg/networks`) | **6** | mis-routed → **registry/key_edit** (`plaso_registry.py`) | SSID, gateway MAC, DNS suffix, first/last-connected. **Fills NO flow field** (near-miss). |
| **FS3** | **Chrome downloads** (History sqlite) | `chrome:history:file_downloaded` (`sqlite/chrome_27_history`) | **42** | **UNMAPPED** (no chrome handler in `plaso_web.py`) | download **source URL** + received/total bytes + start/end — an **http/get**; byte/time flow-adjacent. |
| **FS4** | Chrome cache/cookies/visits | `chrome:cache:entry` 21,636; `chrome:cookie:entry` 8,863; `chrome:history:page_visited` 2,293 | 32k+ | **UNMAPPED** | domains contacted → **http**, not flow. |
| **FS5** | IE/Edge WebCache (WebCacheV01.dat, ESE) | `msie:webcache:container` 921 (`esedb/msie_webcache`) | 921 | **UNMAPPED** | URL/history/download containers → **http**, not flow. |
| **FS6** | Distributed Link Tracking (in .lnk) | `windows:distributed_link_tracking:creation` (`lnk`) | 254 | → registry-adjacent (native only) | embeds **origin machine MAC** + volume GUID. CAR flow has **no MAC field**. |
| **FS7** | **Firewall log** `%windir%\System32\LogFiles\Firewall\pfirewall.log` | — (no plaso parser) | **0** (only registry path refs) | **NO** | Would give a real **5-tuple + allow/block** → flow. Absent + unparseable. |
| **FS8** | **BITS** `qmgr.db` (on disk) | — (plaso has no qmgr.db parser) | 0 | **NO** (disk); BITS only via **EVTX 59/60** → http | url + bytes, but as an event-log http record, not disk-flow. |
| **FS9** | DNS client cache | — (memory-resident, not persisted) | 0 | **NO** | honest null on a dead disk. |
| **FS10** | hosts file | — (filestat sees the file; content not parsed) | 0 | **NO** | static name→IP mapping; not a flow anyway. |
| **FS11** | **Zone.Identifier ADS `HostUrl`** | — (plaso does not parse ADS content) | **0** | **NO** | download source URL — recoverable instead from FS3 (chrome downloads). |
| **FS12** | RDP client MRU (`Terminal Server Client\Servers`, NTUSER) | `windows:registry:key_value` (buried) | (in 1.5M key_value) | → registry/key_edit | outbound RDP **dest host** — a weak dest_hostname/dest_fqdn, not surfaced. |

**Empirical confirmations (streamed over all 4.17M events):**
- `windows:srum:*` data_type count = **0**. SRUDB.dat **exists on disk** (filestat: `\Windows\System32\sru\SRUDB.dat` + `SRUDB.jfm`, in VSS2) but produced **no parsed SRUM rows**. `data_store/processed/zimmerman/` (the dedicated SRUM two-step target) is **empty (.gitkeep only)**. SRUM is 0 end-to-end.
- `Zone.Identifier` substring = **0 lines**. `pfirewall` = 18 lines, **all `windows:registry:key_value` from the SYSTEM hive** (the FirewallPolicy log-path value) — **no parsed firewall-log content**.
- `windows:registry:network` sampled: `ssid="Net 2.4"`, `default_gateway_mac_address="5c:8f:e0:2a:1c:68"`, `dns_suffix="<none>"`, `connection_type=71`, rows at `"Creation Time"` (first-connected) and `"Last Connection Time"`.
- `chrome:history:file_downloaded` sampled: `url="https://s3browser.com/download/s3browser-7-6-9.exe"`, `full_path="C:\Users\jcloudy\Downloads\s3browser-7-6-9.exe"`, `received_bytes=2483848`, `total_bytes=2483848`, `"Start Time"`/`"End Time"` rows.

---

## Per-field provenance table (filesystem vantage)

Legend — **mined?**: **mapped-0** = an active map exists but has no input rows; **NO(fs)** = no filesystem source fills it; **near-miss** = a present artefact carries related data but not this canonical field; **unmapped** = a present artefact could feed it but no map consumes it.

| field | fs artefact → native field | action | mined? | confidence & caveats |
|---|---|---|---|---|
| **out_bytes** | FS1 SRUM `bytes_sent`; (FS3 chrome download `received_bytes` is *in*-direction) | message | **mapped-0** (SRUM) | High design, **zero data**. SRUM is the *only* disk source and it is empty everywhere. Hourly per-app aggregate — never a per-connection count. |
| **in_bytes** | FS1 SRUM `bytes_received`; FS3 chrome `received_bytes` (download) | message | **mapped-0** (SRUM); **unmapped** (FS3) | Same as out_bytes. FS3 download bytes are real but belong to `http` (a GET body), not flow — mapping them to flow.in_bytes would be a category slip. |
| **exe** | FS1 SRUM `application` (basename); FS3/FS4 give the browser, not the flow owner | start/message | **mapped-0** (SRUM) | The one disk field that ties bytes to a process — but SRUM is empty. `application` may be a `\Device\…` path or a bare service name. |
| **image_path** | FS1 SRUM `application` (if `\Device\…`) | start/message | **mapped-0** | Empty. No other disk artefact records the socket-owning image path. |
| **uid** (SID) | FS1 SRUM `user_identifier` (gated to real `S-1-` form) | start/message | **mapped-0** | Empty. An SRUM internal index is refused (not an identity). No other disk source. |
| **start_time** | FS1 SRUM `Timestamp` (hourly bucket); FS2 NetworkList `Creation Time` (first-connected); FS3 chrome download `Start Time` | start | **mapped-0** (SRUM); **near-miss/unmapped** (FS2/FS3) | SRUM = aggregate recorded-time, not a connect instant. NetworkList first-connected is a *network-join* time, not a flow. FS3 is a download start (http). |
| **end_time** | FS3 chrome download `End Time`; FS2 NetworkList `Last Connection Time` | end | **unmapped/near-miss** | No mapped disk source. Both are download/network-join times, not flow ends. |
| **dest_fqdn** | FS12 RDP MRU dest host; FS2 NetworkList `dns_suffix` (local suffix, not a dest) | start | **near-miss** | No disk artefact resolves the *dest* of a captured flow. RDP MRU names an outbound RDP target but is buried in `key_value`. |
| **dest_hostname** | FS12 RDP client MRU server name | start | **near-miss (buried)** | Weak; would need a dedicated RDP-MRU map. Not a flow record per se. |
| **dest_ip / dest_port / src_ip / src_port** | FS7 firewall log 5-tuple **(absent)**; FS1 SRUM has **none** | start/message | **NO(fs)** | **The core gap.** No file at rest carries the flow 5-tuple. SRUM records the interface only. Firewall log would — it is not parsed and not present. |
| **transport_protocol** | FS7 firewall log proto **(absent)** | start/message | **NO(fs)** | Same — only the (absent) firewall log would give L4 from disk. |
| **network_direction** | FS7 firewall log direction **(absent)** | start | **NO(fs)** | Firewall log records allow/block + inbound/outbound; nothing else on disk does. |
| **application_protocol** | — | — | **NO(fs)** | L7 label is a live-capture (Zeek `service`) property. No disk source. |
| **tcp_flags** | — | — | **NO(fs)** | Live-packet-only. Honest null on a dead disk. |
| **packet_count** | — | — | **NO(fs)** | Live-packet-only. |
| **content** | — | — | **NO(fs)** | Full-packet payload only. Never on disk. |
| **proto_info** | — | — | **NO(fs)** | L7 decode (SMB/HTTP) — pcap/DPI only. The biggest flow-analytics gap, and no disk path to it. |
| **pid / ppid** | — (SRUM has no pid) | — | **NO(fs)** | Live host telemetry only (Sysmon3 / memory). SRUM is per-app, not per-process. |
| **user** | — (SRUM gives a SID→uid, not a `user` name) | — | **NO(fs)** | No disk source resolves the flow's process user name. |
| **fqdn / hostname** (observing host) | FS1–FS3 `image_hostname` = `DESKTOP-PM6C56D` | start | **available** | The imaged host is the vantage; every disk row carries `image_hostname`. Fills the *observer* host, not a flow endpoint. |
| **src_fqdn / src_hostname** | — | — | **NO(fs)** | No reverse-resolver; the disk names the host but not as a flow endpoint. |

**Net:** of 26 flow fields, exactly **five** have a filesystem source and it is a **single artefact (SRUM) that is currently empty** (out_bytes, in_bytes, exe, image_path, uid; + image-host fqdn/hostname). Every endpoint/5-tuple/L7/packet field is an honest `NO(fs)` on a dead box.

---

## Ranked UNMINED opportunities (build order)

1. **Parse SRUDB.dat so `l2t_srum` actually gets rows — #1 flow gap, and it is a *pipeline* gap not a data gap.**
   SRUDB.dat is **present on the LoneWolf disk** (filestat, in VSS2) and the map (`plaso_srum.py`, flow/message: in_bytes/out_bytes/exe/image_path/uid) is **schema-complete** — but **0 rows reach it**. Root cause: the plaso lane runs `log2timeline.py` with **no `--parsers`** (default preset — which *does* include `esedb/srum`), yet the live SRUDB.dat yields nothing, consistent with a **dirty/needs-recovery ESE database** that `libesedb` skips (SRUDB.dat is normally an unclean-shutdown ESE db; it parses only after the `.jfm` log is replayed / `esentutl /r` recovery). The dedicated **Zimmerman SRUM two-step** (`dxdfir_zimmerman`, `log2timeline.py esedb/srum → psort`) exists to handle exactly this but its output dir is **empty**. Fix = recover SRUDB.dat before parsing (or point the SRUM two-step at a recovered copy) and route its JSONL through `l2t_srum`. Highest value: turns the only mapped disk-flow source from theoretical to real (per-app in/out bytes + user attribution). *(The docstring's "17,928 rows" figure came from a recovered copy, not this lane.)*

2. **Parse `pfirewall.log` → flow (start/message + allow/block).**
   The **only** filesystem artefact that carries a genuine flow **5-tuple** (`src_ip/dest_ip/src_port/dest_port/transport_protocol/network_direction`) plus action. Not present in the LoneWolf collection and **plaso has no firewall-log parser** — needs (a) the file collected and (b) a text/log map (a `text/` parser variant or a dxdfir map). This is the single biggest *potential* dead-box flow win, because it is the lone disk source for the fields SRUM cannot give (endpoints + direction). Blocked on collection + a parser.

3. **Chrome browser artefacts → `http` (and download bytes/times) — a present, entirely unmapped family.**
   `plaso_web.py` handles msiecf / firefox / java **but not Chrome**, and the LoneWolf disk is Chrome-heavy: `chrome:history:file_downloaded` (42 — download **source URL** + received/total bytes + start/end), `chrome:history:page_visited` (2,293), `chrome:cache:entry` (21,636), `chrome:cookie:entry` (8,863). These are **http** records (URL/domain requested), with the downloads carrying flow-adjacent byte/time data. Adding a `chrome_*` handler to `plaso_web` is a clean, high-volume win — primarily for the `http` object, secondarily surfacing download provenance. (This also *realises* the task's "Zone.Identifier HostUrl" goal: the download source URL is here, richer than the ADS.)

4. **IE/Edge WebCache (`msie:webcache:*`, 921 rows) → `http`.** ESE WebCacheV01.dat containers (history/cache/cookies/downloads) — same http-object opportunity as #3, unmapped today.

5. **NetworkList `windows:registry:network` — re-route + surface its fields (low flow value, honest about it).**
   6 rows present, currently swallowed by `plaso_registry` into **registry/key_edit**, and its network-specific fields (`ssid`, `default_gateway_mac_address`, `dns_suffix`, `connection_type`, first/last-connected) are **not even captured in `native_extract`** — doubly under-mined. **But for CAR *flow* it fills no canonical field** (no IP/port/bytes/exe; a gateway MAC and SSID have no flow slot). Best handled as **enriched registry / a network-environment context**, not forced into flow. Recommend: extend `plaso_registry` native_extract to capture the NetworkList fields (cheap, correct) rather than minting a flow row.

---

## Honest no-sources (dead-box filesystem)

- **content, packet_count, tcp_flags, proto_info** — full-packet / DPI properties. **No file at rest can produce them.** Honest nulls on a dead disk; only pcap / Suricata / Zeek per-protocol logs (a *live* vantage) fill them. `proto_info` remains the highest-impact flow-analytics gap and has **no disk path whatsoever**.
- **application_protocol** — a capture-side L7 label (Zeek `service`); no disk artefact.
- **src_ip / dest_ip / src_port / dest_port / transport_protocol / network_direction** — no filesystem 5-tuple source exists **except** the (absent, unparsed) firewall log. SRUM records the interface, not endpoints.
- **pid / ppid / user** — live host telemetry (Sysmon3 / memory) only; SRUM is per-app-aggregate (SID→uid, no pid/ppid/user-name).
- **src_fqdn / dest_fqdn / src_hostname / dest_hostname** — no reverse-DNS/resolver stage; the disk names the *observing* host (`image_hostname`) but not flow endpoints. (RDP client MRU is a weak, buried dest-host hint only.)
- **Zone.Identifier ADS `HostUrl`** — plaso does not parse NTFS ADS content (0 lines); the download source URL is instead available via chrome:history:file_downloaded (#3).
- **BITS `qmgr.db`** on disk — plaso has no qmgr.db parser; BITS reaches the pipeline only through **EVTX 59/60 → http** (an event-log, not a disk-flow, source).
- **DNS client cache** — memory-resident, not persisted; nothing on the dead disk.
- **hosts file** — filestat sees the file; content is not parsed, and a static name→IP map is not a flow event.

## Key file references
- Real data: `data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (data_type inventory tallied over that file).
- Mapped-but-empty SRUM: `byakugan/byakugan/mappings/plaso_srum.py:73`; source decl `byakugan/byakugan/sources_model.py:120`; SRUM two-step lane `ansible/collections/get_sybers.dxdfir/roles/dxdfir_zimmerman/` (output `data_store/processed/zimmerman/` — empty).
- Plaso lane (no `--parsers`, default preset): `python/get_sybers_dxdfir/plaso.py:312`; argv `roles/dxdfir_plaso/defaults/main.yml`.
- NetworkList mis-route: `byakugan/byakugan/mappings/plaso_registry.py` (`plaso_is_registry`, all `windows:registry:*`).
- Browser maps (no chrome handler): `byakugan/byakugan/mappings/plaso_web.py`.
- BITS via EVTX only: `byakugan/byakugan/mappings/evtx_extra.py:48`.
- Prior (live-vantage) flow catalogue: `docs/car-provenance/flow.md`.
