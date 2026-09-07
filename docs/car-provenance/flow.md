# CAR `flow` — Property-Provenance Catalogue

**Object:** `flow` — *"A sequence of packets from a source computer to a destination… This may be captured at network or host level."*
**Actions:** `start`, `message`, `end`.
**Fields (27):** application_protocol, content, dest_fqdn, dest_hostname, dest_ip, dest_port, end_time, exe, fqdn, hostname, image_path, in_bytes, network_direction, out_bytes, packet_count, pid, ppid, proto_info, src_fqdn, src_hostname, src_ip, src_port, start_time, tcp_flags, transport_protocol, uid, user.

Grounded in: `third_party/piiat-mitrecar/third_party/car/data_model/flow.yaml`, `car_data_model.json`, the four active flow maps, the quarantined WFP audit spec, PIIAT-Mem, and real evidence (`data_store/processed/{zeek,volatility}`).

> **The central fact for `flow`.** A network-vantage source (Zeek conn, pcap, NetFlow) gives the 5-tuple, volume, protocols, and TCP history — but carries **no endpoint identity**: no `exe`/`pid`/`ppid`/`user`/`image_path`. Those fields — the ones CAR flow analytics actually key on (`exe`, `user` appear in the detection corpus) — come **only from a host-side source that watches the socket owner**: **Sysmon EID 3**, **memory netscan**, or **WFP 5156** (quarantined). This catalogue's job is to show, per field, which side each source can and cannot fill.

---

## Source universe (what actually exists in this repo)

| # | Source | Map | Status | Vantage | Gives endpoint owner (exe/pid/user)? |
|---|--------|-----|--------|---------|--------------------------------------|
| **S1** | **Zeek conn.log** | `piiat_mitrecar/mappings/zeek_conn.py` | **MAPPED** | network | **NO** (pcap has no host identity) |
| **S2** | **Sysmon EID 3 NetworkConnect** | `piiat_mitrecar/mappings/sysmon.py:311` | **MAPPED** | host (endpoint) | **YES** — `exe`,`image_path`,`pid`,`user` native; `ppid` inherited |
| **S3** | **Memory netscan / netstat** (Volatility) | `piiat-mem/piiat_mem/mappings.py:125` (`_FLOW_MAP`) | **MAPPED** | host (memory) | **YES** — `pid`,`exe` native; `image_path`,`user`,`uid`,`ppid` **inherited** from owning `_EPROCESS` (definitive) |
| **S4** | **SMBClient/Connectivity 30803** | `piiat_mitrecar/mappings/evtx_more.py:152` | **MAPPED (thin)** | host (endpoint) | NO (no process ctx on 30803) — only `dest_fqdn` |
| **S5** | **SRUM network_usage** (Plaso esedb/srum) | `piiat_mitrecar/mappings/plaso_srum.py:73` | **MAPPED** | host (per-app aggregate) | partial — `exe`,`image_path`,`uid` native; no pid/user/endpoints |
| **U1** | **WFP 5156 (allow) / 5157 (block)** | `piiat-mitrecar/to-be-validated/evtx_audit.yml:157` | **QUARANTINED — NOT active** | host (endpoint) | **YES (spec)** — `image_path`,`pid`,`owning_pid`; no user/exe |
| **U2** | **Zeek dns/ssl/http per-protocol logs** | (raw; `zeek_extra.py` docstring) | **NOT mapped to flow** | network | NO — could enrich `application_protocol`/`proto_info`/`dest_fqdn` by shared `uid` at cascade, not done |
| **U3** | **Sysmon EID 22 DnsQuery** | (raw; `sysmon.py:469` default None) | **NOT mapped** | host | — (DNS resolution, not a flow; could feed `dest_fqdn`) |
| **U4** | **Suricata EVE / NetFlow-IPFIX / raw pcap payload** | — | **NOT mapped (no mapper exists)** | network | NO — but pcap payload is the *only* real source of `content` & `proto_info` |
| **U5** | **Plaso firewall/pfirewall.log, browser history** | (browser→http via `plaso_web`) | **NOT mapped to flow** | host | — |

**Evidence check.** Zeek `conn.json` present for 2 captures (fields verified: `ts`,`uid`,`id.orig_h/p`,`id.resp_h/p`,`proto`,`duration`,`orig_bytes`/`resp_bytes`,`conn_state`,`history`,`orig_pkts`/`resp_pkts`,`local_orig`/`local_resp`,`ip_proto`). Memory `car.db` has a **`flow` table with the full 27-field schema plus owner-link columns** (`owning_pid`,`owning_offset`,`owning_guid`,`parent_pid`,`parent_guid`,`link_confidence`) — but **0 flow rows in this sample** (this memory image produced no `windows.netscan`/`piiat.network` output; only mftscan+processes ran). Pipeline is schema-complete for memory flow; this particular image just has no connections to show.

---

## Per-field provenance table

Legend for "mapped?": **yes** = an active map fills it; **inherit** = filled by the enrich cascade from the owning process (fill-only-null, never overwrites native); **quarantined** = spec exists in `to-be-validated/`, not active; **NO** = no source in the repo fills it.

| field | sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|---|
| **src_ip** | S1 Zeek `id.orig_h`; S2 Sysmon3 `SourceIp`; S3 mem `LocalAddr`; U1 WFP `SourceAddress` | start/message/end | **yes** (S1,S2,S3) | High. Convention: `src`=originator (Zeek) / local endpoint (Sysmon,mem). Memory's local=src is a **snapshot convention**, not proven originator (`network_direction` null there). S4 SMB has only SOCKADDR-hex `LocalAddress`→native, **not** src_ip. |
| **src_port** | S1 `id.orig_p`; S2 `SourcePort`; S3 `LocalPort`; U1 `SourcePort` | start/message/end | **yes** (S1,S2,S3) | High, same convention as src_ip. |
| **dest_ip** | S1 `id.resp_h`; S2 `DestinationIp`; S3 `ForeignAddr`; U1 `DestAddress` | start/message/end | **yes** (S1,S2,S3) | High. S4 SMB `RemoteAddress` is SOCKADDR-hex→native, **honest-null dest_ip**. |
| **dest_port** | S1 `id.resp_p`; S2 `DestinationPort`; S3 `ForeignPort`; U1 `DestPort` | start/message/end | **yes** (S1,S2,S3) | High. Most-used field in flow analytics (11 refs). |
| **transport_protocol** | S1 `proto` (tcp/udp/icmp); S2 `Protocol`; S3 `Proto` (TCPv4→TCP); U1 `Protocol` (6→tcp,17→udp) | start/message/end | **yes** (S1,S2,S3) | High. Authoritative model name (KQL's stale `protocol` was renamed). Memory normalizes `TCPv4`→`TCP`. |
| **application_protocol** | S1 Zeek `service` only | start/message/end | **yes** (S1) | Medium. Zeek `service` is the app-proto label. **Only Zeek fills it.** Richer L7 (via dns/ssl/http uid-join = U2) is possible but **not done**. Sysmon3 `Source/DestinationPortName` are port name-table guesses → **native, deliberately NOT application_protocol** (near-miss refused). |
| **tcp_flags** | S1 Zeek `history` only | start/message/end | **yes** (S1) | Medium — **recorded, not literal.** Zeek `history` is per-event state-history letters (`ShADadFf`, upper=orig/lower=resp), present on UDP/ICMP too, **NOT a TCP flag bitmask**. Consumers must read it as Zeek history. No other source carries flags (Sysmon3/mem/WFP have none). |
| **out_bytes** | S1 Zeek `orig_bytes`; S5 SRUM `bytes_sent` | end/message | **yes** (S1,S5) | High. Zeek: payload bytes, src=originator ⇒ out=orig-sent. `orig_ip_bytes` is IP-level, **never a fallback**. Absent counters (S0/REJ) stay **null, not 0**. SRUM = hourly per-app aggregate (no endpoints). |
| **in_bytes** | S1 Zeek `resp_bytes`; S5 SRUM `bytes_received` | end/message | **yes** (S1,S5) | High, mirror of out_bytes. |
| **packet_count** | S1 Zeek `_zc_packet_count` = `orig_pkts`+`resp_pkts` | end/message | **yes** (S1) | High. Derived sum; **null when neither counter present** (a missing pair is not a 0-packet flow). Only Zeek. |
| **start_time** | S1 Zeek `ts`; S2 Sysmon3 `TimeCreated`; S3 mem `Created`; S4 SMB `TimeCreated`; S5 SRUM `Timestamp` | start/message/end | **yes** (S1–S5) | High for S1/S2/S4. **Caveat S3:** memory `Created` on a live-connection snapshot is the socket-create time *as recorded in the acquired image*, reliable only as far as the acquisition. **Caveat S5:** SRUM is the aggregate's Recorded Time (hourly bucket), not a connect instant. |
| **end_time** | S1 Zeek `_zc_end_time` = `ts`+`duration` | end/message | **yes** (S1) | Medium. Only when Zeek MEASURED a duration (S0/REJ attempts → null). Single-event sources (Sysmon3, SMB, WFP) have **no end** — honest null. |
| **network_direction** | S2 Sysmon3 `Initiated` (TRUE→outbound/FALSE→inbound); U1 WFP `Direction` (%%14593→out/%%14592→in) | start | **yes** (S2); quarantined (U1) | Medium. **Sysmon3 is the only active source.** Zeek could derive from `local_orig`/`local_resp` (both present in evidence) but **deliberately leaves it null** (vetted view asserts no direction). Memory=null (socket snapshot can't tell originator). |
| **exe** | S2 Sysmon3 `Image`; S3 mem `Owner` (proc name); S5 SRUM `application` (basename) | start/message | **yes** (S2,S3,S5) | **The endpoint field.** Sysmon3/memory are authoritative. SRUM `application` may be a device path (basename→exe) or bare service name. **Zeek/pcap/NetFlow give NOTHING here.** Used by flow analytics (4 refs). |
| **image_path** | S2 Sysmon3 `Image`; S3 mem **inherited** from owning `_EPROCESS` `Path`; S5 SRUM `application` (if `\Device\…`); U1 WFP `Application` | start/message | **yes** (S2,S5) / **inherit** (S3) | High for S2. Memory netscan's own row has only `Owner` (name); full `image_path` arrives via **definitive owner inheritance** (`owning_offset`→process `Path`). No path from Zeek/pcap. |
| **pid** | S2 Sysmon3 `ProcessId`; S3 mem `PID`; U1 WFP `ProcessID` | start/message | **yes** (S2,S3) | **Endpoint field.** Sysmon3/memory authoritative. WFP `ProcessID` is **decimal** (not hex) per spec. None from network sources. |
| **ppid** | S2 Sysmon3 **inherited** (owner ProcessGuid, definitive); S3 mem **inherited** (owner `_EPROCESS`, definitive) | start | **inherit** (S2,S3) | Medium. **No source carries ppid natively on a flow record.** Filled by the enrich cascade from the owning process (`from_owning_process` includes `ppid` = the parent of the process the flow belongs to). Sysmon3's `owning_guid`=ProcessGuid and memory's `owning_offset` make this link **definitive** (tier-1). Absent an owner link (Zeek, SMB30803, SRUM, WFP) → **honest null**. |
| **user** | S2 Sysmon3 `User`; S3 mem **inherited** token `User` from owning `_EPROCESS` | start/message | **yes** (S2) / **inherit** (S3) | **Endpoint field.** Sysmon3 native. Memory inherits the owning process's token user (definitive). **WFP 5156 has no user field; SRUM gives a SID not a name; Zeek/pcap give nothing.** Used by flow analytics. |
| **uid** *(SID / user-id of flow-handling entity)* | S3 mem **inherited** owner `Sid`; S5 SRUM `user_identifier` (only if `S-1-` form) | start/message | **inherit** (S3) / **yes** (S5) | Medium. This is the *SID/user-id* family field, **not** the Zeek connection uid (that stays in `_native`, filling it would be a category error — see zeek_conn.py). Sysmon3 gives `User` (name) but **no SID → uid null on Sysmon3**. SRUM gates on real `S-1-` form (an SRUM internal index is not an identity). |
| **dest_hostname** | S2 Sysmon3 `DestinationHostname` | start | **yes** (S2) | Medium — Sysmon-resolved remote name (best-effort, may be empty). No reverse-DNS resolver in pipeline. |
| **src_hostname** | S2 Sysmon3 `SourceHostname` | start | **yes** (S2) | Medium — same as dest_hostname. |
| **dest_fqdn** | S4 SMB30803 `ServerName`; (U3 Sysmon22 `QueryName` — not mapped) | start | **yes** (S4) | Low coverage. SMB30803 `ServerName` is the target server name (SMB-specific), the **only** active dest_fqdn source. Sysmon22 DNS or a Zeek dns uid-join could add it — **not implemented**. |
| **src_fqdn** | — | — | **NO** | **Honest no-source.** No mapped source resolves the originator's FQDN. Would require reverse-DNS of `src_ip` — no resolver stage exists. |
| **fqdn** *(observing host)* | S2 Sysmon3 `Computer` (if dotted); S4 SMB30803 `Computer` | start | **yes** (S2,S4) | Medium. This is the **vantage host** FQDN (the collection endpoint), per MITRE flow.fqdn = "the host". `regex1(Computer, ^([^.]+\.+)$)` — null on a bare workgroup name. **Zeek flow has null fqdn** (capture vantage is the pipeline `source_host` column, not written to this CAR field); memory flow inherits host fqdn from the image context. |
| **hostname** *(observing host)* | S2 Sysmon3 `host_label(Computer)`; S3 mem inherited image host; S4 SMB30803 `host_label(Computer)` | start | **yes** (S2,S4) / **inherit** (S3) | Medium. Vantage host short name (NOT a flow endpoint — those are src/dest_hostname). **Zeek flow hostname = null** (no `hostname` prop in zeek_conn map; source_host is separate). |
| **proto_info** | — (native to none) | — | **NO** | **Honest no-source — and a real gap.** Application-layer decode (SMB write request, HTTP headers/content). Only full **pcap payload / Suricata DPI / Zeek per-protocol logs** could produce it; **no mapper exists**. Zeek `service`→`application_protocol` deliberately leaves proto_info null (a bare service label would be a near-miss). **Flow analytics reference `proto_info` heavily (~10 refs) — the single biggest semantic gap for flow detections.** |
| **content** | — (native to none) | — | **NO** | **Honest no-source.** ASCII of the flow payload (`GET https://… HTTP/1.1`). Requires **full-packet capture / PCAP payload**; the pipeline ingests Zeek *logs*, not payload. Referenced by ≥1 flow analytic. No source in repo. |

---

## Coverage summary

**Fields with an active source (23 of 27):** src_ip, src_port, dest_ip, dest_port, transport_protocol, application_protocol, tcp_flags, out_bytes, in_bytes, packet_count, start_time, end_time, network_direction, exe, image_path, pid, ppid(inherit), user, uid, dest_hostname, src_hostname, dest_fqdn, fqdn/hostname.

**Two-sided coverage is real:** the **network side** (5-tuple, volume, protocols, flags, times) is carried by **Zeek conn** (S1); the **endpoint side** (exe/image_path/pid/ppid/user/uid) is carried by **Sysmon EID 3** (S2) and **memory netscan** (S3). These are complementary vantages of the *same* flow — the pipeline keeps them as separate rows (different guids: Zeek `uid` vs record-guid vs proto+endpoint tuple); a cross-source 5-tuple+window bridge (`community_id`) is **deferred** (CAR-Relations.md).

### The endpoint-side owner — who fills exe/pid/user/image_path (what pcap/Zeek lack)

| owner field | Sysmon 3 | Memory netscan | WFP 5156 (quarantined) | Zeek/pcap/NetFlow |
|---|---|---|---|---|
| `exe` | native (`Image`) | native (`Owner`) | derivable (basename `Application`) | **never** |
| `image_path` | native (`Image`) | inherit (owner `Path`) | native (`Application`) | **never** |
| `pid` | native (`ProcessId`) | native (`PID`) | native (`ProcessID`, decimal) | **never** |
| `ppid` | inherit (definitive) | inherit (definitive) | — (no owner link) | **never** |
| `user` | native (`User`) | inherit (owner token) | **none** | **never** |
| `uid`(SID) | **none** (name only) | inherit (owner `Sid`) | **none** | **never** |

### Honest no-source / weak-source (ranked gaps)

1. **`proto_info` — NO SOURCE, highest-impact gap.** ~10 references across flow analytics; nothing fills it. Needs pcap DPI / Suricata / Zeek per-protocol decode. **U2 (Zeek dns/ssl/http uid-join) is the cheapest realistic win — the logs already exist unmapped.**
2. **`content` — NO SOURCE.** Requires full-packet PCAP payload; pipeline ingests logs, not payload.
3. **`src_fqdn` — NO SOURCE**, and **`dest_fqdn` weak** (only SMB30803 `ServerName`). No reverse-DNS/DNS-answer join stage exists (U2 Zeek dns or U3 Sysmon22 would supply dest_fqdn).

### UNMAPPED opportunities, ranked (build-order)

1. **WFP 5156/5157 → flow (U1)** — spec is written and schema-grounded in `to-be-validated/evtx_audit.yml` (`security_5156_wfp_connection_allowed` → flow/start; 5157 → flow/message). Gives endpoint 5-tuple + `image_path` + `pid` + `network_direction` from the **Windows Security log** (no Sysmon required). **Blocked only on a capture with the Filtering-Platform-Connection audit subcategory enabled** (absent from lonewolf/M57/attack-samples). Highest value: a second, log-native endpoint source.
2. **Memory netscan flow (S3) — already mapped, under-exercised.** Schema/pipeline complete; the on-hand memory image produced no netscan rows. Validate against an image that has live connections to prove the exe/pid/user/uid/ppid inheritance end-to-end.
3. **Zeek dns/ssl/http → flow enrichment by `uid` (U2)** — fills `application_protocol` (richer), `proto_info`, and `dest_fqdn` for network-vantage flows. The logs are already produced and sit raw; a cascade `from_owning_flow`-style rule (the R3 pattern already used for http/file) would attach them.
4. **Sysmon EID 22 DnsQuery (U3), Suricata EVE / NetFlow / pcap (U4)** — no mappers today; would add DNS-based `dest_fqdn`, and (pcap/Suricata) the only realistic path to `content`/`proto_info`.

### Notes on honesty / near-misses the engine deliberately refuses
- Zeek `tcp_flags` = state-history letters, **not** a TCP bitmask (documented).
- Zeek `service` → `application_protocol` only; **`proto_info` stays null** (near-miss refused).
- Sysmon3 `Source/DestinationPortName` → **native**, not `application_protocol` (port-name-table guess).
- SMB30803 `RemoteAddress`/`LocalAddress` → **native SOCKADDR hex**, never faked into `dest_ip`/`src_ip`.
- `flow.uid` (SID family) is **never** the Zeek connection uid (category error) — the Zeek uid lives in `_native` as the http/files join key.
- Zeek/mem `network_direction` left **null** rather than guessed, though the raw fields (`local_orig`/`local_resp`; socket local/foreign) exist.
- **`flow.yaml` `coverage_map` lists `sysmon_13`** for the start action — that is MITRE's own sensor-taxonomy token for its Sysmon network-connection sensor config, **not** Windows Sysmon EventID 13 (RegistryValueSet). This repo's authoritative endpoint source for flow is **Sysmon EventID 3 (NetworkConnect)**; treat the data-model `coverage_map` as MITRE's generic placeholder, not this engine's coverage.

### Key file references
- Active maps: `third_party/piiat-mitrecar/piiat_mitrecar/mappings/{zeek_conn.py, sysmon.py:311, evtx_more.py:152, plaso_srum.py:73}`
- Memory flow map: `third_party/piiat-mem/piiat_mem/mappings.py:125` (`_FLOW_MAP`); inheritance list `piiat_mem/enrich.py:72` (`_INHERIT`)
- Enrich inheritance rules: `piiat_mitrecar/relationships.yml` (`from_owning_process` includes `ppid`)
- Quarantined WFP spec: `third_party/piiat-mitrecar/to-be-validated/evtx_audit.yml:157-189`
- Model + semantics: `car_data_model.json`, `third_party/piiat-mitrecar/third_party/car/data_model/flow.yaml`
- Relations discipline: `docs/CAR-Relations.md`
