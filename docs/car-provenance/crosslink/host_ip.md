# Cross-Artefact Linkage Hunt: Hostnames, IPs, MACs & Domains

Dataset: `/opt/github/DX_DFIR/data_store/processed/` (READ-ONLY analysis)
Scope: plaso (`log2timeline/jsonl/*`), Windows logs (`windows_logs/`), Zeek (`zeek/*`), Volatility memory (`volatility/memdump.mem/plugins/*` + `car.db`).

---

## TL;DR

- **This is a MULTI-HOST, MULTI-SCENARIO dataset — 4 distinctly-named machines + 2 un-attributed network capture identities. NO single hostname value bridges any two named hosts.** Each anchor hostname appears ONLY in its own artefact.
- The only genuine cross-source bridges are **network-infrastructure identifiers, none of which any normalisation layer (CAR) captures**:
  1. **DNS resolver `100.95.95.4` / IPv6 `2a07:1181:95:95::4`** links the **memory host `BGP-WS1-CONF`** (registry NameServer) to the **Zeek DFIRdump capture** (DNS `id.resp_h`). Same network, adjacent /25 subnets.
  2. **Domain `berylia.org`** links the **`5g-webui` Linux disk** (on-disk TLS cert) to the **Zeek capture** (DNS/SSL/HTTP).
- The memory→disk→log host-identity reconciliation **fails by name**: memory `ComputerName = BGP-WS1-CONF`, disks = `DESKTOP-PM6C56D` / `5g-webui`, logs = `DESKTOP-M913391`. Confirmed the earlier finding — memory host ≠ disk/log host. They can only be tied together (partially) through the shared DNS server and the berylia domain.
- **CAR normalises host identity only for the memory image, and drops ALL network identity**: `flow`, `socket`, `http`, `email`, `authentication` tables = 0 rows; `user_session.src_ip/dest_ip` all NULL. Every IP/MAC/domain/flow in the dataset is available only in raw/native form.

---

## 1. Multi-Host Map — which artefacts = which machine

| Machine (hostname) | Artefact(s) | Asserting field / evidence | Primary user | Scenario / network |
|---|---|---|---|---|
| **DESKTOP-PM6C56D** | `log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (disk `LoneWolf.E01`, Win10) | plaso `image_hostname` | `jcloudy` | "LoneWolf" scenario — **no** berylia domain, **no** 10.27/100.x IPs; isolated from the exercise network |
| **5g-webui** | `log2timeline/jsonl/5g-webui.jsonl` (disk `5g-image-1.vmdk`, Linux) | plaso `image_hostname`; FQDN from on-disk cert `/srv/certs/5g-webui.sac.baf.10.berylia.org_cert.crt` | root | berylia exercise (`sac.baf.10.berylia.org`) |
| **BGP-WS1-CONF** | `volatility/memdump.mem/plugins/*.jsonl` + `car.db` (process/file/registry/user_session) | registry `...\Control\ComputerName\ComputerName = BGP-WS1-CONF`; process env `COMPUTERNAME=BGP-WS1-CONF`; CAR `hostname` column | `Administrator` | berylia exercise — static IP **10.27.32.51/25**, GW **10.27.32.1**, DNS **100.95.95.4** |
| **DESKTOP-M913391** | `windows_logs/unspecified_host/log_EvtxECmd_Output.json` (85 Sysmon recs) | EvtxECmd `Computer` field (all 85 records) | `DESKTOP-M913391\JDH` | Sysmon process telemetry (Chrome activity); EventIDs 1 & 5 only — **no network events**, host never tied to an IP |
| *(un-named)* `10.27.33.61` / `2a07:1182:27:33::61` | `zeek/DFIRdump_FOR_200_capture_pcap/*` | Zeek `id.orig_h` (C2-beacon source) | — | berylia exercise client, subnet 10.27.33.x (adjacent to BGP-WS1-CONF's 10.27.32.x) |
| *(un-named)* `100.100.250.37` | `zeek/ME_FOR_1308_pcapng/conn.json` | Zeek `id.orig_h` (large HTTP upload → 100.101.0.162:80) | — | berylia exercise, subnet 100.100.250.x |
| *(no IP — USB)* | `zeek/keylogging_pcapng/*` | USB link-layer capture (packet-filter install failed: "USB link-layer type") | — | HID keylogging capture; **contains no IP/host data at all** |

**Does any value bridge the named hosts?** No hostname does. Bridges are network-level only: `100.95.95.4`/`2a07:1181:95:95::4` (BGP-WS1-CONF ↔ Zeek DFIRdump) and `berylia.org` (5g-webui ↔ Zeek). LoneWolf `DESKTOP-PM6C56D` and Sysmon `DESKTOP-M913391` are **not bridged to anything** — separate scenarios.

---

## 2. Master linkage table

`| value | artefacts | normalised? | link use |`

| value (host/IP/MAC/domain) | artefacts asserting it | normalised (CAR)? | link use |
|---|---|---|---|
| `DESKTOP-PM6C56D` | plaso DESKTOP-PM6C56D.jsonl only | n/a (plaso `image_hostname`) | single-artefact; no cross-link |
| `5g-webui` | plaso 5g-webui.jsonl only | n/a (plaso `image_hostname`) | anchors Linux disk; FQDN carries berylia bridge |
| `BGP-WS1-CONF` | memory: pslist/piiat.* + `car.db` process/file/registry/user_session | **YES** — CAR `hostname` (from registry ComputerName + env) | memory host identity; NOT found in any disk/log |
| `DESKTOP-M913391` | windows_logs EvtxECmd `Computer` (85 recs) | NO | Sysmon host identity; no IP, no cross-link |
| `5g-webui.sac.baf.10.berylia.org` (FQDN) | 5g-webui disk cert `/srv/certs/*.crt` | NO | ties 5g-webui disk into berylia.org domain |
| **`100.95.95.4`** (IPv4 DNS) | Zeek conn.json + Zeek dns.json (`id.resp_h`) **AND** memory registry `Tcpip\...\Interfaces\{89b3e14f-...}` NameServer | **NO** (memory reg raw; CAR has 0 IPs) | **CONVERGENCE KEY — memory↔network.** Same DNS for BGP-WS1-CONF and Zeek client 10.27.33.61 |
| **`2a07:1181:95:95::4`** (IPv6 DNS) | Zeek conn.json (7608 resp) + dns.json **AND** memory registry Tcpip6 Interfaces NameServer | **NO** | **CONVERGENCE KEY — memory↔network** (IPv6 sibling of above) |
| **`berylia.org`** (+ `scoring-c2`, `dfir-rt-web02`, `*.confidential.baf.27`) | Zeek dns/ssl/http/x509 **AND** 5g-webui disk cert filename | **NO** | **CONVERGENCE KEY — disk↔network** |
| `100.101.0.42` | Zeek dns (`answers`) + conn + http (`host`=scoring-c2) + ssl (SNI=scoring-c2) | NO | DNS→IP→flow C2 pivot within Zeek (4 log types) |
| `10.27.32.51` (BGP-WS1-CONF IP) | memory registry IPAddress only | NO | memory host's own IP — **absent from Zeek pcap** (its traffic not captured) |
| `10.27.32.1` (BGP-WS1-CONF GW) | memory registry DefaultGateway only | NO | not seen elsewhere |
| `10.27.33.61` / `2a07:1182:27:33::61` | Zeek DFIRdump conn/dns/http/ssl (`id.orig_h`) | NO | C2-beacon client; adjacent subnet to BGP-WS1-CONF |
| `100.100.250.37` → `100.101.0.162` | Zeek ME_FOR_1308 conn.json | NO | large HTTP upload (exfil pattern) |
| `144.202.62.192` | Zeek dns (`answers` for whatthecommit.com) + conn | NO | resolved external IP |
| MAC `00:50:56:89:a2:69`, `00:50:56:89:ab:90` | Zeek conn IPv6 link-local (EUI-64 embedded), e.g. `fe80::250:56ff:fe89:a269` | **NO** (no MAC field anywhere) | VMware OUI `00:50:56` → confirms virtualised (ESXi vNIC) infra |

---

## 3. Cross-source IP / domain links (zeek ↔ registry ↔ memory)

### Link A — DNS resolver bridges MEMORY ↔ NETWORK
- **Memory (`BGP-WS1-CONF`)** — `windows.piiat.registry.jsonl`, key `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{89b3e14f-e403-4965-be04-aaeceb0a4e2f}`:
  - `IPAddress = 10.27.32.51`, `SubnetMask = 255.255.255.128` (/25), `DefaultGateway = 10.27.32.1`
  - `NameServer = 100.95.95.4`; Tcpip6 `NameServer = 2a07:1181:95:95::4`; `DhcpServer = 255.255.255.255` (static)
- **Zeek DFIRdump** — `conn.json`/`dns.json`: `id.resp_h = 100.95.95.4` (118 flows) and `2a07:1181:95:95::4` (7608 flows) on `id.resp_p = 53` — i.e. the **same DNS resolver**.
- **Inference:** `BGP-WS1-CONF` (10.27.32.51) and the Zeek client (10.27.33.61) are on **adjacent /25 subnets of the same network** and share DNS infrastructure. `10.27.32.51` itself does **not** appear in the pcap, so BGP-WS1-CONF's own traffic was not captured — the bridge is the shared resolver, not host identity.

### Link B — berylia.org bridges DISK ↔ NETWORK
- **5g-webui disk:** `fs:stat` on `/srv/certs/5g-webui.sac.baf.10.berylia.org_cert.crt` → host FQDN in `berylia.org`.
- **Zeek DFIRdump:** DNS queries dominated by `dfir-rt-web02.berylia.org` (7912) and `scoring-c2.berylia.org` (15); SSL SNI + HTTP Host = `scoring-c2.berylia.org`; x509 subject `CN=berylia.org`, SAN `*.berylia.org`; also `*.fastedge.cloud.confidential.baf.27.berylia.org`.
- **Inference:** the 5g-webui disk and the Zeek capture belong to the same `berylia.org` exercise domain (5g-webui in `baf.10`, Zeek DNS traffic in `baf.27` — sibling org segments).

### Link C — DNS→IP→flow C2 chain (within Zeek; not normalised)
- `scoring-c2.berylia.org` --(DNS A via 100.95.95.4)--> `100.101.0.42` --(conn)--> flows `10.27.33.61 → 100.101.0.42` on ports **22 (SSH), 80 (HTTP), 443 (HTTPS)**.
- HTTP beacons use `User-Agent: masscan/1.0` POSTing to `/stuffing.php`, `/quintuple.jsp`, etc. → classic scored-C2 beaconing. This full chain is derivable ONLY by manually joining Zeek's raw `dns.answers` ↔ `conn` ↔ `http`; no normaliser ties them.

---

## 4. Un-normalised network identifiers (raw/native — no CAR field carries them)

1. **CAR drops all network identity.** `car.db` tables `flow`, `socket`, `http`, `email`, `authentication`, `driver`, `module`, `service`, `thread` = **0 rows**. Populated: `file` (31828), `registry` (12171), `process` (180), `user_session` (9), `image_context` (163). Even `user_session.src_ip/src_port/dest_ip/dest_port` are **all NULL**. So the CAR schema *has* IP columns but nothing populates them.
2. **Memory static IP config is buried in raw registry.** `10.27.32.51`, `10.27.32.1`, `100.95.95.4`, `2a07:1181:95:95::4`, subnet `255.255.255.128` live only inside raw `windows.piiat.registry.jsonl` Tcpip Interface `ValueData` strings — never surfaced to a normalised IP field. The memory host is therefore never programmatically tied to its own IP.
3. **Zeek is entirely raw** (not ingested into CAR at all): every `id.orig_h`/`id.resp_h`, `dns.query`, `dns.answers`, `ssl.server_name`, `http.host`, `x509` subject/SAN is native JSON only.
4. **DNS answers not tied to flows.** `dns.answers` present in only 21 records; even there, the domain→IP→conn correlation must be done by hand (no join key emitted).
5. **MAC addresses exist only implicitly.** No artefact emits a MAC field. The only MACs recoverable are EUI-64-embedded in Zeek IPv6 link-locals: `fe80::250:56ff:fe89:a269 → 00:50:56:89:a2:69` and `fe80::250:56ff:fe89:ab90 → 00:50:56:89:ab:90` (VMware OUI 00:50:56). Registry `NetworkAddress`/`PermanentAddress` MAC values: none present in the dumped SYSTEM hive.
6. **Sysmon host has no network telemetry.** `DESKTOP-M913391` EvtxECmd = EventID 1 (ProcessCreate) & 5 (ProcessTerminate) only; no EventID 3 (NetworkConnect). Host can never be joined to the network graph by IP.
7. **On-disk TLS cert subject not normalised.** `5g-webui.sac.baf.10.berylia.org` (disk) and Zeek `CN=berylia.org` / SAN `*.berylia.org` are never reconciled to a common domain entity.

---

## 5. YARA rule stubs (IPv4 / IPv6 / MAC / hostname / domain)

```yara
/*
   Cross-artefact network-identity anchors — DX_DFIR processed dataset.
   Real values pulled from Zeek + Volatility memory registry + plaso disks.
   Intended for sweeping raw/unstructured evidence (memory strings, disk
   images, pcaps, logs) for the convergence keys the CAR layer never normalised.
*/

rule DXDFIR_Hostnames_MultiHost
{
    meta:
        author = "car-crosslink hunt"
        description = "The four named hosts across disk/memory/log artefacts"
    strings:
        $h1 = "DESKTOP-PM6C56D" ascii wide nocase   // LoneWolf disk
        $h2 = "5g-webui"        ascii wide nocase   // Linux disk
        $h3 = "BGP-WS1-CONF"    ascii wide nocase   // memory dump
        $h4 = "DESKTOP-M913391" ascii wide nocase   // Sysmon logs
    condition:
        any of them
}

rule DXDFIR_Berylia_C2_Domains
{
    meta:
        description = "berylia.org exercise domains — disk<->network bridge & C2"
    strings:
        $d1 = "berylia.org"                 ascii wide nocase
        $d2 = "scoring-c2.berylia.org"      ascii wide nocase   // C2
        $d3 = "dfir-rt-web02.berylia.org"   ascii wide nocase
        $d4 = "5g-webui.sac.baf.10.berylia.org" ascii wide nocase
        $d5 = "confidential.baf.27.berylia.org" ascii wide nocase
    condition:
        any of them
}

rule DXDFIR_IPv4_Anchors
{
    meta:
        description = "Convergence IPv4s: DNS 100.95.95.4 links memory<->zeek"
    strings:
        $ip_dns  = "100.95.95.4"    ascii wide   // DNS: memory reg + zeek
        $ip_bgp  = "10.27.32.51"    ascii wide   // BGP-WS1-CONF static IP
        $ip_gw   = "10.27.32.1"     ascii wide   // BGP-WS1-CONF gateway
        $ip_cli  = "10.27.33.61"    ascii wide   // zeek C2-beacon client
        $ip_c2   = "100.101.0.42"   ascii wide   // scoring-c2 resolved IP
        $ip_up   = "100.100.250.37" ascii wide   // ME_FOR_1308 uploader
    condition:
        any of them
}

rule DXDFIR_IPv6_Anchors
{
    meta:
        description = "Convergence IPv6s incl. DNS resolver (memory<->zeek)"
    strings:
        $v6_dns = "2a07:1181:95:95::4"     ascii wide nocase   // DNS memory+zeek
        $v6_cli = "2a07:1182:27:33::61"    ascii wide nocase   // zeek client
    condition:
        any of them
}

rule DXDFIR_VMware_MAC
{
    meta:
        description = "VMware vNIC MACs recovered from zeek IPv6 EUI-64 link-locals"
    strings:
        $m1 = "00:50:56:89:a2:69" ascii wide nocase
        $m2 = "00:50:56:89:ab:90" ascii wide nocase
        // EUI-64 forms as seen on the wire:
        $e1 = "fe80::250:56ff:fe89:a269" ascii wide nocase
        $e2 = "fe80::250:56ff:fe89:ab90" ascii wide nocase
    condition:
        any of them
}

/* ---- Generic pattern rules (regex) for un-anchored discovery ---- */

rule GENERIC_IPv4_Address
{
    meta: description = "Any dotted-quad IPv4 (validate octets downstream)"
    strings:
        $ipv4 = /([0-9]{1,3}\.){3}[0-9]{1,3}/ ascii wide
    condition:
        $ipv4
}

rule GENERIC_IPv6_Address
{
    meta: description = "IPv6 incl. compressed :: forms"
    strings:
        $ipv6 = /([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]{1,4}/ ascii wide
    condition:
        $ipv6
}

rule GENERIC_MAC_Address
{
    meta: description = "48-bit MAC, colon or hyphen separated"
    strings:
        $mac = /([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}/ ascii wide
    condition:
        // guard against date-like false positives (e.g. 24-02-14-06-36-46)
        $mac
}

rule GENERIC_Windows_Hostname_NETBIOS
{
    meta: description = "DESKTOP-/WS-style NetBIOS names for host discovery"
    strings:
        $nb = /\b(DESKTOP|WIN|WS|SRV|BGP)[-][A-Z0-9]{3,15}\b/ ascii wide nocase
    condition:
        $nb
}
```

---

## 6. Evidence pointers (absolute paths)

- Memory static IP / DNS (BGP-WS1-CONF): `/opt/github/DX_DFIR/data_store/processed/volatility/memdump.mem/plugins/windows.piiat.registry.jsonl` — Tcpip Interface `{89b3e14f-e403-4965-be04-aaeceb0a4e2f}`; ComputerName under `...\Control\ComputerName\ComputerName`.
- Memory COMPUTERNAME env: `/opt/github/DX_DFIR/data_store/processed/volatility/memdump.mem/plugins/windows.piiat.processes.jsonl` (EnvVars `COMPUTERNAME=BGP-WS1-CONF`).
- CAR normalised host / empty network tables: `/opt/github/DX_DFIR/data_store/processed/volatility/memdump.mem/car.db`.
- Zeek DNS/flow/C2: `/opt/github/DX_DFIR/data_store/processed/zeek/DFIRdump_FOR_200_capture_pcap/{conn,dns,http,ssl,x509}.json`; second capture `/opt/github/DX_DFIR/data_store/processed/zeek/ME_FOR_1308_pcapng/conn.json`.
- 5g-webui FQDN cert: `/opt/github/DX_DFIR/data_store/processed/log2timeline/jsonl/5g-webui.jsonl` (`berylia` matches → `/srv/certs/5g-webui.sac.baf.10.berylia.org_cert.crt`).
- Sysmon host: `/opt/github/DX_DFIR/data_store/processed/windows_logs/unspecified_host/log_EvtxECmd_Output.json` (`Computer = DESKTOP-M913391`).
- LoneWolf host: `/opt/github/DX_DFIR/data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (`image_hostname = DESKTOP-PM6C56D`).
