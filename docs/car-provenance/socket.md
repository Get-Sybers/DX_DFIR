# Property-Provenance Catalogue — MITRE CAR `socket`

**Object:** `socket` — *"Socket events are low-level events that may or may not result in a flow. Socket
listening events in particular can be helpful in detecting malicious activity."*
**Canonical fields (10):** `family`, `image_path`, `local_address`, `local_path`, `local_port`, `pid`,
`protocol`, `remote_address`, `remote_port`, `success`
**Actions (3):** `bind`, `listen`, `close`
**Repo:** `/opt/github/DX_DFIR` — READ-ONLY audit, evidence as of 2026-09-07.

Grounded in:
- `third_party/piiat-mitrecar/third_party/car/data_model/socket.yaml` + `docs/data_model/socket.md` (semantics + upstream coverage map)
- `car_data_model.json` (canonical field/action list — matches the object header above exactly)
- `third_party/piiat-mitrecar/model/{car,projection}/objects/socket.yml` (reconstructed CAR object + ECS projection)
- CAR sensors `third_party/piiat-mitrecar/third_party/car/sensors/{osquery_4.6.0,auditd_2.8}.yaml`

---

## TL;DR — the honest state

- **Exactly ONE active socket source ships in this pipeline: MEMORY (Volatility 3 netscan/netstat / `windows.piiat.network`) via PIIAT-Mem → CAR `socket`/`listen`.** It is the primary (only) dead-box socket source.
- That memory source only produces the **`listen`** action and only the **local-end** fields (`local_address`, `local_port`, `protocol`, `family`, `pid`, `success`) + `image_path` **by enrichment**. It never asserts `remote_*` or `local_path`, and never `bind`/`close`.
- **Windows Security 5158 (WFP bind) → `socket`/`bind` exists but is INERT** — quarantined in `third_party/piiat-mitrecar/to-be-validated/evtx_audit.yml`, not in the active `mappings/` package.
- **Sysmon 3, WFP 5156/5157 are mapped to `flow`, NOT `socket`** (deliberate — the connection "as made"). **5031 firewall block is not referenced anywhere in the repo.**
- No `socket` source exists for **`remote_address`, `remote_port`, `local_path`, or the `close` action** — honest no-source (matches even the upstream CAR coverage map, which leaves `local_path` and `success` empty and has no non-osquery sensor).
- **The current evidence corpus contains ZERO socket rows** — no netscan/netstat/`piiat.network` output was collected into `data_store/processed/volatility/…`, and the EvtxECmd corpus has only Sysmon 1/5 (no 5158, no Sysmon 3). The capability is present but unexercised.

---

## Source universe (what can, in principle, supply a `socket` row) — status in THIS repo

| Source | Native table/event | → CAR object here | socket status |
|---|---|---|---|
| **Volatility 3 `windows.netscan` / `windows.netstat` / `windows.piiat.network`** (PIIAT-Mem) | bound/LISTENING pooled `_TCP/UDP` endpoint objects | **`socket`/`listen`** (via `is_bound_socket` predicate) | **ACTIVE** — `third_party/piiat-mem/piiat_mem/mappings.py` `_SOCKET_MAP` |
| **Security 5158** (WFP "connection bind allowed") | `SourceAddress/SourcePort/Protocol/Application/ProcessID` | **`socket`/`bind`** | **INERT** — `to-be-validated/evtx_audit.yml` key `security_5158_wfp_bind` |
| osquery 4.6.0 `socket_events` | (bind/listen/close) | `socket` bind/listen/close **(upstream CAR coverage map only)** | **NOT INGESTED** — no osquery collector or mapping in this repo |
| Sysmon 3 (NetworkConnect) | `SourceIp/DestinationIp/…/Initiated` | **`flow`/`start`** (`mappings/sysmon.py` EID 3) | routed to flow, **not socket** |
| Security 5156 / 5157 (WFP conn allowed/blocked) | `SourceAddress/DestAddress/…` | **`flow`** start/message | routed to flow (5156/5157 in the same `to-be-validated` file) |
| Security 5031 (firewall blocked an app) | — | — | **not referenced anywhere in repo** |
| Linux auditd `SOCKADDR` / `ss` / `netstat` / `/proc/net` / systemd:journal | `saddr` (AF_UNIX path, AF_INET addr/port) | — | **NOT IMPLEMENTED** — `mappings/plaso_linux.py` emits only `user_session` + `file` |
| Vol2 `sockscan`/`sockets` | — | — | not used (Vol3 line; superseded by netscan) |
| Zeek/Suricata | conn/flow records | `flow` / `http` (flow-side) | not socket |

---

## Per-field provenance

Legend — **action**: which socket action the row carries. **mapped?**: `yes+where` / `INERT+where` / `NO`.
`native → field` is the source column feeding the CAR field.

### `family` — AF_INET / AF_INET6 / AF_UNIX (socket type)
| source (native → field) | action | mapped? | confidence & caveats |
|---|---|---|---|
| Vol3 netscan `Proto` → `family()` | listen | **yes** — piiat-mem `mappings.py` `_SOCKET_MAP` (`family("Proto")`) | **Med.** Value form diverges: emits **`ipv4`/`ipv6`** (ECS-style, from `TCPv4`→`ipv4` in `normalize.py`), **not** the CAR-documented `AF_INET`/`AF_INET6`. Consequence: the STIX `_b_socket` `socket-ext` gate (`str(fam).startswith("AF_")` in `stix.py:995`) never fires, so `address_family`/`is_listening` are dropped from the STIX SCO — though the CAR field itself is populated. Windows memory is only ever ipv4/ipv6, **never AF_UNIX**. |
| Security 5158 WFP | bind | **NO** — 5158 map omits `family` entirely | — |
| osquery `socket_events` | bind/listen/close | NO (not ingested) | upstream coverage lists osquery for family |

### `image_path` — path to the executable that acted on the socket
| source (native → field) | action | mapped? | confidence & caveats |
|---|---|---|---|
| Vol3 netscan (owning process) | listen | **yes (by ENRICHMENT)** — piiat-mem `enrich.py` `_INHERIT` (line 72) fills `image_path` from the owning process | **High.** NOT native to the netscan row (netscan `Owner` = `ImageFileName`, the process **name** only, no path — `plugins/windows/piiat/network.py:17`). Filled from the owner's `image_path`, joined **definitively** on `OwnerOffset` (the kernel `_EPROCESS` pointer), falling back to (reusable) PID. Null if the owning process isn't recovered. |
| Security 5158 WFP `Application` → `image_path` | bind | **INERT** — `to-be-validated/evtx_audit.yml` (`image_path: Application`) | Native full path when promoted; inert today. |
| osquery `socket_events` | bind/listen/close | NO (not ingested) | upstream coverage lists osquery |

### `local_address` — IP the socket accepts on (no port)
| source (native → field) | action | mapped? | confidence & caveats |
|---|---|---|---|
| Vol3 netscan `LocalAddr` → `local_address` | listen | **yes** — `_SOCKET_MAP` | **High.** `0.0.0.0`/`::` legitimately appears for wildcard listeners (also the `is_bound_socket` trigger). |
| Security 5158 WFP `SourceAddress` → `local_address` | bind | **INERT** — `to-be-validated/evtx_audit.yml` | High once promoted. |
| osquery `socket_events` | bind/listen/close | NO (not ingested) | upstream |

### `local_path` — AF_UNIX socket filesystem path (`/tmp/foo`)
| source (native → field) | action | mapped? | confidence & caveats |
|---|---|---|---|
| — | — | **NO SOURCE (honest gap)** | Only a **Linux/AF_UNIX** concept. Would require **auditd `SOCKADDR`** (`saddr` unix path) — not implemented (`plaso_linux.py` has no socket mapping). Windows memory netscan is IP-only; 5158 has no path. **Even the upstream CAR coverage map leaves `local_path` empty for all three actions** (`docs/data_model/socket.md`). The ECS projection reserves `local_path → file.path` (`model/projection/objects/socket.yml`), but nothing feeds it. |

### `local_port` — bound port at the local end
| source (native → field) | action | mapped? | confidence & caveats |
|---|---|---|---|
| Vol3 netscan `LocalPort` → `local_port` | listen | **yes** — `_SOCKET_MAP` | **High.** |
| Security 5158 WFP `SourcePort` → `local_port` | bind | **INERT** — `to-be-validated/evtx_audit.yml` | High once promoted. |
| osquery `socket_events` | bind/listen/close | NO (not ingested) | upstream |

### `pid` — process that acted on the socket
| source (native → field) | action | mapped? | confidence & caveats |
|---|---|---|---|
| Vol3 netscan `PID` → `pid` (+ `owning_pid=PID`, `owning_offset=OwnerOffset`) | listen | **yes** — `_SOCKET_MAP` | **High.** The `pid` value is the heuristic/reusable owner PID (kept for humans); the **definitive** process linkage is `OwnerOffset` (`network.py:16` "reusable PID is only a heuristic"). |
| Security 5158 WFP `ProcessID` (**decimal**) → `pid` | bind | **INERT** — `to-be-validated/evtx_audit.yml` | Note: WFP `ProcessID` is decimal (unlike hex 4663 `ProcessId`). |
| osquery `socket_events` | bind/listen/close | NO (not ingested) | upstream |

### `protocol` — TCP / UDP
| source (native → field) | action | mapped? | confidence & caveats |
|---|---|---|---|
| Vol3 netscan `Proto` → `transport()` → `TCP`/`UDP` | listen | **yes** — `_SOCKET_MAP` (`transport("Proto")`) | **High.** Clean `TCPv4`→`TCP` extraction (`normalize.py`). |
| Security 5158 WFP `Protocol` → `protocol` (**raw**) | bind | **INERT** — `to-be-validated/evtx_audit.yml` | **Caveat:** mapped **raw** (numeric IP proto `6`/`17`), *not* normalized — unlike sibling 5156/5157 which apply `map_value(Protocol,{6:tcp,17:udp})`. Fix on promotion. |
| osquery `socket_events` | bind/listen/close | NO (not ingested) | upstream |

### `remote_address` — IP at the remote end
| source (native → field) | action | mapped? | confidence & caveats |
|---|---|---|---|
| — | — | **NO SOURCE (by design)** | A socket with a live remote end **is a connection → modeled as `flow`, not `socket`** in every producer here. Memory netscan keeps `ForeignAddr` only as `keep` native (never mapped to `remote_address`); non-listening rows route to `_FLOW_MAP`. 5158 `bind` is local-only. The STIX/`_network` plumbing (`stix.py:989`) *reads* `remote_address` if present, but no mapping ever sets it. osquery upstream lists it, but osquery isn't ingested. |

### `remote_port` — port at the remote end
| source (native → field) | action | mapped? | confidence & caveats |
|---|---|---|---|
| — | — | **NO SOURCE (by design)** | Same as `remote_address`: a remote endpoint means it's a `flow`. `ForeignPort` retained as native only. |

### `success` — did the socket op succeed
| source (native → field) | action | mapped? | confidence & caveats |
|---|---|---|---|
| Vol3 netscan → `const(True)` | listen | **yes** — `_SOCKET_MAP` (`"success": const(True)`) | **High-but-inferential.** Not observed — **proven by existence**: "a kernel socket object exists only after a successful bind/listen" (`mappings.py:51`, CHANGELOG). Never `false` (no failure events captured). |
| Security 5158 WFP → `const(true)` | bind | **INERT** — `to-be-validated/evtx_audit.yml` (`success: const(true)`) | Same existence inference (5158 is the *allowed* bind). A *blocked* bind has no distinct EID mapped. |
| osquery `socket_events` | — | NO | **Upstream CAR coverage map also leaves `success` EMPTY** — no sensor supplies it upstream either. |

---

## Action coverage

| action | source(s) | mapped? | note |
|---|---|---|---|
| **`listen`** | Vol3 memory netscan/netstat/`piiat.network` | **yes (ACTIVE)** — piiat-mem `_SOCKET_MAP action=listen` | A memory snapshot sees the **steady-state** listener → `listen`. This is the entire active socket object. |
| **`bind`** | Security 5158 WFP | **INERT** — `to-be-validated/evtx_audit.yml` | Schema-grounded, not sample-verified; absent from all corpora. |
| **`close`** | — | **NO SOURCE** | No producer emits `close`: a memory snapshot can't observe a close transition; no WFP close EID is mapped; osquery upstream has it but isn't ingested. |

Minor: the cascade verb map (`piiat_mitrecar/cascade_relationships.yml:38`) declares only `socket: bind: "bound to"` — the **active `listen`** action falls through to `default_spoke_verb: accessed`. Cosmetic (STIX/relations narration), not a data gap.

---

## Coverage summary

**What ships (active):** memory-only, `listen`-only, local-end-only.
`socket`/`listen` from Vol3 netscan/netstat/`windows.piiat.network` → `local_address`, `local_port`,
`protocol`, `family`(as ipv4/ipv6), `pid`, `success`(const) natively + `image_path` by owner-inheritance.
Windows AF_INET/INET6 only. 4 of 10 fields have **no** active source (`local_path`, `remote_address`,
`remote_port`, and — for the `bind`/`close` actions — everything).

**What's built but inert:** `socket`/`bind` from **WFP 5158** (`to-be-validated/evtx_audit.yml`) — adds the
`bind` action + `local_address`/`local_port`/`protocol`/`image_path`/`pid`/`success`.

**What has no source at all:** `local_path` (AF_UNIX / auditd), `remote_address`/`remote_port` (those are
`flow` by design), the `close` action.

### UNMAPPED gaps, ranked

1. **Memory socket capability ACTIVE but UNEXERCISED in the corpus (collection gap).** `data_store/processed/volatility/memdump.mem/plugins/` contains only `banners`, `mftscan`, `piiat.processes`, `piiat.registry`, `piiat.sessions`, `pslist` — **no `netscan`/`netstat`/`windows.piiat.network` output**. So the *entire* listen/bind socket object is invisible in current evidence. **Fix: run `windows.piiat.network` (or `netscan`/`netstat`) over `memdump.mem`** — the map already handles the output 1:1 (passthrough via `pipeline.py:150`). Highest value, zero code.
2. **Promote WFP 5158 (`to-be-validated/evtx_audit.yml` → active `mappings/*.py`).** The only path to the **`bind`** action and to socket coverage from Windows event logs. Needs a capture with the *Filtering Platform Connection* auditpol subcategory enabled to validate, then port back (prior impl in git history: `mappings/evtx_audit.py`). **On promotion, fix `protocol` to normalize** (`map_value(Protocol,{6:tcp,17:udp})`) rather than passing the raw numeric, to match the memory source's `TCP`/`UDP`.
3. **`family` value-form normalization.** Memory emits `ipv4`/`ipv6`; the STIX `socket-ext` gate expects `AF_*` and silently drops the extension. Decide one canonical form (CAR docs say `AF_INET`; ECS projection says `ipv4`) and align emitter + STIX gate.
4. **`remote_address`/`remote_port` — no socket source (by design).** Only worth revisiting if an *established* (non-listening) endpoint should ever be represented as `socket` rather than `flow`. Currently intentional; low priority.
5. **`local_path` (AF_UNIX) — true no-source.** Would require **Linux auditd `SOCKADDR`** ingestion (`plaso_linux.py` currently emits only `user_session` + `file`). Even upstream CAR has no source for it. Lowest priority.
6. **`close` action — no source anywhere.** Would need a lifecycle-observing sensor (osquery `socket_events`, ETW, or auditd) that this pipeline doesn't ingest.
