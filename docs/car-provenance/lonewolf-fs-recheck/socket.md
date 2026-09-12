# CAR `socket` — FILESYSTEM/disk Property-Provenance Audit (unmined-artefact hunt)

FS/disk companion to the earlier memory-grounded catalogue (`../socket.md`).
That pass established the **live/memory** truth: the *only* active socket source in this pipeline is
Volatility3 `windows.piiat.network`/`netscan` → `socket`/`listen` (memory), and WFP 5158 → `socket`/`bind`
is built-but-inert. **This pass asks a different question: what DISK artefacts record a bound/listening
socket, and does the pipeline mine them?** Answer up front: **socket is a runtime object — disk evidence is
thin, and what little exists is *policy/config*, not an observed bind.** But there is one real, sizeable,
completely-unmined seam: **the Windows Firewall rule set in the registry.**

- **Evidence (real):** `data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (6.6 GB, LoneWolf
  Win10 via plaso). Every count/example below is measured on this file this pass.
- **Maps under audit:** `byakugan/byakugan/mappings/plaso_registry.py` (claims every
  `windows:registry:*` type as `registry`/`key_edit`), `plaso_artifacts.py`, `plaso_fs_extra.py`,
  `plaso_linux.py`. Memory socket map for the field vocabulary:
  `third_party/piiat-mem/piiat_mem/mappings.py` `_SOCKET_MAP`.
- **CAR `socket` fields (car_data_model.json):** `family, image_path, local_address, local_path,
  local_port, pid, protocol, remote_address, remote_port, success`; actions `bind, listen, close`.

## 0. Headline

- **NO disk→`socket` mapping exists anywhere in the pipeline.** `grep` for socket emission across
  `mappings/*.py` returns only the memory package (`piiat-mem`). Every plaso mapping routes to
  `file`/`registry`/`process`/`user_session`/`flow`/`http` — **never `socket`.** So 100 % of the disk
  socket surface below is UNMINED.
- **The one real seam: `SharedAccess\...\FirewallPolicy\FirewallRules`** in the SYSTEM hive. Each rule is a
  pipe-delimited REG_SZ string carrying **`Dir` + `Protocol` + `LPort`/`RPort` + `App` + `Svc`** — i.e. a
  *configured* per-app inbound listener (`image_path`+`local_port`+`protocol`+direction). Measured on
  LoneWolf: **895 `Dir=In` rules carry an `LPort`** (≈298 per VSS snapshot) across 40 distinct `App`
  binaries. This is a **policy**, not an observed bind — heuristic/config confidence — but it is exactly the
  socket local-end tuple, and today it is invisible at field level.
- **The data is ALREADY in the CAR store, just not projected.** `plaso_registry.py` claims the
  `FirewallRules` key as a `registry`/`key_edit` row and keeps its `values` list in `_native.values`
  (`native_extract: {"values": _R("values")}`). But — per the prior `registry.md` finding — the marker set
  cannot index a list, and nothing parses the rule grammar, so the `Dir`/`LPort`/`App` tuple stays as opaque
  REG_SZ text. Mining it needs **no disk re-read** — a downstream value-explode + grammar-parse.
- **PortProxy exists but is EMPTY on this image** (default). Populated, it is the strongest disk artefact of
  all (a real `bind`+`remote` forward). **hosts/services/IIS configs are present only as `fs:stat`
  filenames** — plaso never parses their content, so their ports/bindings are unrecoverable without a new
  parser. SSH/PuTTY: **absent** from this image.

---

## 1. Corpus facts (measured this pass on `DESKTOP-PM6C56D.jsonl`)

- **`FirewallRules` registry keys: 3 distinct locations**, each captured 3× (VSS snapshots ×3 → 9 records):
  1. `HKLM\System\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules` — OS default set
  2. `HKLM\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules` — **effective/
     active set** (where user- or malware-added rules land; the T1562.004 forensic target)
  3. `HKLM\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules`
     — UWP app-container isolation rules
  - Each is a single `windows:registry:key_value` record (parser `winreg/winreg_default`) with a **`values`
    LIST** (the first Defaults record alone holds **356** rule values).
- **Rule-grammar tally over the 9 records (VSS-inflated ~3×; per-snapshot ≈ ⅓):**
  `Dir` = In **1604** / Out **1362**; `Protocol` = 6/TCP **1159**, 17/UDP **734**, 58/ICMPv6 165, 1/ICMPv4 33,
  47/GRE 12, 41/IPv6 12, 2/IGMP 12; **`Dir=In` WITH `LPort` = 895** (the configured-listener seam);
  `Dir=Out` WITH `RPort` = 414; rules with `RA4=`/`RA6=` (remote-address scope) = 978; **40 distinct `App`**
  paths, **36 distinct `Svc`** names.
- **Rule string grammar (verbatim example):**
  `v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=9955|App=%SystemRoot%\system32\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37003|...`
  Sample configured inbound listeners (App, LPort, Proto, Svc, Action, Active):
  `svchost.exe/9955/TCP/AJRouter/Allow/TRUE`, `svchost.exe/1900/UDP/Ssdpsrv/Allow/FALSE`,
  `svchost.exe/68/UDP/dhcp/Allow/TRUE`, `svchost.exe/546/UDP/dhcp/Allow/TRUE`, `System/10247/TCP/-/Allow/TRUE`,
  `svchost.exe/Teredo/UDP/iphlpsvc/Allow/TRUE`.
- **PortProxy:** `HKLM\System\ControlSet001\Services\PortProxy` present, message `(empty)`, **no values** — no
  `netsh interface portproxy` forwarding configured on this host.
- **`RpcEptMapper\Parameters`:** present (`ServiceDll: RpcEpMap.dll`), **no port** — RPC endpoints are dynamic
  (assigned at runtime), never on disk.
- **`applicationHost.config` / `web.config`:** present but as **`data_type: fs:stat` (parser `filestat`)**
  only — e.g. `…\WinSxS\…servercommon…\applicationHost.config`. Content (the `<binding>` ports) is **not
  parsed** by plaso; IIS is not even active on this workstation image.
- **`\drivers\etc\hosts` and `\drivers\etc\services`:** present as `fs:stat` file records only (`Type: file`);
  content not parsed.
- **`sshd_config`/`ssh_config`: 0. PuTTY (`SimonTatham`): 0. `iptables`: 0** (Windows image, no Linux).

---

## 2. Per-field provenance — DISK artefacts (all currently UNMINED into `socket`)

Legend — **action**: which socket action the artefact would carry. **mined?**: is there a disk→`socket`
projection today (almost always **NO**). `fs artefact → native field` is the on-disk source column.

| field | fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|---|
| **image_path** | FirewallRules rule string `App=` (e.g. `%SystemRoot%\system32\svchost.exe`) → rule value `data` | bind/listen (configured) | **NO** — ingested as `registry` native `values[]` only; never projected to `socket` | **Med (config).** 40 distinct App paths; svchost dominates (786) so `Svc=` is needed to disambiguate which hosted service. Env-var form (`%SystemRoot%`) needs expansion. It is the *permitted* binary, not an observed bind. |
| **local_port** | FirewallRules `LPort=` on `Dir=In` rules → rule value `data` | bind/listen (configured) | **NO** | **Med (config).** 895 In-rules carry LPort. **Caveat: not always numeric** — keywords (`Teredo`, `RPC`, `RPC-EPMap`, `IPHTTPS`) and lists/ranges (`137,138`) appear; parser must handle them. A rule is a *policy* — the port may never actually be bound. |
| **protocol** | FirewallRules `Protocol=` (`6`→TCP, `17`→UDP) → rule value `data` | bind/listen (configured) | **NO** | **Med (config).** Needs numeric→name normalize (same fix the inert 5158 map needs). Non-L4 protos also appear (1/58 ICMP, 47 GRE, 41 IPv6, 2 IGMP) — those are not TCP/UDP sockets and should be filtered/kept native. |
| **local_address** | FirewallRules `LA4=`/`LA6=` (local-address scope) → rule value `data` | bind (configured) | **NO** | **Low.** Present on few rules; most inbound app rules omit it (wildcard `0.0.0.0`/`::`). It is an *allowed local scope*, not the actual bound address. |
| **remote_address** | FirewallRules `RA4=`/`RA6=` (remote-address scope) on scoped rules → rule value `data`; **PortProxy** `connectaddress` | (Out) / bind+forward | **NO** | **Low.** 978 rules carry RA4/RA6, but these are *allowed peer ranges* (often `LocalSubnet`, `Intranet`, a CIDR), not an observed remote end — and a socket with a live remote end is a `flow` here anyway. PortProxy would give a real forward target but is **empty** on LoneWolf. |
| **remote_port** | FirewallRules `RPort=` on `Dir=Out` rules; **PortProxy** `connectport` | (Out) / bind+forward | **NO** | **Low.** 414 Out-rules carry RPort — but an outbound-to-remote-port rule is `flow`-shaped, not a bound socket. PortProxy `connectport` would be the true bind+remote pairing; empty here. |
| **pid** | — (no disk artefact) | — | **NO (honest null)** | A firewall rule / portproxy / config file records **policy**, never the runtime PID that binds. `Svc=`/`App=` are the join keys; PID resolves only at runtime (memory). Correct null on disk. |
| **family** | weakly inferrable: FirewallRules `RA4/LA4`→ipv4, `RA6/LA6`→ipv6, `Protocol=58`→ipv6 | bind (configured) | **NO** | **Low/weak.** A plain TCP/UDP `LPort` rule is dual-stack (no family). Only address-scoped or ICMPv6 rules hint at family. Don't fake it for the common case. |
| **success** | n/a (const-by-existence does not apply to a policy) | — | **NO (honest n/a)** | Unlike the memory listener (`success=const(True)` — a kernel socket object *proves* a successful bind), a firewall rule proves nothing was ever bound. If projected, `success` must stay **null** (or an explicit `configured`/`Active` flag in native), never `true`. `Active=TRUE/FALSE` is on the rule (many sampled listeners are `FALSE`/disabled). |
| **local_path** | — (AF_UNIX, Linux-only) | — | **NO SOURCE (honest)** | AF_UNIX socket filesystem path. Windows image has no AF_UNIX; `plaso_linux.py` emits only `user_session`+`file` (no socket). Even upstream CAR leaves `local_path` empty. True no-source. |

**Action mapping note.** A firewall *inbound-allow* rule with `LPort`+`App` is the disk analogue of WFP 5158
("bind allowed") → it maps most naturally to **`bind`** (or `listen`) at **config confidence**. It must be
tagged distinctly from the memory `listen` (which is an *observed* steady-state listener) so a consumer never
conflates "the firewall would permit this app to listen on 9955" with "this app is listening on 9955".

---

## 3. Ranked UNMINED opportunities (highest value first)

1. **Parse `FirewallRules` → per-app configured inbound listeners as `socket`/`bind` (config confidence).**
   The single real disk seam. For every `Dir=In` value with an `LPort`: emit `socket`/`bind` with
   `image_path=expand(App)`, `local_port=LPort`, `protocol=map(Protocol,{6:TCP,17:UDP})`, `success=null`,
   plus native `svc=Svc`, `rule_name=name`, `active=Active`, `profile=Profile`, `action=Action`. **≈298
   listeners per VSS snapshot on LoneWolf, 40 distinct binaries.** Requires: (a) explode the registry
   `values` LIST per rule (the same list-flatten the `registry.md` audit already asks for value/data/type),
   (b) a small pipe-grammar parser, (c) numeric-protocol normalize, (d) LPort-keyword handling
   (`Teredo`/`RPC`/ranges). **No disk re-read — the rule strings are already in `_native.values` in the CAR
   store.** Value: it is the *only* way this pipeline gets any socket coverage from a dead disk image.
   Caveat to bake in: it is **policy, not observation** — distinct action/confidence, `success` null.

2. **`Svc=` → service-object join (cross-object enrichment).** The rule's `Svc=AJRouter`/`Ssdpsrv`/`dhcp`
   ties the configured listener to a service already ingested (`windows:registry:service` rows carry
   `name`+`image_path`). Joining lets svchost-hosted rules (786 of them share `svchost.exe`) resolve *which*
   hosted service owns the port — the disambiguation memory does with the real PID. Surfaces as a
   relationship, not a new socket field.

3. **PortProxy → `socket`/`bind`+remote forward (empty here, but wire it).** When
   `…\Services\PortProxy\v4tov4\tcp` (or v4tov6/v6tov4/v6tov6) is populated, each value is
   `<listenaddress>/<listenport> = <connectaddress>/<connectport>` — a genuine **bind (local) + remote
   forward** in one record: `local_address`/`local_port` + `remote_address`/`remote_port`. This is the
   richest disk socket artefact (a real configured redirector, classic T1090 relay). **Zero rows on LoneWolf**
   (parent key empty), so it can't be validated here, but the mapping is worth building against a host that
   has run `netsh interface portproxy add`. Note: plaso renders the parent as one empty `key_value` — the
   forwards live in the typed subkey, which must be captured.

4. **IIS `applicationHost.config` / `web.config` bound ports — needs a new parser (no plaso source).**
   The `<binding protocol="http" bindingInformation="*:80:host" />` elements are real configured listeners,
   but plaso emits these files **only as `fs:stat` filenames** — content is never parsed. Would require a
   dedicated XML binding parser fed the file bytes. Low priority for this corpus (IIS inactive; the hit is a
   staged WinSxS copy), but it is the canonical "web-app bound port on disk" artefact for server images.

5. **`remote_*` from FirewallRules `RA*`/`RPort` / outbound rules — mostly out of scope by design.** 978
   rules carry `RA4/RA6`, 414 carry `RPort`, but a remote endpoint means the record is `flow`-shaped, and the
   values are *allowed peer scopes* (`LocalSubnet`, CIDRs), not observed peers. Only revisit if outbound
   firewall policy should ever be modelled as `socket` rather than dropped — currently correct to leave null.

---

## 4. Honest no-source / correct-null (do NOT "fix") — socket is fundamentally a runtime object

- **`pid`** — no disk artefact records the process that binds. Firewall rule / portproxy / config carry
  `App`/`Svc` (policy identity), never a runtime PID. Correct null from disk; PID is memory's job.
- **`success`** — the memory listener's `success=const(True)` is proven by a kernel object's *existence*; a
  disk policy proves nothing was bound. Any FS projection must leave `success` null. Honest n/a.
- **`local_path` (AF_UNIX)** — Linux-only; no AF_UNIX on the Windows image, and `plaso_linux.py` has no
  socket mapping. Upstream CAR also empty. True no-source (matches the memory pass).
- **`close` action** — no disk artefact records a socket *close* transition. A firewall rule/portproxy is a
  steady-state policy; a config file has no lifecycle. No producer anywhere emits `close`.
- **`family`** — largely absent from disk policy (TCP/UDP rules are dual-stack); only weakly inferable from
  `RA6`/`LA6`/ICMPv6. Better left null than faked.
- **`\drivers\etc\hosts`** — present, but it is **name→IP resolution**, not a socket bind. And plaso records
  only its `fs:stat`; content unparsed. Not a socket source even in principle.
- **`\drivers\etc\services`** — present, but it is the **static IANA service-name↔port lookup table** shipped
  with every Windows box; it proves nothing is bound to those ports. Content unparsed (fs:stat only). Not a
  socket source.
- **`RpcEptMapper` / `\Rpc\` keys** — present, but RPC endpoints are **dynamic** (ncacn_ip_tcp ports assigned
  at runtime); the registry holds `ServiceDll`/config, never a bound port. No local_port from disk.
- **SSH / PuTTY config** — absent from this image (0 hits); on a host that had them, `sshd_config Port 22` /
  PuTTY `PortForwardings` would be config-level listener/forward evidence needing bespoke parsers — but plaso
  ships no parser for either (config file → `fs:stat` filename only).
- **Scheduled tasks that open listeners** — 1,454 `task_scheduler:task_cache:entry` rows exist, but a task's
  *action* is a command line; whether that command binds a port is opaque on disk (would require parsing the
  target binary's behaviour). No disk field expresses a task-opened socket.

## 5. Cross-reference to the memory pass (`../socket.md`)

- **Consistent:** that pass found the active socket object is memory-only / `listen`-only / local-end-only,
  with WFP 5158 `bind` inert and `remote_*`/`local_path`/`close` unsourced. This FS pass confirms **disk adds
  no *observed* socket at all** — only *policy* (firewall rules) and, potentially, a *configured forward*
  (portproxy).
- **New here:** the FirewallRules seam (895 In+LPort rules, 40 apps, already sitting unparsed in
  `_native.values`) is a concrete, no-disk-re-read way to give a dead-disk image *some* socket local-end
  coverage — at explicit config/heuristic confidence, `bind` action, `success` null. It is the disk cousin of
  the inert 5158 `bind` map and shares the same protocol-normalize fix.
- **Honest bottom line:** socket's real home is memory/live. The FS contribution is one policy seam worth
  mining (firewall rules), one empty-here-but-worth-wiring seam (portproxy), and a set of genuine no-sources
  that should stay null rather than be faked from name-resolution or static OS files.
