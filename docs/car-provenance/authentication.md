# Property-Provenance Catalogue — MITRE CAR `authentication`

**Object:** `authentication` — "An authentication event occurs whenever a user or process attempts to access a privileged system resource. Examples include logging into a system, or elevating privilege."
**Actions:** `success` · `failure` · `error`
**Canonical fields (19):** ad_domain, app_name, auth_service, auth_target, decision_reason, fqdn, hostname, method, response_time, target_ad_domain, target_uid, target_user, target_user_role, target_user_type, uid, user, user_agent, user_role, user_type

**Ground truth read:**
- Semantics: `third_party/piiat-mitrecar/third_party/car/data_model/authentication.yaml`, `.../docs/data_model/authentication.md`, root `car_data_model.json` (13 objects; authentication actions = error/failure/success — confirmed).
- Engine maps: `third_party/piiat-mitrecar/piiat_mitrecar/mappings/core.py` (the ONLY authentication mapper), generated source spec `third_party/piiat-mitrecar/sources/evtx_security.yaml`.
- Design law: `third_party/piiat-mitrecar/docs/CAR-Relations.md` (authentication ← 4624/4625; identity/joins/inheritance/limits).
- Real evidence inspected: `data_store/processed/windows_logs/unspecified_host/log_EvtxECmd_Output.json` (85 records — **Sysmon EID 1/45 & 5/40 only, NO Security channel**), `data_store/processed/zeek/*/ssh.json` (real SSH auth, `auth_success` present), zeek dirs (conn/dns/files/http/notice/ssh/ssl/weird/x509 — **no kerberos/ntlm/radius/smtp**), `data_store/processed/linux_logs/` (empty).

---

## 1. What the pipeline maps TODAY (the whole of it)

**One mapper, one artefact key, three EventIds.** `core.py` → source `evtx_security` (EvtxECmd, Windows Security channel):

| EventId | Action | Fields populated (per `evtx_security.yaml` field_provenance) |
|---|---|---|
| **4624** (success logon) | `success` | ad_domain, app_name, auth_service, auth_target, hostname, method, target_ad_domain, target_uid, target_user, uid, user (+ user_role via 4672 merge) |
| **4625** (failed logon) | `failure` | as above **+ decision_reason** (SubStatus\|Status\|FailureReason, coalesced); no user_role |
| **4672** (special privileges) | `success` | companion entry → **user_role = `administrator`** (const/asserted), user, uid, ad_domain, auth_target only |

**Native (kept for joins, never canonical):** TargetLogonId, SubjectLogonId, LogonType, IpAddress (+ PrivilegeList on 4672). LUID (`TargetLogonId`/`SubjectLogonId`) is the designed join to `user_session`; `ProcessId` (hex) is the heuristic join to `process`.

**Deliberately NOT mapped (documented):** 4648 (explicit-cred logon at issuance — no service response, asserting success/failure would fake an outcome — `core.py:184`, `CAR-Relations.md:44`).

**Nothing else in the repo produces `authentication`:** the only two sources whose YAML mentions the word are `evtx_security.yaml` (the mapper) and `l2t_text.yaml` (only in a native-keys note — it maps SSH syslog to **user_session/login**, not authentication). PIIAT-Mem emits 10 objects (driver/file/flow/module/process/registry/service/socket/thread/user_session) — **not authentication** (its token `AuthenticationId` LUID feeds `user_session.login_id`). Sysmon has no authentication object. Zeek mappers emit email/file/flow only. **No analytic references `authentication/*` in structured `data_model_references`** (0 of 91) — it is consumed only in prose.

---

## 2. Field-by-field provenance

Legend — **Mapped?**: `YES` (+ where) / `NO`. Native field shown as `Source → NativeField`. "Origin" = host the request was made *from*; "target/dest" = machine authenticated *to*.

### ad_domain — AD domain the request was generated from (subject side)
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx Security **4624/4625** → `SubjectDomainName` | success, failure | **YES** — `core.py:_auth_props` `ad_domain` | HIGH. Often the *machine/SYSTEM* context on network logons, not a person. |
| evtx **4672** → `SubjectDomainName` | success | **YES** (companion) | HIGH |
| evtx Kerberos **4768/4769** → `TargetDomainName` is target-side; subject realm implicit | success, failure | **NO** | MED — 4768/4769 not mapped |
| zeek **ntlm.log** → `domainname` | success, failure | **NO** | MED — no ntlm mapper/evidence |
| zeek **kerberos.log** → realm (in `client`/`service`) | success, failure | **NO** | LOW-MED |

### app_name — application that made the request
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4624/4625** → `ProcessName` (basename) | success, failure | **YES** — `app_name` `[derived]` | HIGH. Calling process image, e.g. `winlogon.exe`, `svchost.exe`. |
| evtx **4648** → `ProcessName` | (issuance) | **NO** | MED — 4648 unmapped |
| syslog auth/secure (Plaso `syslog`) → program (`sshd`/`sudo`/`su`/`login`) | success, failure | **NO** | HIGH-value, unmapped — maps to user_session today |
| zeek **ssh.log** → `client` (e.g. `SSH-2.0-OpenSSH_for_Windows_8.1`) | success, failure | **NO** | MED — client banner, not strictly app_name |
| zeek **kerberos.log** → `service` (SPN class) | success | **NO** | LOW |
| model example `ssh, win:local` | — | — | The canonical example values. |

### auth_service — service used to accomplish authentication
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4624/4625** → `LogonProcessName` | success, failure | **YES** — `auth_service` `[direct]` | HIGH. e.g. `NtLmSsp`, `Kerberos`, `User32`, `Negotiate`, `Advapi`. |
| evtx **4776** → `PackageName` (DC NTLM validation) | success, failure | **NO** | MED — 4776 unmapped |
| Cloud IdP (Okta / AzureAD / ADFS) sign-in logs | success, failure | **NO** | Model examples are `Okta, ActiveDirectory` — out of scope for this host/network pipeline. |

### auth_target — machine for which authentication was requested (destination)
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4624/4625** → `Computer` | success, failure | **YES** — `auth_target: "Computer"` `[direct]` | HIGH. The host authenticated TO (opposite direction from `hostname`). |
| evtx **4672** → `Computer` | success | **YES** (companion) | HIGH |
| evtx **4648** → `TargetServerName` / `TargetInfo` | (issuance) | **NO** | HIGH-value, unmapped — 4648 explicitly names the target server. |
| evtx **4769** → `ServiceName`/`ServiceSid` (SPN) | success, failure | **NO** | MED |
| zeek **ntlm.log** → `server_nb_computer_name` / `server_dns_computer_name` | success, failure | **NO** | MED |
| zeek **kerberos.log** → `service` | success | **NO** | MED |
| zeek **radius.log** → `remote_ip` / NAS | success, failure | **NO** | LOW-MED |
| zeek **ssh.log** → `id.resp_h` | success, failure | **NO** | MED — dest IP, real evidence on hand |

### decision_reason — justification for approve/deny (**failure/error only**)
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4625** → `SubStatus` \| `Status` \| `FailureReason` (coalesced) | failure | **YES** — `core.py:153` | HIGH. NTSTATUS carries the real why (`0xC000006A` bad pw, `0xC0000064` no user, `0xC0000234` locked); `FailureReason` is an unresolved `%%` token. |
| evtx **4776** → `Status` (NTLM validation code) | failure | **NO** | MED |
| evtx Kerberos **4768/4769/4771** → `Status` (Kerberos result, `0x18` bad pw, `0x12` disabled) | failure | **NO** | MED-HIGH — richest DC-side failure reason, unmapped |
| zeek **kerberos.log** → `error_msg` | failure, error | **NO** | MED |
| zeek **ntlm.log** → `status` | failure | **NO** | MED |
| syslog auth → `Failed password` / `invalid user` / PAM `authentication failure` | failure | **NO** | HIGH-value, unmapped |
| IIS W3C → `sc-status` / `sc-substatus` (401.x) | failure | **NO** | LOW-MED |

### fqdn — FQDN of the origin host
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| Host-identity enrichment / DNS resolution of origin `IpAddress` | success, failure | **NO** | CAR-Relations: `fqdn ← host identity` by **inheritance**, not from the auth record. |
| evtx 4624/4625 | — | **NO** | **No native source** — `WorkstationName` is NetBIOS, `Computer` is the *destination*. |

**Near no-source in-record.** Only obtainable by enriching the origin IP against DNS/host identity; the event itself has no origin FQDN.

### hostname — origin host the request was made from
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4624/4625** → `WorkstationName` | success, failure | **YES** — `hostname` `[direct]` | HIGH but **client-reported/forgeable — recorded not trusted**; no fallback to `Computer` (that is the destination). |
| utmp/wtmp/btmp (Plaso `utmp`) → `ut_host` / `hostname` (origin) | success, failure | **NO** | MED — kept native in l2t_utmp (user_session), not surfaced to auth |
| syslog auth → `rhost` / `from <IP>` (origin, usually IP) | success, failure | **NO** | MED — IP not hostname |
| zeek ssh/ntlm/kerberos → `id.orig_h` (origin IP) | success, failure | **NO** | MED — IP, real ssh evidence on hand |
| evtx **4776** → `Workstation` | success, failure | **NO** | MED |

### method — authentication method used
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4624/4625** → `AuthenticationPackageName` | success, failure | **YES** — `method` `[direct]` | HIGH. `NTLM`/`Kerberos`/`Negotiate`. **`Negotiate` = negotiated — never assert NTLM vs Kerberos** (CAR-Relations limit). |
| evtx **4768/4769** → `TicketEncryptionType` (Kerberos enctype) | success, failure | **NO** | MED |
| evtx **4776** → `PackageName` | success, failure | **NO** | MED |
| syslog auth → `password` / `publickey` / `keyboard-interactive` (sshd) | success, failure | **NO** | HIGH-value — real SSH method, currently kept as native `authentication_method` in `l2t_text`/`plaso_linux.py` (user_session), **not** surfaced to `authentication.method`. |
| zeek **kerberos.log** → `cipher` | success | **NO** | LOW-MED |
| zeek **ssh.log** | — | **NO** | Default ssh.log does **not** record password-vs-pubkey (encrypted). |

### response_time — duration until the auth response
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| — | — | **NO** | **NO SOURCE.** No host/network DFIR artefact records auth-response duration. (Zeek `conn.duration` is the *connection*, not the auth decision.) Model example `12ms` is cloud/API telemetry. Honest null everywhere. |

### target_ad_domain — AD domain within which authentication was requested (target side)
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4624/4625** → `TargetDomainName` | success, failure | **YES** — `target_ad_domain` `[direct]` | HIGH |
| evtx Kerberos **4768/4769/4771** → `TargetDomainName` (realm) | success, failure | **NO** | MED |
| zeek **ntlm.log** → `domainname`; **kerberos.log** → realm | success, failure | **NO** | MED |

### target_uid — SID of the user being authenticated
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4624/4625** → `TargetUserSid` | success, failure | **YES** — `target_uid` `[direct]` | HIGH |
| evtx **4768/4771** → `TargetSid` | success, failure | **NO** | MED |
| Memory (Volatility `sessions`/token owner SID); getsids | (inferred) | **NO** | LOW — memory feeds user_session, not auth |

### target_user — name of the user being authenticated (the actual principal)
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4624/4625** → `TargetUserName` | success, failure | **YES** — `target_user` `[direct]` | HIGH. (MITRE's "priv-esc only" clause is its own copy-paste error — Windows fills it every logon — noted in `core.py:74`.) |
| evtx **4648** → `TargetUserName` | (issuance) | **NO** | HIGH-value, unmapped |
| evtx **4768/4769/4771** → `TargetUserName`; **4776** → `TargetUserName` | success, failure | **NO** | HIGH-value — the DC-side authenticated account |
| zeek **ntlm.log** → `username` | success, failure | **NO** | MED |
| zeek **kerberos.log** → `client` | success | **NO** | MED |
| zeek **radius.log** → `username` | success, failure | **NO** | LOW-MED |
| syslog auth → `Accepted/Failed password for <USER>`; su/sudo target `USER=` | success, failure | **NO** | HIGH-value, unmapped |
| zeek **ssh.log** | — | **NO** | No username (encrypted) in default ssh.log. |

### target_user_role — IPAM access-control role of the target user (priv-esc only)
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| IPAM (Infoblox) directory | — | **NO** | **Effectively no source** in a host/network pipeline — the field is IPAM-specific by definition. |
| evtx 4672 gives role for the *subject*, not target | — | **NO** | Cannot fill target side. |

### target_user_type — type of the target user (priv-esc only)
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| Derivable from well-known SID RID (500=Administrator, 501=Guest) on `TargetUserSid` | success, failure | **NO** | LOW — derivation, not recorded; not currently done. |
| Memory getsids / SAM group membership of target | (inferred) | **NO** | LOW |
| — | — | **NO direct source.** | The type is not a recorded field on any auth artefact. |

### uid — SID of the process that initiated the request (subject/calling context)
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4624/4625** → `SubjectUserSid` | success, failure | **YES** — `uid` `[direct]` | HIGH. Often `S-1-5-18` (SYSTEM) on network logons. |
| evtx **4672** → `SubjectUserSid` | success | **YES** (companion) | HIGH |
| evtx **4648** → `SubjectUserSid` | (issuance) | **NO** | MED |
| Memory (`_TOKEN` owner SID) | (inferred) | **NO** | LOW — feeds user_session |

### user — name of the user that initiated the request (subject)
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4624/4625** → `SubjectUserName` | success, failure | **YES** — `user` `[direct]` | HIGH but "the calling context, **never** the person who typed the password" (CAR-Relations limit); often a machine account. |
| evtx **4672** → `SubjectUserName` | success | **YES** (companion) | HIGH |
| evtx **4648** → `SubjectUserName` | (issuance) | **NO** | MED |
| syslog `sudo`/`su` invoking user | success, failure | **NO** | MED |
| Memory session owner | (inferred) | **NO** | LOW |

### user_agent — user agent through which the request was made
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| zeek **http.log** → `user_agent` (HTTP Basic/NTLM-over-HTTP auth) | success, failure | **NO** | MED — mapped to `http.user_agent_full` (http object), not authentication. |
| IIS W3C → `cs(User-Agent)` | success, failure | **NO** | LOW-MED |
| Cloud IdP sign-in logs (`aws-cli/2.0.0 …` — the model example) | success, failure | **NO** | Out of scope for host/network artefacts. |
| evtx Security channel | — | **NO** | **No source** — Windows logon events carry no user agent. |

### user_role — IPAM access-control role of the initiating user
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| evtx **4672** → `PrivilegeList` present ⇒ `administrator` | success | **YES** — `core.py:176` `const("administrator")`, `[asserted]` | MED — a coarse assertion (admin-equivalent privileges granted), not a true IPAM role. Only on success. |
| Memory getsids (Administrators group membership) | (inferred) | **NO** | LOW |
| IPAM (Infoblox) directory | — | **NO** | The literal definition source; not in pipeline. |

### user_type — type of user that initiated the request
| sources (source → native field) | action(s) | mapped? | confidence & caveats |
|---|---|---|---|
| Derivable from `SubjectUserSid` RID / `ElevatedToken` / integrity | success, failure | **NO** | LOW — derivation (500/501, elevated vs standard), not recorded; not done today. |
| Memory getsids / SAM | (inferred) | **NO** | LOW |
| — | — | **NO direct source.** | Model example `Administrator, Standard, Guest`. |

---

## 3. Action coverage (which sources prove each action)

| action | mapped sources | additional (unmapped) sources |
|---|---|---|
| **success** | evtx 4624, 4672 (`core.py`) | evtx 4768/4769/4776(0x0); zeek ssh `auth_success:true` (real evidence), kerberos `success:T`, ntlm `success:T`, radius `result:success`; syslog `Accepted`; utmp/wtmp login; IIS 200/302 |
| **failure** | evtx 4625 (`core.py`) | evtx 4771, 4768/4769 fail, 4776 (0xC000006A/0xC0000064…); zeek ssh `auth_success:false`, kerberos `success:F`, ntlm `success:F`, radius fail; syslog `Failed password`/`invalid user`/PAM; **btmp**; IIS 401 |
| **error** | — (none) | evtx **4649** (replay attack detected); anomalous NTSTATUS/Kerberos KRB-ERR that are not clean auth failures; zeek kerberos `error_msg` | 

`error` has **no clean mapped source**; thin everywhere (4649 is the closest genuine "unexpected error").

---

## 4. Summary

**Coverage of the 19 fields:**
- **≥1 genuine source (14):** ad_domain, app_name, auth_service, auth_target, decision_reason, hostname, method, target_ad_domain, target_uid, target_user, uid, user, user_agent, user_role.
- **Derivable-only / effectively no direct source (4):** fqdn (host-identity inheritance / DNS enrichment only), target_user_type & user_type (SID-RID / group-membership derivation, not recorded), target_user_role (IPAM-only).
- **Hard no-source (1):** **response_time** — no DFIR artefact records auth-response duration.

**Currently mapped:** 12 of 19 fields, from a **single artefact** (evtx Security 4624/4625/4672). decision_reason (failure-only) and user_role (4672-only, asserted) included. Nothing else in the repo produces the object.

### Unmapped gaps ranked by value (a source exists; the pipeline ignores it)

1. **Kerberos DC events 4768 / 4769 / 4771** (EvtxECmd already parses them). The authoritative domain-wide auth record: target_user, target_ad_domain, method (enctype), decision_reason (Kerberos status), auth_target (SPN), hostname (IpAddress), success/failure. **Highest value** — currently zero Kerberos coverage.
2. **NTLM DC event 4776** — target_user, hostname (Workstation), auth_service (PackageName), decision_reason (Status), success/failure. Fills the DC-side NTLM validation gap.
3. **Linux syslog auth/secure (sshd/sudo/su/PAM)** via Plaso — real success/failure with user, target_user, method (password/publickey), decision_reason, app_name, origin. **The pipeline already parses these but routes them to `user_session/login` (`l2t_text`), discarding the authentication semantics** (`authentication_method` is dropped to native). High value, low incremental cost.
4. **Zeek ssh.log** — real evidence is on hand (`auth_success`, `auth_attempts`, orig/resp, client/server) yet **ssh.json is not even ingested** (zeek routing = conn/files/http/smtp only). Yields the success/failure action + origin/target/app for network SSH auth (no username — encrypted).
5. **Zeek kerberos.log / ntlm.log / radius.log** — target_user, ad_domain, auth_target, method, decision_reason, action. Not present in current evidence but standard Zeek outputs; no mappers exist.
6. **evtx 4648** (explicit-cred / RunAs) — deliberately unmapped for the *action* (issuance, no outcome), but it uniquely names **auth_target (TargetServerName)** and the Subject→Target credential swap; its fields could be surfaced as native even while the action stays raw.
7. **RDP operational logs** (TerminalServices-RemoteConnectionManager **1149** "User authentication succeeded"; LocalSessionManager 21/25) — carry User/Domain/Source-Network-Address; 1149 is a genuine network-auth success. Today EID 21 is mapped to `user_session` (`evtx_extra`), not authentication.
8. **IIS / web-server W3C logs** (HTTP Basic/Windows auth) — user, user_agent (**the only realistic in-pipeline source for `user_agent`**), decision_reason (sc-status), hostname (c-ip). No mapper.
9. **utmp/wtmp/btmp** — btmp especially is a pure *failure* record; wtmp/utmp logins carry user + origin. Today mapped to `user_session` only.

### Honest non-gaps
- **response_time**: unreachable from any host/network artefact — accept the null.
- **user_role / target_user_role / target_user_type / user_type**: IPAM/type semantics are external-directory or derivation-only; only the coarse 4672 `administrator` assertion is defensible. Anything richer would be a near-miss.
- **fqdn**: correctly treated as host-identity *inheritance*, not an auth-record field.
- **Memory/Volatility** proves sessions *existed* (implying prior successful auth) and yields uid/user, but records no auth decision/method/target — rightly feeds `user_session`, not `authentication`.
- **Sysmon** has no authentication object (confirmed against real evidence, which is Sysmon-only here) — not a gap, a non-source.
