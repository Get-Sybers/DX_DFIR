# CAR `authentication` — FILESYSTEM/disk provenance audit

**Scope of THIS pass:** what a **dead disk image** (registry hives, Credential Manager,
scheduled tasks — no live event stream) can genuinely contribute to the CAR
`authentication` object, and which of it the pipeline has **not mined**. READ-ONLY.

**Object:** `authentication` — "a user or process attempts to access a privileged
system resource" (logon / privilege elevation). Actions: `success` · `failure` · `error`.
**19 fields:** ad_domain, app_name, auth_service, auth_target, decision_reason, fqdn,
hostname, method, response_time, target_ad_domain, target_uid, target_user,
target_user_role, target_user_type, uid, user, user_agent, user_role, user_type.

**The headline honesty finding (read first):**
Authentication is fundamentally an **event** — a request, a decision, a response. A
disk image records **none of that decision flow**. It records **residual state** left
behind by past authentications. Exactly **one** disk artefact carries a
*dated authentication outcome*: the **SAM hive's per-user "Last Login Time" + login
count** (a genuine `success` with a timestamp, user, and RID). Everything else on
disk is either an **identity hint** (who logged on last / by default), a **join key**
(SID↔name), or **encrypted state Plaso does not crack** (LSA secrets). The event-only
fields — `method`, `auth_service`, `response_time`, `decision_reason` — are **honest
nulls from disk**. The one disk path that *does* fill the object today is the
**on-disk `Security.evtx`** parsed by EvtxECmd → the existing 4624/4625/4672 mapper;
that is the event log living on disk, **not a hive/registry artefact**, and is
covered by the prior event-log audit (`docs/car-provenance/authentication.md`).

**Ground truth inspected (real evidence):**
- `data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` — **LoneWolf Win10**,
  a **workgroup** host (`DESKTOP-PM6C56D`, no AD). 27 `windows:registry:sam_users`
  rows, 12 `windows:registry:winlogon`, full `SOFTWARE\...\ProfileList`, LSA policy
  keys, `windows:tasks:job`. This is the authoritative "what the pipeline actually
  sees from a disk image" corpus.
- Engine maps: `third_party/piiat-mitrecar/piiat_mitrecar/mappings/plaso_registry.py`
  (every `windows:registry:*` → **registry** `key_edit`, sam/profile fields kept
  `_native`), `mappings/core.py` (the ONLY `authentication` mapper — evtx Security).
- Routing: `piiat_mitrecar/pipeline.py:62` (`.L2tWinreg → plaso_registry`),
  `sources/*.yaml` — **only `evtx_security.yaml` declares `data_model_coverage:
  authentication`.** No plaso/registry/disk source routes to `authentication` at all.
- Governing law: `docs/CAR-Extraction-Rules.md` §1 (extract every field the artefact
  can supply) & §3 (one authoritative artefact per object, tied to identity);
  `docs/CAR-Relations.md` §14 (authentication ← Security 4624/4625, identity =
  `Computer`+`Channel`+`EventRecordId`).

---

## 1. What disk feeds `authentication` today: **nothing from hives.**

`grep authentication sources/*.yaml` → the object is declared by **`evtx_security`
only** (4624/4625/4672). The disk registry family is routed by `plaso_registry.py`
to the **`registry`** object as `key_edit` snapshots; `sam_users`' auth-bearing
fields (`username`, `account_rid`, `login_count`) are surfaced into **`_native`**
and **never reach `authentication`**. So every row below is **NOT mined for auth**
today — by construction, not by oversight.

The only *disk-resident* path that reaches `authentication` is **`Security.evtx`
on the image → EvtxECmd → `evtx_security`/`core.py`** — i.e. the event log that
happens to live on the disk. No hive, no snapshot, no credential store contributes.

---

## 2. Per-field provenance — FILESYSTEM/disk artefacts only

Legend — **action**: which CAR action the disk fact would support. **mined?**: is it
routed to `authentication` today (disk sources: **NO** everywhere — auth is
event-log-only today). Native field shown as `artefact → NativeField`.

### uid — SID of the subject/initiating context
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| SAM `sam_users` → `account_rid` (500/501/1001…) | success | **NO** (→ registry `_native.account_rid`) | MED. **RID only, not a full SID.** Needs the machine SID (from SOFTWARE ProfileList, or SAM `Domains\Account` V-value) to become `S-1-5-21-…-<RID>`. On a *local* logon the subject ≈ the account itself. |
| SOFTWARE `ProfileList\<SID>` → key basename | — | **NO** | HIGH as a **join key**, not an auth event. Supplies the machine SID + SID→name that upgrades the SAM RID to a real `uid`. |

### user — name of the initiating user (subject)
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| SAM `sam_users` → `username` | success | **NO** (`_native.username`) | HIGH string. Local account name (`jcloudy`, `Administrator`). For a local interactive logon subject≈target. |
| SOFTWARE `ProfileList\<SID>` → `ProfileImagePath` basename | — | **NO** | HIGH — SID→name resolver (already used by piiat-mem `enrich.py` for the memory lane). |
| Winlogon `DefaultUserName` (autologon) | success | **NO** | LOW — identity hint, and **not set** in the real sample (only WinSxS component-store noise matched); trapped in the `values` list → `_native`. |
| LogonUI `LastLoggedOnUser` / `LastLoggedOnSAMUser` | success | **NO** | LOW — last interactive user hint; **no dedicated Plaso plugin** (generic `key_value` → unindexed `values` list); not present as a real value in this sample. |

### target_uid — SID of the account being authenticated
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| SAM `sam_users` → `account_rid` (+ machine SID) | success | **NO** | MED — same RID→SID caveat as `uid`. On the SAM record the account **is** the target. |
| LogonUI `SelectedUserSID` | success | **NO** | LOW — hint; not surfaced (no plugin; not in sample). |

### target_user — name of the account being authenticated
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| SAM `sam_users` → `username` | success | **NO** (`_native.username`) | HIGH string — the local principal whose "Last Login" this row records. **The single strongest disk-native auth field.** |

### user_type — type of initiating user (Administrator/Standard/Guest)
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| SAM `sam_users` → `account_rid` well-known RID | success | **NO** | LOW-MED — **derivation** from RID: 500=Administrator, 501=Guest, 503=DefaultAccount, 504=WDAGUtility(service). Real sample shows all of these. Not recorded, not currently derived. |
| SAM account control flags (F-value ACB bits: disabled/locked/normal) | success/failure | **NO** | LOW — the ACB flags are in the SAM F-value but **Plaso's `sam_users` plugin does not emit them** (see §5). |

### target_user_type — type of target account
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| SAM `sam_users` → `account_rid` well-known RID | success | **NO** | LOW-MED — same RID derivation (target≈subject on a SAM row). |

### hostname — origin host the request was made from
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| SAM/ProfileList row → `image_hostname` (`DESKTOP-PM6C56D`) | success | **NO** | MED — this is the **image identity** (the host the hive came from = where the local logon happened), stamped by the lane. Legitimate for a *local* logon (origin=target=this host); it is **not** a remote-origin hostname. |

### ad_domain / target_ad_domain — AD domain (subject / target side)
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| SECURITY hive `LSA\Cache` (`NL$1`…) cached **domain** logon | success | **NO** | **NO in-pipeline source.** Cached-cred entries carry the last domain logons but are **DPAPI/LSA-encrypted**; **Plaso winreg does not decrypt LSA secrets** (only LSA *policy* keys surface — Credssp, MSV1_0, `Kerberos\Domains` empty). Would need a secretsdump/creddump-class tool (not in repo). |
| SECURITY `Policy\Secrets\$MACHINE.ACC` / domain-join secret | success | **NO** | Same — encrypted, not decrypted; no parser. |
| SOFTWARE `…\Group Policy\History` / `Tcpip\Parameters\Domain` / `ComputerName` | success | **NO** | LOW — domain membership hint only; **this host is a workgroup** so empty here anyway. |
| Winlogon `DefaultDomainName` | success | **NO** | LOW — identity hint; not set in sample (WinSxS noise only). |

### auth_service · method · response_time · decision_reason
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| — | — | **NO** | **Honest null from disk.** These describe the *live authentication exchange* (which SSP validated, NTLM vs Kerberos, how long it took, why it was denied). No hive/snapshot records them. Only the live event (Security 4624/4625/4776/4768…) carries them. `response_time` has no DFIR source at all. |

### app_name — application that made the request
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| — (Winlogon autostart `Userinit`/`Shell` describes the shell, not the auth caller) | — | **NO** | Effectively no disk source — the calling process of a past logon is not persisted in a hive. |

### user_agent
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| — | — | **NO** | No disk artefact records a logon user-agent (web/IdP-only field). |

### auth_target — machine authenticated TO
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| SAM row → `image_hostname` | success | **NO** | LOW-MED — for a **local** SAM logon the target machine *is* this host; degenerate but true. No record of a *remote* auth_target on a local hive. |

### fqdn
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| — | — | **NO** | Host-identity inheritance only; `image_hostname` is a bare NetBIOS name (no domain on this workgroup host). |

### user_role / target_user_role
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| SAM group membership (RID 544 Administrators via the SAM `Aliases`/`Members`) | success | **NO** | LOW — reconstructable in principle from SAM alias membership, but **Plaso does not parse SAM aliases/group membership** (only `sam_users`). IPAM-role semantics are external. Not derivable in-pipeline today. |

---

## 3. The ONE real unmined disk auth record — SAM `Last Login Time`

The `windows:registry:sam_users` plugin emits, per local account, events tagged
`timestamp_desc` ∈ {**Last Login Time**, Last Password Set Time, Content Modification
Time} carrying `username`, `account_rid`, `login_count`, `fullname`, `comments`.

**Real LoneWolf `Last Login Time` rows (decoded):**

| username | RID | login_count | last_login (UTC) |
|---|---|---|---|
| jcloudy | 1001 | 2 | 2018-03-27 09:19:58 |
| defaultuser0 | 1000 | 2 | 2018-03-27 12:13:28 |
| jcloudy | 1001 | 15 | 2018-04-04 04:30:48 |
| jcloudy | 1001 | 23 | 2018-04-06 12:26:27 |

(Multiple jcloudy rows = successive hive/transaction-log versions Plaso replayed —
the login count climbing 2→15→23 gives *dated snapshots* of successful-logon
accrual.) Built-ins Administrator(500)/Guest(501)/DefaultAccount(503)/
WDAGUtility(504) all show `login_count 0` — **never logged in** (a defensible
"no successful auth" signal).

**Why this is a genuine — but qualified — `authentication.success`:** it is the only
disk fact with a **timestamp + outcome + principal**: "account `jcloudy` (RID 1001)
successfully logged on interactively at 2018-04-06 12:26:27, for the 23rd time." That
fills `success` + `user`/`target_user` + `uid`/`target_uid` (RID→SID via ProfileList)
+ `hostname`/`auth_target` (this host). `login_count` is decision *context* (no CAR
field — keep native). **Caveats that must ride with it:**
- It is **console/interactive local logon only** (the SAM F-value counter); network/
  RunAs/service logons don't touch it.
- It is a **snapshot state, not an event** — it has no CAR-Relations §14 event
  identity (`EventRecordId`); its natural identity is the hive-key snapshot, which is
  why it currently lands as a `registry` `key_edit`. Emitting it as `authentication`
  would be a **second authoritative artefact** for the object (tension with
  Extraction-Rules §3) — defensible because it's the *only* disk auth outcome, but it
  must be marked snapshot-derived and never merged onto a real 4624's identity.
- **Overlaps `user_session/login`** — the memory lane's `windows.piiat.sessions`
  already resolves `User` via ProfileList for login events; the SAM last-login is
  arguably a `user_session/login` too. Pick one canonical home (auth vs session) to
  avoid a double count.

---

## 4. Ranked UNMINED disk opportunities

1. **SAM `sam_users` "Last Login Time" → `authentication.success`** (with `user`/
   `target_user`←`username`, `uid`/`target_uid`←`account_rid`+machine-SID,
   `hostname`/`auth_target`←`image_hostname`, ts←the Last-Login event). **The only
   dated auth outcome a disk image yields.** Already parsed and sitting in
   `plaso_registry` `_native` (`username`/`account_rid`/`login_count`); needs a
   dedicated auth variant (or a downstream promotion) that fires **only** on the
   `Last Login Time` timestamp_desc. Low incremental cost; honest snapshot caveat.
2. **SOFTWARE `ProfileList` SID↔name + machine-SID join** — not an auth event, the
   **enabler**: turns SAM's bare RID into a full `S-1-5-21-…-<RID>` SID and resolves
   SID→username. Real machine SID present (`S-1-5-21-2734969515-1644526556-1039763013`,
   RIDs 1000/1001). The join logic already exists for the memory lane
   (`piiat-mem/enrich.py` `_PROFILELIST_SID`); reuse it disk-side. Ship with #1.
3. **SAM well-known-RID → `user_type` / `target_user_type` derivation**
   (500=Administrator, 501=Guest, 503=DefaultAccount, 504=service). Pure derivation
   from a field already captured (`account_rid`); the same coarse-assertion class as
   the existing 4672→`user_role=administrator`. Ship with #1.
4. **`login_count == 0` on built-ins as a "never-authenticated" signal** — keep as
   native context on the success/`user_session` row (no CAR field); useful for the
   downstream cascade, cheap.

Everything above is **one artefact family (SAM + ProfileList)**, already parsed and
already in `_native` — the work is *routing/derivation*, not new evidence.

---

## 5. Honest nulls / non-sources from disk (do NOT try to fake)

- **SAM `failed-count` / `last-failed-logon` → `failure`.** The task hypothesised
  this; **it is not available.** The SAM F-value *does* hold bad-password-count and
  last-incorrect-password time, but **Plaso's `windows_sam_users` plugin does not
  parse or emit them** — confirmed empirically: the only `timestamp_desc` values seen
  are Last Login / Last Password Set / Content Modification, and no `fail`/`incorrect`/
  `bad-password` field exists on any of the 27 rows. So **disk yields a `success`
  source but NO `failure` source.** (Failure remains Security **4625**-only; btmp on
  Linux — both event logs, not hives.)
- **SECURITY hive LSA cached creds / domain secrets → `ad_domain`.** Encrypted
  (`NL$KM`/`Cache\NL$x`/`Policy\Secrets`); **Plaso winreg does not decrypt LSA
  secrets** — only LSA *policy* keys surface (Credssp/MSV1_0/FipsAlgorithmPolicy/
  `Kerberos\Domains` empty). No secretsdump/creddump-class tool in the repo. Honest
  no-source in-pipeline (and this host is a workgroup — no domain regardless).
- **Winlogon `DefaultUserName`/`DefaultDomainName`/`AutoAdminLogon`.** Identity hints
  at best (autologon config), not an auth event; **not set** in the real sample (the
  matches were WinSxS component-store `wcm://…metadata\elements\DefaultUserName`
  noise). Also structurally trapped in the `values` list → `_native`. Near-null.
- **LogonUI `LastLoggedOnUser`/`LastLoggedOnSAMUser`/`SelectedUserSID`.** Last-user
  hint, not an outcome; **no dedicated Plaso plugin** (generic `key_value` → unindexed
  `values` list); the value isn't in this sample's LogonUI extract. Weak.
- **Credential Manager / DPAPI blobs / Vault.** Encrypted; enumerate *accounts*, not
  auth outcomes; **no parser in the repo**, no evidence. No-source.
- **Scheduled-task author SID.** No structured field: `windows:tasks:job` → `author =
  None`, `task_scheduler:task_cache:entry` carries only `task_identifier`/`task_name`/
  `username`. The **creator principal IS present but only as an unstructured string**
  in the `.job` message (`Scheduled by: DESKTOP-PM6C56D\jcloudy` observed on the real
  Dropbox tasks) — a name, no SID, and only via regex on the message. Weak signal
  regardless (task *creation* is not an authentication event). Treat as effectively
  no-source for `authentication`.
- **`auth_service`, `method`, `decision_reason`, `response_time`, `app_name`,
  `user_agent`.** Event-only by nature; a disk snapshot never records the live
  exchange. Permanent honest nulls from any hive/disk artefact.
- **On-disk `Security.evtx`.** Not a new disk source — it *is* the existing
  `evtx_security`/`core.py` mapper's input (EvtxECmd over the image's evtx files).
  De-emphasised here; covered by the event-log audit.

---

## 6. Summary

- **Disk contributes to `authentication` today: nothing from hives** — the object is
  wired to `evtx_security` (4624/4625/4672) alone; every `windows:registry:*` row
  (SAM included) is routed to the **registry** object with its auth-bearing fields
  parked in `_native`.
- **The one real disk auth record is SAM `Last Login Time`** — a dated, principal-
  bound **`success`** (user, RID→SID, host, timestamp, count). It is a **snapshot
  state, not an event**, overlaps `user_session/login`, and is **success-only**.
- **SAM gives NO failure** (Plaso drops the bad-password/last-incorrect fields), and
  **LSA cached-cred `ad_domain` is unreachable** (encrypted, no decryptor in repo).
- **Best unmined lever:** promote SAM `sam_users`(Last Login) + SOFTWARE `ProfileList`
  (SID/machine-SID join) + RID→user_type derivation — all already parsed and sitting
  in `_native`, needing only routing/derivation, marked snapshot-derived.
- **Honest nulls from disk:** auth_service, method, decision_reason, response_time,
  app_name, user_agent (event-only); failure record; ad_domain via LSA; Credential
  Manager; scheduled-task author.
