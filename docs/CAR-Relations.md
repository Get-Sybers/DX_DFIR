# CAR relations — identity, joins, inheritance, limits

The relational discipline of [PIIAT-Mem](https://github.com/Get-Sybers/PIIAT-Mem)'s `car-store.md` §3, applied to the CAR
objects the **memory artefact cannot supply** — determined from MITRE's own doc
pages (car.mitre.org, field semantics read verbatim) and ratified against real
evidence. The ten memory-fed objects are governed by
PIIAT-Mem's own `docs/design/car-store.md` (github.com/Get-Sybers/PIIAT-Mem); this document covers
**authentication**, **http**, and **email**, and the engine rules they added.

The test, unchanged: *a property may be attributed across objects only via a key
that identifies the same entity instance beyond doubt; anything else is marked
heuristic; what cannot be known is an honest null.*

## authentication (← Security 4624 / 4625)

**Identity.** One event = one Security record of one auth decision:
`guid = authentication-<Computer>-<Channel>-<EventRecordId>` (record ids are
per-channel monotonic; unique within one `.evtx` export — a log-clear (1102)
resets them, the documented caveat). MITRE's authentication object has no `guid`
field — this is the engine's event identity, not a canonical property.

**Joins.**
- → **user_session** via the LUID — the *designed* key: `TargetLogonId` names
  the session a successful authentication opened; `SubjectLogonId` the existing
  session it was requested *from* (valid on failures too). LUIDs are unique per
  boot per host, so a same-host match is **definitive** within the evidence
  window — except the well-known per-boot singletons (`0x3e7/0x3e5/0x3e4`),
  which recur every boot and are marked **heuristic** across multi-boot logs.
  `0x0`/blank is a null session, never a key. Case-normalized (hex case differs
  between artefacts). This join works **cross-artefact** — an evtx 4624 to a
  memory-extracted session.
- → **process** via `Payload.ProcessId` (a **hex** string — the engine parses
  `0x…`) — the create-time-window PID join, **heuristic** (PID reuse).
- `LogonGuid` is the designed *cross-host* correlation key (Kerberos) but is
  all-zero in workgroup evidence — joined only where non-zero.

**Inheritance.** `user`/`uid` ← the owning process (they are, per MITRE, the
*requesting process's* identity) — fill-only-null via the heuristic link.
`fqdn` ← host identity. Everything target-side is native to the event.

**Limits.**
- A **failed** authentication opens **no** session — the target-session join
  never runs for `failure`.
- **4648 is not mapped**: it records an explicit-credential logon at *issuance*;
  no service response exists in the record — mapping it to `success` would
  assert an outcome the evidence doesn't contain. Rows stay raw.
- `hostname` (origin) and `auth_target` (destination) point opposite ways and
  the direction flips by EventId; the origin (`WorkstationName`) is
  client-reported and forgeable — *recorded, not trusted* (no fallback to
  `Computer`, which is the destination).
- `method="Negotiate"` means *negotiated* — never assert NTLM vs Kerberos.
- Subject `user`/`uid` is the calling context (often a machine account) — never
  "the person who typed the password"; the canonicalization pass may unify
  alternate renderings of a well-known account but never overwrites an
  arbitrary native value.

## http (← Zeek http.log)

**Identity.** One event = one HTTP *transaction*:
`guid = http-<uid>-<trans_depth>` (sensor-minted connection id + pipeline
depth). **Run-scoped**: zeek mints fresh uids per run — cross-run correlation
goes through time + 5-tuple, never uid equality.

**Joins.** → **flow** via the shared zeek `uid` — sensor-assigned, content-
independent: **definitive** within the capture (the 5-tuple+window fallback for
cross-source flows is heuristic — ephemeral ports recycle). → **file** (zeek
files.log) via `resp_fuids`/`orig_fuids` — definitive within the capture (a
file-in-transit, not a host filesystem file). → process/user_session: **none** —
a pcap carries no endpoint identity.

**Inheritance.** None today; kept keys (`uid`, fuids) carry the future joins.

**Limits.**
- `hostname` is the host the request was **seen on** (the vantage) — **not**
  the Host header; the header is `url_domain` and is client-forgeable (domain
  fronting): the connection-truth destination is `id.resp_h`, kept native.
- `url_scheme`'s MITRE description is a copy-paste error — implement the field
  *name* (scheme), not the pasted text.
- `url_full` is reconstructed (`http://` + Host + uri) only for origin-form
  requests; a CONNECT target is authority-form — no scheme, no URL, and a
  tunnel event proves a tunnel was *requested*, nothing about what's inside.
- No response captured (null `status_code`) asserts **no outcome**.
- `request_referrer`/`user_agent_*` are client-supplied strings — never proof
  of provenance or real client software.
- The CAR action set (get/post/put/tunnel) is deliberately incomplete — the
  car_http table is **not** a complete web-traffic record; absence proves
  nothing (HEAD/OPTIONS/… stay raw).

## email (no artefact yet — principles recorded for the first mapper)

**Identity.** `(source_host, smtp_uid, action, time)` — `smtp_uid` is the
server-**local** queue/transaction id (MITRE's designated discriminator), *not*
the RFC 5322 Message-ID: it re-assigns per relay hop and **never joins across
hosts**. Multiple actions on one message at one server (deliver→delete) share
it — definitive within that server's log.

**Joins.** → flow via a shared capture uid (definitive within the capture) or
4-tuple+window (heuristic). → file (attachments) via zeek fuids (definitive
within capture); name/size matching is heuristic at best. → http via
`message_links` vs later requests — **temporal correlation only** (presence ≠
click; scanners follow links). → authentication/process: **none** (a mailbox
address maps to an account only through an external directory).

**Limits.** `from` is trivially forged (MITRE says so verbatim) — never
attribute; `to` is not the recipient list (envelope `dest_address` is);
`return_address` is attacker-chosen (mismatch = signal, not identity); `date`
is the *client's* header — never the event timestamp; `server_relay` is
trustworthy only from the observing server inward; `attachment_mime_type` is
declared, not actual; only `deliver` means delivery reached the recipient
server-side — nothing implies a human read it. The one real smtp capture on
hand is STARTTLS-encrypted — an empty `car_email` table is the honest output.

## Engine rules added by this pass

- `payload()` values are stripped (Microsoft pads e.g. `LogonProcessName`).
- PID parsing accepts Windows hex strings (`0x1FC`) everywhere joins use PIDs.
- Canonicalization of well-known accounts fills blanks and unifies *alternate
  renderings of the same account* only — a natively extracted value (e.g. a
  machine account on a 4624 Subject) is evidence and is never overwritten.
- `native_extract` promotes parsed join keys out of raw blobs into `native`
  (never into canonical columns).
- The authentication↔user_session LUID join writes
  `native.target_session_guid` / `native.subject_session_guid` with its tier.

## Adopted from MITRE CAR analytics (proven relationships)

- **file → process by image path (CAR-2014-02-001)** — a file whose `file_path`
  equals a process's `image_path` on the same `source_host` is the binary that
  process executed. Implemented in `enrich.py` (`_link_file_to_process`):
  surfaces `_native.executed_as_process_guid` (+ `_link` = heuristic — path
  equality, not instance identity; `_count` when several processes ran the
  path). This is MITRE CAR's own correlation, ported as a within-source edge.
  Regression-tested against CAR's true-positive telemetry (`tests/
  test_true_positives.py`, CreateRemoteThread guid cascade).

## Within-source inference rules

These rules mine each per-source `car.db` for join keys the base cascade does not
already exploit. Every rule is **within one `car.db`** (scoped per `source_host`)
and grounded in a concrete key in the evidence, implemented in `enrich.py` +
`relationships.yml`. Cross-source correlation (memory + disk + network) is a
separate stage — see [CAR-CrossSource.md](CAR-CrossSource.md).

The CAR model has no session/process `end_time` field, so R1/R2 surface the
lifetime in `_native` (never a fabricated column); R2's real gain is
**window-bounding** — a pid-reuse match now rejects an owner that had already
terminated (`enrich._alive_at`), improving owner/parent link correctness.

| # | rule | join key (tier) | fills |
|---|---|---|---|
| R1 | **user_session lifecycle** — pair logout→login, close the session | TS id24 by `SessionID`; Security 4634 by `TargetLogonId` LUID (definitive within window; well-known LUID heuristic) | `_native.session_login_guid` / `session_logout_guid` / `session_end` |
| R2 | **process lifetime bounding** — index terminate/exit; reject a pid-owner that had already exited before the spoke ts | ProcessGuid (definitive) / pid+window (heuristic) | tightens owner/parent pid-window (`_alive_at`) |
| R3 | **zeek uid spoke→flow** — link each http/file to its connection | `uid` (definitive within capture); `fuid` = file identity | http/file inherit `from_owning_flow` (requester_ip, hostname); `_native.flow_guid` |
| R5 | **thread injection dual-link** — link BOTH source and target process | source + target ProcessGuid (both native, definitive) | owner = source; `_native.target_process_guid` = injected target |
| R6 | **auth caller-process owner** — link an auth to the process that requested it | 4624/4625 Payload `ProcessId` → owning_pid (heuristic pid+window) | auth `owning_guid` (previously auth linked only to its *session* via LUID) |
| R4 | **BITS transfer correlation** — assemble one transfer from its events | `transferId` GUID (definitive) | final bytes/URL, completion; owner from the BITS job-created event's process |
| R7 | **service→process by image** (weak) — link a 7045 install to a run of its binary | 7045 `ImagePath` ↔ 4688 `NewProcessName` exe+window (heuristic) | service `owning_guid` |

**Deferred to the cross-source aggregate stage (different `car.db`s):**
service↔registry service-key writes (evtx and registry are separate sources),
host-rename lineage (a host-identity call across scopes), and any `community_id`
zeek↔host-flow bridge.

### Coverage pass — ingest more event-log + registry CAR content

A triage over the real lonewolf image (55k records / 842 distinct
Channel+EventId) added maps for every event that has a CLEAN canonical CAR home
(`mappings/evtx_more.py`, wired into `EVTX_MAPS` so it also serves the
`l2t_winevt` Plaso adapter). lonewolf coverage rose **2808 → 4852 events (+73%)**:

| (Channel, EventId) | → object/action | count |
|---|---|---|
| Security 4907 (ObjectType=File) | file / acl_modify | 1686 |
| WMI-Activity 5857 | module / load (wmiprvse provider DLL) | 312 |
| System 20003 (UserPnp) | service / create | 35 |
| SmbClient/Connectivity 30803 | flow / start (ServerName; addr is SOCKADDR hex → native) | 3 |
| System 7001 / 7002 (Winlogon) | user_session / login, logout | 7 |
| System 7034 (SCM) | service / stop (crash = involuntary) | 1 |

Registry (`recmd.py`): `registry.type` ← `ValueType` (4969/4969) and
`new_content` set for parity with the Sysmon registry map.

**Honest nulls — deliberately left raw** (no CAR object in the 13-object model;
mapping them would repeat the near-miss the codebase refuses at 7040/4648): the
high-volume account/group **lifecycle** (4720/4726/4731…), local-group
**enumeration** (4798 ×2789, 4799 ×630), privilege-rights grants (4717/4718),
audit-policy (4719), system-time change (4616), and crypto-key ops. These are
forensically meaningful but stay raw-but-queryable rather than forced into a
wrong object. PowerShell script-block (4104) and WMI event-consumer persistence
(5861) likewise have no clean CAR action → raw.

### Coverage pass 2 — Sysmon access, disk-image registry/shell, audit families

Goal (owner): **populate as many CAR object/action/property rows as possible**
(null or duplicate properties are fine) so the end-stage cascade has the most to
relate. Relationship joins are NOT done at map time — maps only normalise and
surface join keys; joining stays in `enrich.py` (the end stage).

Verified, measured:
- **Sysmon EID 10 (ProcessAccess) → process/access** — was unmapped; the
  cred-dump/injection indicator (source→target handle, GrantedAccess). +2 on the
  attack-samples source.
- **Plaso disk-image registry** (`plaso_registry`): every `windows:registry:*`
  data_type → registry/key_edit. **M57: 498,325 registry rows** (was ~2.3k).
  Runs alongside `plaso_exec_winreg` on L2tWinreg — an execution artefact
  (amcache/userassist) legitimately yields BOTH a process row and a registry
  row (intended duplicate views).
- **Plaso shell items** (`plaso_shellitem`): `windows:shell_item:file_entry`
  (from LNK targets + shellbags) → file, action by MAC `timestamp_desc`. Folds
  into M57's **190,718 file rows** (filestat + usn + lnk + shell + recycle).
- M57 total: **~192k → 691,934 CAR events**.

Schema-grounded, INERT until the audit subcategory is enabled (`evtx_audit`,
absent from current corpora — field names from the documented Windows schema,
action DECISIONS keyed on the STABLE numeric AccessMask, smoke-tested on
synthetic records): Security **4663** object-access → file read/write/delete,
**4660** → file/delete, **4670** → file/acl_modify, **4657** → registry
add/value_edit/remove, **4689** → process/terminate, **5140/5145** share →
file, **5156/5157** WFP → flow start/message, **5158** → socket/bind, **5058**
key-file → file/read. Each is gated on Channel+EventId so it never touches a
non-matching record; confirm the decision maps against a real audit-enabled
capture before relying on the read/write split.

**Still genuinely raw — no object exists in the 13-object model** (not
conservatism; there is no row type to instantiate): account/group **lifecycle**
(4720/4726/4731…), group-membership **enumeration** (4798/4799), privilege
grants (4717/4718), audit-policy (4719), scheduled-task **registration**
(4698/TaskScheduler), firewall-**rule** changes, WMI query telemetry, and pure
app/telemetry channels. These stay raw-but-queryable.

**What the measured cascade already does right (baseline, lonewolf evtx):**
parent link 36/40 (heuristic); auth↔session LUID join 1616/1616 (104
definitive); user_session owner 692/880; well-known accounts unified (Local
System ×790). `service`/`http`/`authentication` show 0 *owner* links because the
artefact carries no owning-process key — honest nulls, and exactly what R3–R6
above set out to add where a real key does exist.
