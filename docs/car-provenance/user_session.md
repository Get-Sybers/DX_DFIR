# CAR `user_session` — Property-Provenance Catalogue

Authoritative "find once, done" map of **every canonical field × every artefact/source that can supply it** for the MITRE CAR **`user_session`** object, as implemented in this repo (`/opt/github/DX_DFIR`). Grounded in the pinned CAR data model, the engine mappings, the generated source YAMLs, and real evidence in `data_store/processed/`.

- **Object def (pinned):** `third_party/piiat-mitrecar/third_party/car/data_model/user_session.yaml`; `car_data_model.json` (lines 364–388).
- **Fields (10):** `dest_ip, dest_port, hostname, login_id, login_successful, login_type, src_ip, src_port, uid, user`
- **Actions (5):** `lock, login, logout, reconnect, unlock`
- **OSSEM-CDM:** no `user_session` schema exists (only `network_session.yml`) — nothing to cross-check against there.

## Source universe (what actually feeds `user_session` in this engine)

| # | source key | tool / parser | events | actions produced | map file | source yaml |
|---|---|---|---|---|---|---|
| S1 | `evtx_security_sessions` | EvtxECmd (Security channel) *(alt: Plaso winevt via `l2t_winevt` adapter)* | 4624; 4634/4647/4779; 4778 | login/**unlock**(LogonType 7); logout; reconnect | `piiat_mitrecar/mappings/evtx_windows.py` | `sources/evtx_security_sessions.yaml` |
| S2 | `evtx_rdp` | EvtxECmd (TerminalServices-LocalSessionManager) | 21; 24; 25 | login; logout; reconnect | `piiat_mitrecar/mappings/evtx_extra.py` | `sources/evtx_rdp.yaml` |
| S3 | `evtx_more` | EvtxECmd (System / Winlogon) | 7001; 7002 | login; logout | `piiat_mitrecar/mappings/evtx_more.py` | `sources/evtx_more.yaml` |
| S4 | `l2t_utmp` / `l2t_utmpx` | Plaso utmp / utmpx (Linux/macOS login DB, incl. wtmp) | record-type 6/7; 8 | login; logout | `piiat_mitrecar/mappings/plaso_linux.py` | `sources/l2t_utmp.yaml`, `l2t_utmpx.yaml` |
| S5 | `l2t_text` | Plaso syslog (`syslog:ssh:login`) | sshd "Accepted" | login | `piiat_mitrecar/mappings/plaso_linux.py` | `sources/l2t_text.yaml` |
| S6 | `windows.piiat.sessions` | Volatility3 (PIIAT-Mem custom plugin) | per-process token LUID | login | `third_party/piiat-mem/piiat_mem/mappings.py` (+ `plugins/windows/piiat/sessions.py`) | `sources/memory.yaml` |
| S7 | `windows.sessions` | Volatility3 built-in (fallback) | TS session | login | `third_party/piiat-mem/piiat_mem/mappings.py` | — |

**Provenance-tier legend** (as used in the generated `sources/*.yaml`): `[direct]` = 1:1 native field; `[coalesced]` = first-non-null of several; `[inferred]` = value-mapped / regex-filtered; `[derived]` = transformed (e.g. host label); `[asserted]` = a constant the event's existence proves.

---

## Per-field provenance

### `dest_ip` — destination IP of the session (remote/RDP only)

| source | native field → | action(s) | mapped? | confidence & caveats |
|---|---|---|---|---|
| **ALL (S1–S7)** | — (none) | — | **NO — honest no-source everywhere** | High. No host-side session artefact records a *destination* address: `Computer` is the destination *host* (→ `hostname`), not an IP. EvtxECmd `evtx_windows.py:154-156` explicitly nulls it; SMB SOCKADDR blobs (`evtx_more.py:158`) are kept native, never faked into `dest_ip`. `dest_ip`/`dest_port` are meaningful only for a *client-side/outbound* RDP session, which none of these logs capture. |

**Verdict:** `dest_ip` is **unmapped for all 5 actions from all 7 sources** — and correctly so; there is no grounded source.

### `dest_port` — destination port (remote/RDP only)

| source | native field → | action(s) | mapped? | confidence & caveats |
|---|---|---|---|---|
| **ALL (S1–S7)** | — (none) | — | **NO — honest no-source everywhere** | High. Same as `dest_ip`: no session artefact records a destination port. |

### `hostname` — host of the session, without domain (the machine the session runs ON)

| source | native field → | action(s) | mapped? | confidence & caveats |
|---|---|---|---|---|
| S1 `evtx_security_sessions` | `Computer` → `host_label()` (first DNS label) `[derived]` | login, logout, reconnect, unlock | **YES** — `evtx_windows.py` `_session_props()` | High. |
| S2 `evtx_rdp` | `Computer` → `host_label()` `[derived]` | login, logout, reconnect | **YES** — `evtx_extra.py` | High. |
| S3 `evtx_more` (7001/7002) | `Computer` → `host_label()` `[derived]` | login, logout | **YES** — `evtx_more.py` (`_HOST`) | High. |
| S4 `l2t_utmp`/`utmpx` | `image_hostname` `[direct]` | login, logout | **YES** — `plaso_linux.py` `_session_map()` | High. **Caveat:** this is the *imaged host*, per the vetted view. utmp's own `Record.hostname` field is the login **SOURCE** host and is kept in `_native.hostname` — CAR `user_session` has no `src_hostname` field. |
| S5 `l2t_text` (sshd) | `image_hostname` `[direct]` | login | **YES** — `plaso_linux.py` | High. Syslog reporter hostname kept native, not used here. |
| S6 `windows.piiat.sessions` | — | login | **NO (as a `props` field)** | Med. Not set in `props`; the host is carried on the CAR common header `source_host`, not the canonical `hostname` column → canonical `hostname` is an honest null from memory. |
| S7 `windows.sessions` | — | login | **NO (as a `props` field)** | Same as S6. |

### `login_id` — the Windows LUID; THE join key of the authentication↔user_session cascade (persists until logout)

| source | native field → | action(s) | mapped? | confidence & caveats |
|---|---|---|---|---|
| S1 `evtx_security_sessions` | `first(TargetLogonId, LogonID)` `[coalesced]` | login, logout, reconnect, unlock | **YES** — `evtx_windows.py` `_session_props()` | High. THE designed key. 4624 family uses `TargetLogonId`; the 4778/4779 pair uses `LogonID` (coalesced). Well-known singletons (`0x3e7/0x3e5/0x3e4`) recur per boot → heuristic across multi-boot logs (`docs/CAR-Relations.md` auth §, R1). `0x0`/blank = null session, never a key. |
| S6 `windows.piiat.sessions` | `LogonId` = `_TOKEN.AuthenticationId` (hex) `[direct]` | login | **YES** — `piiat-mem/mappings.py` | High. This is the *real* LUID (same value 4624 logs as `TargetLogonId`) → **cross-artefact joinable** (evtx 4624 ↔ memory session; `CAR-Relations.md`: 1616/1616, 104 definitive on lonewolf). Verified in evidence: `windows.piiat.sessions.jsonl` rows carry `LogonId:"0x3e7"`. |
| S7 `windows.sessions` (built-in fallback) | `"Session ID"` (TS session int) `[direct]` | login | **YES, but near-miss** — `piiat-mem/mappings.py` | Low-Med. This is the *terminal-services session number* (0/1/…), **not** the token LUID — so it will NOT join evtx `TargetLogonId`. S6 is preferred precisely to avoid this; S7 is a degraded fallback when the custom plugin is absent. |
| S2 `evtx_rdp` | — (`SessionID` kept native) | login/logout/reconnect | **NO** | High. TerminalServices carries a TS `SessionID`, not a LUID → `login_id` null; `SessionID` in `_native` (used by R1 lifecycle's by-SID pairing, never promoted). |
| S3 `evtx_more` (7001/7002) | — (`TSId` kept native) | login/logout | **NO** | High. Winlogon 7001/7002 carry only `UserSid` + `TSId` → `login_id` null. |
| S4/S5 Linux (utmp/utmpx/sshd) | — (none) | login/logout | **NO — honest null** | High. No Linux LUID analogue; `plaso_linux.py` docstring is explicit: never faked from pid/terminal. |

### `login_successful` — boolean; was the login attempt successful

| source | native field → | action(s) | mapped? | confidence & caveats |
|---|---|---|---|---|
| S1 `evtx_security_sessions` (4624) | `const(True)` `[asserted]` | login, **unlock** | **YES (True only)** — `evtx_windows.py` (`login_successful=const(True)`) | High. A mapped 4624 *is* the successful logon. **Not set** on logout/reconnect (a logoff/disconnect records no login decision) → null there. |
| S3 `evtx_more` (7001) | `const(True)` `[asserted]` | login | **YES (True only)** — `evtx_more.py` | Med. Winlogon 7001 corroborates a completed logon. Not set on 7002/logout. |
| S6 `windows.piiat.sessions` | `const(True)` `[asserted]` | login | **YES (True only)** — `piiat-mem/mappings.py` (**recently extended**) | High. Proven by existence: a live access-token bearing the AuthenticationId LUID exists only because LSA completed the logon. |
| S7 `windows.sessions` | `const(True)` `[asserted]` | login | **YES (True only)** — `piiat-mem/mappings.py` | Med. Same "session with live processes ⇒ logon completed" logic. |
| S2 `evtx_rdp` | — | login/logout/reconnect | **NO** | Med. Left null — though TS EID 21 is literally "logon succeeded", the map does not assert `True` (design choice: the record is a session-state notice, not an auth decision). Candidate to assert `True` on 21. |
| S4 `l2t_utmp`/`utmpx` | — | login/logout | **NO** | Med. A USER_PROCESS record implies success but the map does not assert it; failed logins live in **btmp** (not ingested). |
| S5 `l2t_text` (sshd) | — | login | **NO** | High. `syslog:ssh:login` = an "Accepted" line (implicitly success) but `True` is not asserted; sshd **"Failed password"** lines are a *different* data_type, **not mapped** → no `False`. |
| **— FAILED LOGINS (`False`) —** | Security **4625** → **authentication/failure** (`core.py`), NOT user_session; sshd "Failed password"; **btmp**; **lastlog** | login | **NO SOURCE PRODUCES `False`** | High, load-bearing gap. Per `evtx_windows.py:14-19` and `CAR-Relations.md` "a failed authentication opens **no** session" — 4625 is deliberately diverted to the `authentication` object. Net effect: **`login_successful` is effectively write-only-`True`** on `user_session`. |

### `login_type` — CAR vocabulary (`interactive` / `local` / `rdp` / `remote`)

| source | native field → | action(s) | mapped? | confidence & caveats |
|---|---|---|---|---|
| S1 `evtx_security_sessions` | `map_value(LogonType, {2→interactive, 3→remote, 10→rdp})` `[inferred]` | login, logout, reconnect, unlock | **YES (partial)** — `evtx_windows.py` `_LOGIN_TYPE` | High. Only the three vetted ints map. Every other `LogonType` (0 system, 4 batch, 5 service, 7 unlock, 8/9 cleartext/new-cred, 11 cached) → **null**, with the raw int kept in `_native.LogonType`. **`local` has no source here** (console feeders like utmp would assert it, but don't). Note: `LogonType 7` drives the **unlock action**, not `login_type`. |
| S2 `evtx_rdp` | — (deliberately null) | login/logout/reconnect | **NO** | High. EID 21 fires for BOTH console and RDP (only `Address` distinguishes) → asserting `rdp` would be a guess. **Gap:** even a non-`LOCAL` `Address` (proven RDP) does not set `login_type=rdp`. |
| S3–S7 (Winlogon / Linux / memory) | — | — | **NO — null** | High. utmp record-type ints are NOT the CAR vocabulary → kept native (`plaso_linux.py`); sshd `authentication_method` (password/publickey) is native, not `login_type`; memory carries none. |

### `src_ip` — source IP of the session (remote/RDP only)

| source | native field → | action(s) | mapped? | confidence & caveats |
|---|---|---|---|---|
| S1 `evtx_security_sessions` | `regex1(first(IpAddress, ClientAddress), <not ::1/127.0.0.1/LOCAL>)` `[inferred]` | login, logout, reconnect, unlock | **YES** — `evtx_windows.py` `_session_props()` | High. 4624 `IpAddress` (type 3/10); 4778/4779 `ClientAddress`. Console (type 2) is blank/`-`/`LOCAL` → null. **This is one RDP `src_ip` path.** |
| S2 `evtx_rdp` | `regex1(userdata("Address"), <not LOCAL>)` `[inferred]` | login, logout, reconnect | **YES** — `evtx_extra.py` | High. **The TerminalServices RDP client IP is mapped.** Console session `Address="LOCAL"` → honest null. |
| S4 `l2t_utmp`/`utmpx` | `regex1(ip_address, <not 0.0.0.0/127.0.0.1/::1>)` `[inferred]` | login, logout | **YES** — `plaso_linux.py` `_SRC_IP` | High. Remote source of the login; loopback/unset → null. |
| S5 `l2t_text` (sshd) | `regex1(ip_address, …)` `[inferred]` | login | **YES** — `plaso_linux.py` | High. sshd client IP. |
| S3 `evtx_more` (7001/7002) | — | login/logout | **NO — null** | High. Winlogon carries no origin address. |
| S6/S7 memory | — | login | **NO — null** | High. Memory sessions carry no origin address. |

> **Correction to the brief's gap list:** RDP `src_ip` is **NOT a gap** — it is covered twice (S1 Security 4778/4779 `ClientAddress`, and S2 TerminalServices `Address`). What *is* thin on RDP is `src_port` and `login_type` (below).

### `src_port` — source port

| source | native field → | action(s) | mapped? | confidence & caveats |
|---|---|---|---|---|
| S1 `evtx_security_sessions` | `regex1(IpPort, <not 0>)` `[inferred]` | login, logout, reconnect, unlock | **YES** — `evtx_windows.py` | High. 4624 `IpPort`; `0`/`-` → null. Only network logons carry it. |
| S5 `l2t_text` (sshd) | `port` `[direct]` | login | **YES** — `plaso_linux.py` (`extra_props`) | High. sshd client port. |
| S2 `evtx_rdp` | — | login/logout/reconnect | **NO — null** | High. TerminalServices records no client port. |
| S4 `l2t_utmp`/`utmpx` | — | login/logout | **NO — null** | High. utmp carries no port. |
| S3/S6/S7 | — | — | **NO — null** | High. None carry a port. |

### `uid` — SID / ID of the user

| source | native field → | action(s) | mapped? | confidence & caveats |
|---|---|---|---|---|
| S1 `evtx_security_sessions` | `TargetUserSid` `[direct]` | login, logout, reconnect, unlock | **YES** — `evtx_windows.py` | High. **Caveat:** the 4778/4779 pair carries **no SID** → `uid` null on those records (affects some reconnect/logout rows). |
| S3 `evtx_more` (7001/7002) | `UserSid` `[direct]` | login, logout | **YES** — `evtx_more.py` | High. This is 7001/7002's *only* identity (no username) → uid-only rows. |
| S6 `windows.piiat.sessions` | `Sid` (token user SID) `[direct]` | login | **YES** — `piiat-mem/mappings.py` | High. Verified in evidence (`Sid:"S-1-5-18"`). |
| S2 `evtx_rdp` | — | login/logout/reconnect | **NO — null** | High. TerminalServices has no SID. |
| S4/S5 Linux (utmp/utmpx/sshd) | — | login/logout | **NO — null** | High. utmp/sshd records carry a *username*, not a numeric POSIX uid → honest null (never faked). |
| S7 `windows.sessions` | — | login | **NO — null** | Med. Built-in sessions row has no SID column. |

### `user` — the account affiliated with the session

| source | native field → | action(s) | mapped? | confidence & caveats |
|---|---|---|---|---|
| S1 `evtx_security_sessions` | `first(TargetUserName, AccountName, UserName)` `[coalesced]` | login, logout, reconnect, unlock | **YES** — `evtx_windows.py` | High. 4778/4779 use `AccountName`; `UserName` (EvtxECmd column) is last-resort. |
| S2 `evtx_rdp` | `userdata("User")` `[direct]` | login, logout, reconnect | **YES** — `evtx_extra.py` | High. |
| S4 `l2t_utmp`/`utmpx` | `username` `[direct]` | login, logout | **YES** — `plaso_linux.py` | High. |
| S5 `l2t_text` (sshd) | `username` `[direct]` | login | **YES** — `plaso_linux.py` | High. |
| S6 `windows.piiat.sessions` | `User` (SID→SOFTWARE ProfileList basename) `[derived]` | login | **YES** — `piiat-mem/mappings.py` | Med-High. `NotAvailable` when the SID has no profile (service/well-known SIDs). Verified (`User:"systemprofile"`). |
| S7 `windows.sessions` | `"User Name"` `[direct]` | login | **YES** — `piiat-mem/mappings.py` | Med. |
| S3 `evtx_more` (7001/7002) | — | login/logout | **NO — null** | High. Winlogon 7001/7002 carry `UserSid` only, no name → `uid`-only (a resolvable-downstream gap: name must come from a SID→name join). |

---

## Coverage matrix (field × action, best available source)

Legend: ✔ mapped · ✔* mapped True-only (asserted) · ~ partial / near-miss · ✘ no source / null. "best source" in parentheses.

| field | login | logout | reconnect | unlock | lock |
|---|---|---|---|---|---|
| dest_ip | ✘ | ✘ | ✘ | ✘ | ✘ |
| dest_port | ✘ | ✘ | ✘ | ✘ | ✘ |
| hostname | ✔ (S1/2/3/4/5) | ✔ (S1/2/3/4) | ✔ (S1/2) | ✔ (S1) | ✘ |
| login_id | ✔ (S1, S6 LUID) | ✔ (S1) | ✔ (S1) | ✔ (S1) | ✘ |
| login_successful | ✔* (S1/3/6/7 True) | ✘ | ✘ | ✔* (S1) | ✘ |
| login_type | ~ (S1: 2/3/10 only) | ~ (S1) | ~ (S1) | ~ (S1) | ✘ |
| src_ip | ✔ (S1/2/4/5) | ✔ (S1/2/4) | ✔ (S1/2) | ✔ (S1) | ✘ |
| src_port | ✔ (S1/5) | ✔ (S1) | ~ (S1 only) | ✔ (S1) | ✘ |
| uid | ✔ (S1/3/6) | ✔ (S1/3) | ~ (S1: null on 4778) | ✔ (S1) | ✘ |
| user | ✔ (S1/2/4/5/6/7) | ✔ (S1/2/4) | ✔ (S1/2) | ✔ (S1) | ✘ |

**The `lock` action is a fully empty row — no source fires it (see gap #1).** The `unlock` column is populated only via S1's 4624/LogonType-7 relogon, not by a true lock/unlock event.

---

## Summary

**What is well covered.** The Windows Security 4624-family (S1) is the workhorse: it supplies **8 of 10 fields** (`hostname, login_id, login_successful, login_type, src_ip, src_port, uid, user`) across login/logout/reconnect/unlock, and the LUID (`login_id`) it emits is the designed join key — corroborated cross-artefact by the Volatility memory plugin (S6, `_TOKEN.AuthenticationId`), verified against real evidence (`windows.piiat.sessions.jsonl`, `LogonId:"0x3e7"`). RDP (S2) and Linux utmp/utmpx/sshd (S4/S5) fill `user`/`src_ip`(+`src_port` for sshd) with good confidence. `user` and `hostname` have the broadest source coverage; `src_ip`/`src_port` have solid Windows+Linux coverage. The `login_successful=True` assertion is present on all four "opening" Windows/memory paths (recently extended into PIIAT-Mem sessions).

**UNMAPPED / weak — ranked by impact:**

1. **`lock` action + true lock/unlock events (Security 4800/4801, 4802/4803).** Highest gap. The `lock` action **never fires** from any source; `unlock` fires only as a 4624 LogonType-7 relogon, never from the actual lock/unlock (4800/4801) events, which are deliberately out of `evtx_security_sessions` scope (`evtx_windows.py:18-19, 267`). Two of five canonical actions are effectively uncovered by their proper artefacts. **Fix:** add a Security 4800→`lock` / 4801→`unlock` (and 4802/4803 screensaver) map keyed on `TargetLogonId` for the LUID join.

2. **`login_successful = False` (failed logins) — no source produces it.** `login_successful` is write-only-`True`. Security **4625** is diverted to the `authentication/failure` object (by design, `CAR-Relations.md`: "a failed authentication opens no session"); sshd "Failed password", **btmp**, and **lastlog** failures are not ingested at all. If failed-login visibility on `user_session` is desired, it needs a deliberate decision (map a shadow `login_successful=False` from 4625 / btmp / sshd-failed).

3. **`btmp` and `lastlog` (Linux) — not ingested.** Plaso parses utmp/utmpx/wtmp (successful/logout only). btmp (failed logins) and lastlog (last-login summary) have no source key → no failed-login or last-login `user_session` on Linux.

4. **RDP thinness (NOT `src_ip` — that is covered).** Correcting the brief: RDP `src_ip` **is** mapped twice (S1 4778/4779 `ClientAddress`, S2 TerminalServices `Address`). The real RDP gaps are: `login_type=rdp` is **never asserted** on S2 (left null even when `Address` proves RDP); `src_port`, `login_id`(LUID), and `uid` are all null on the TerminalServices channel; and S2 only handles EIDs **21/24/25** — **23 (logoff), 39/40 (disconnect)** are unmapped (24-disconnect is used as the `logout` proxy). Security 4779 covers RDP disconnect on the S1 side.

5. **`dest_ip` / `dest_port` — no source, correctly.** No host-side session artefact records a session *destination* address/port (these matter only for client-side/outbound RDP). Honest permanent null across all sources.

6. **Winlogon 7001/7002 (S3) name gap.** Carries `UserSid` only → `user` null (uid-only rows); `login_id`(LUID) also null (`TSId` kept native). Resolvable downstream via a SID→name / TSId join, not at map time.

7. **`login_type` partial + no `local`.** Only Windows LogonType 2/3/10 map (→interactive/remote/rdp); the `local` vocabulary value is never emitted by any source, and utmp record-types are (correctly) not force-fit into it.

8. **Security 4964 (special-groups logon), 4648 (explicit-cred issuance) — unmapped.** 4648 is a deliberate honest-null (no outcome in the record); 4964 has no map.

**Evidence caveat:** the processed corpus on hand (`data_store/processed/`) is a light set — the only EvtxECmd export present is Sysmon-only (no Security/System/TerminalServices session events), so S1–S3 wiring is verified by code + generated `sources/*.yaml` rather than by a live session row here. Real `user_session` evidence present: `volatility/.../windows.piiat.sessions.jsonl` (clean S6 rows) and `log2timeline/jsonl/5g-webui.jsonl` (1,398 `linux:utmp:event` — S4; note this particular image parses to junk field values, so it validates field *wiring*, not content).
