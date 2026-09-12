# CAR `user_session` — FILESYSTEM / dead-box provenance (unmined disk artefacts)

Deep audit of the MITRE CAR **`user_session`** object for **filesystem / disk artefacts** (dead-box, no
event logs) that *could* fill its properties but the pipeline has **not mined** yet. Companion to the
event-log-centric `docs/car-provenance/user_session.md` (that pass covered S1–S7: Security evtx, RDP
TerminalServices evtx, Winlogon evtx, Linux utmp/utmpx/sshd, Volatility memory). This pass is the **disk
lane** those seven sources ignore.

- **Object fields (10):** `dest_ip, dest_port, hostname, login_id, login_successful, login_type, src_ip, src_port, uid, user`
- **Actions (5 in brief; model also has create/metadata/terminate):** `lock, login, logout, reconnect, unlock`
- **Ground truth image:** LoneWolf Win10 (`LoneWolf.E01`, host `DESKTOP-PM6C56D`), plaso super-timeline
  `data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl` (6.5 GB, 4.17 M rows). Real records quoted below.
- **Engine maps:** `byakugan/byakugan/mappings/` (`plaso_registry.py`, `plaso_linux.py`),
  enrichment `byakugan/byakugan/enrich.py`, routing `byakugan/byakugan/pipeline.py`.

---

## Headline finding — the whole disk lane is unmined for `user_session`

**No filesystem/disk artefact produces a `user_session` object today.** Every emitter of
`"object": "user_session"` in the codebase is an **event-log / winevt / utmp / memory** source:

| emitter | file | lane |
|---|---|---|
| Security 4624-family | `mappings/evtx_windows.py:231,248,259` | evtx |
| Winlogon 7001/7002 | `mappings/evtx_more.py:172,183` | evtx |
| RDP TerminalServices 21/24/25 | `mappings/evtx_extra.py:80` | evtx |
| utmp/utmpx/sshd | `mappings/plaso_linux.py:300` | plaso (Linux login DB) |
| Volatility sessions | `../piiat-mem/piiat_mem/mappings.py:251,343` | memory |

The registry hives **are parsed and ingested** — SAM `sam_users`, SOFTWARE `ProfileList`, `Winlogon`,
`shutdown` all flow through the pipeline — but `mappings/plaso_registry.py` claims **every** `windows:registry:*`
data_type as a **`registry` object, action `key_edit`** (line 44-110). The account fields that ARE the
substance of a session (`username`, `account_rid`, `login_count`) are dropped into `_native` (lines 80-84) and
the timestamp — even when it is literally a **"Last Login Time"** — is relabelled a registry key-edit. The
session semantics is thrown away. So the answer to the "is ANY disk source mapped to user_session?" column
below is **NO, everywhere.**

Second-order gap: `byakugan/byakugan/enrich.py` has **no SID→user resolution from plaso ProfileList rows**. (The
separate PIIAT-Mem/Volatility `enrich.py:_sid_user_index` does a ProfileList join, but it keys on a flat
`value=="ProfileImagePath"` shape the plaso registry rows — which nest values in a `_native.values` LIST — do
not have.) So even the `uid`↔`user` link that disk fully supports is not wired on the disk lane.

---

## Per-field provenance (filesystem / disk artefacts only)

Legend for **mined?**: **NO(reg)** = the artefact IS ingested but only as a `registry`/`file` object, never
as `user_session`; **NO(none)** = not ingested at all; **null** = honest no-source from disk.

| field | fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|---|
| **user** | SAM `sam_users.username` (`jcloudy`) **[direct]**; SOFTWARE `ProfileList\<SID>.ProfileImagePath` basename (`C:\Users\jcloudy`→`jcloudy`) **[derived]** | login | **NO(reg)** — both become `registry/key_edit`; username sits in `_native`, ProfileImagePath in `_native.values` | HIGH. Two independent disk sources agree. |
| **uid** (SID) | SAM `account_rid` (`1001`) **[direct]** + machine domain-SID prefix from any `ProfileList\S-1-5-21-…` subkey → full SID `S-1-5-21-2734969515-1644526556-1039763013-1001` **[derived]**; or the ProfileList key SID itself **[direct from key_path]** | login | **NO(reg)** | HIGH. RID→SID reconstruction is deterministic (one domain-SID prefix per image; also in `SAM\Domains\Account\V`). ProfileList only lists *loaded* profiles, but the prefix it yields resolves every local RID (incl. never-logged-in Administrator/Guest). |
| **hostname** | `image_hostname` (`DESKTOP-PM6C56D`) on every plaso row **[direct]**; SYSTEM hive `ComputerName` | all | **NO(reg)** as a `user_session` field — value rides on registry rows / the CAR header, never a session | HIGH. |
| **login_successful** | SAM `sam_users.login_count`>0 **and** a real "Last Login Time" ⇒ assert `True` **[asserted]** | login | **NO** | MED. Sound *True* assertion (a recorded last-login proves ≥1 success). **No `False` from disk**: plaso's `sam_users` exposes `login_count` but **not** the bad-password / failed-login counters in the SAM `F` value, and Windows has no on-disk failed-login store (no btmp analogue) — failed logons live only in Security.evtx 4625. |
| **login_id** (LUID) | — | — | **null** | HIGH honest null. The LUID is a runtime, per-boot token id; it is never persisted to any hive or file. Disk cannot supply the cross-artefact join key. |
| **login_type** | — (LogonUI/Winlogon/SAM record no logon-type) | — | **null** | HIGH honest null. Could only be *guessed* (`interactive`/`local` for a console profile) — no artefact states it. Do not fake. |
| **src_ip / src_port** | — (inbound-session origin is not written to disk) | — | **null** | HIGH. Source endpoint of an inbound logon exists only in the Security log / network capture, not on the dead disk. |
| **dest_ip / dest_port** | RDP **client** artefacts only: `NTUSER\…\Terminal Server Client\Default\MRU*` + `\Servers\<host>` (dest host/user), `Default.rdp`, bitmap cache `Cache####.bin` **[derived]** | login | **NO(none) / null here** | MED-conditional. Meaningful **only if the host was used as an RDP client**. **Absent on this image** — DESKTOP-PM6C56D was not an RDP client (no `Terminal Server Client` key; only OS RDP binaries in WinSxS). So honest null *here*, a real conditional source *elsewhere*. Yields a hostname, rarely a literal IP; port never. |

---

## Ranked UNMINED opportunities (real disk sources, not yet mapped to `user_session`)

**1. SAM `sam_users` → `user_session/login` — the headline.** `winreg/windows_sam_users` already emits a
per-account **"Last Login Time"** row whose `Timestamp` IS the last-logon FILETIME; `plaso_registry.py`
currently drowns it as a `registry/key_edit`. Everything a login row needs is on the record:

```
data_type: windows:registry:sam_users   parser: winreg/windows_sam_users
display_name: NTFS:\Windows\System32\config\SAM     image_hostname: DESKTOP-PM6C56D
username: jcloudy   account_rid: 1001   login_count: 23
timestamp_desc: "Last Login Time"   ts: 1523017587572470  (2018-04-06T13:46:27Z)
```

Map → `user_session` login: `user`=username, `uid`=RID→SID, `login_successful=True` (login_count>0),
`hostname`=image_hostname, `login_count`→`_native`, ts=Last Login Time. Confidence HIGH; the data is *already
flowing through the pipeline* with the correct timestamp — it only needs a second (user_session) emission on
the `Last Login Time` variant. (LoneWolf: `jcloudy` RID 1001, 23 logins, last 2018-04-06; `defaultuser0` RID
1000, 2 logins.)

**2. SOFTWARE `ProfileList` SID↔user index → `uid`↔`user` resolution + downstream naming.** Ingested today as
`windows:registry:key_value` (`ProfileList\S-1-5-21-…-1001 → C:\Users\jcloudy`). Wire a disk-lane SID→user
index in `byakugan/byakugan/enrich.py` (mirroring PIIAT-Mem's `_sid_user_index`, but reading `_native.values` for
`ProfileImagePath`) so RID-only SAM rows and SID-only Winlogon rows get a `user`, and vice-versa. Confidence HIGH.

**3. SAM "Last Password Set Time" → `user_session/metadata` (or `authentication`).** Same `sam_users` record
carries a `Last Password Set Time` variant (`jcloudy` ts 1522142338259150) — the account credential timeline
alongside the login. Currently a registry key_edit. Confidence HIGH for the fact, MED for placing it on
`user_session` vs `authentication`.

**4. Profile-hive load times (session-activity proxy).** `NTUSER.DAT` / `UsrClass.dat` MAC times
(`fs:stat`, currently the **`file`** object) and their registry **last-write** stamps bound when the profile
was mounted — i.e. a login/logout window when no session log survives. LoneWolf `NTFS:\Users\jcloudy\NTUSER.DAT`
Creation Time ts 1522142338688793. Confidence MED (a proxy, not a session record); best surfaced as a
`user_session/metadata` corroborator, not a hard login.

**5. `Last Shutdown Time` (SYSTEM `\ControlSet001\Control\Windows\ShutdownTime`) → logout/session-end proxy.**
Present (`windows:registry:shutdown`, `timestamp_desc: Last Shutdown Time`) → registry key_edit today. Bounds
the end of the last session. Confidence MED (machine-wide, not per-user).

**6. RDP client-side artefacts → `dest_*`/`user` for OUTBOUND rdp (conditional).** `Terminal Server Client`
MRU / `Servers` subkeys, `Default.rdp`, bitmap cache `Cache*.bin`. The only disk path to `dest_ip`/`dest_port`.
**Not present on this image** (workstation, not an RDP client) — a real source on jump-boxes/admin hosts.
Confidence MED-conditional.

---

## Honest no-sources (do not fake from disk)

- **`login_id` (LUID)** — runtime-only, never persisted; permanent disk null.
- **`login_type`** — no hive/file records the CAR vocabulary; would be a guess.
- **`src_ip` / `src_port`** — inbound-session origin is not written to disk (Security.evtx / pcap only).
- **`dest_ip` / `dest_port`** — only via RDP *client* artefacts, only if the host was a client; null on this image.
- **`login_successful = False`** — plaso `sam_users` exposes `login_count` but not the SAM `F` bad-password /
  failed-login counters; Windows keeps no on-disk failed-login store (no btmp analogue). No `False` from disk.
- **`lock` action** — no filesystem artefact records a workstation lock/unlock (Security 4800/4801 only).

**Tangential / weak:** `ActivitiesCache.db` (Windows Timeline, per-user under
`…\ConnectedDevicesPlatform\<id>\`) is present **only as `fs:stat`** (file MAC times) — plaso does not parse
its SQLite content; and it records app usage, not sessions. Note, don't prioritise.

**Security.evtx fallback (de-emphasised, filesystem focus):** carving the on-disk `Security.evtx` from the
image and feeding the **evtx lane** would light up S1 (4624-family → 8/10 fields) — but that is the event-log
lane, not a registry/filesystem artefact, and no on-disk Security.evtx is present in this light LoneWolf
collection (`data_store/raw/collections/lonewolf/logs/winevt/` is empty). Filesystem-native `user_session`
therefore rests on the SAM/ProfileList registry chain above.

---

## Bottom line

The disk lane is a **clean, unexploited seam** for `user_session`: SAM `sam_users` "Last Login Time" (login,
user, uid-via-RID, login_successful=True, login_count) plus SOFTWARE `ProfileList` (uid↔user) reconstruct a
genuine login event with HIGH confidence entirely from dead hives that the pipeline already parses — today
they are silently demoted to `registry/key_edit` rows. `login_id`, `login_type`, `src_*`, and inbound
`dest_*` are honest disk nulls; `dest_*` via RDP-client artefacts is a real but image-conditional source
(absent on LoneWolf).
