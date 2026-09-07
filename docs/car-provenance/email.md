# CAR `email` — Property-Provenance Catalogue

Authoritative "find once, done" map of every canonical `email` field to every artefact/source that can supply it, what the DX_DFIR engine maps **today**, and what an unmapped field **would** need. Grounded in-repo; honest about the gaps.

- **Object semantics:** `third_party/piiat-mitrecar/third_party/car/data_model/email.yaml`, `.../docs/data_model/email.md`, `python model/car/objects/email.yml`, `python model/projection/objects/email.yml` (ECS projection).
- **Engine mapping (the only email mapper):** `third_party/piiat-mitrecar/piiat_mitrecar/mappings/zeek_extra.py` (map `zeek_smtp`), contract `third_party/piiat-mitrecar/sources/zeek_smtp.yaml`, helpers `piiat_mitrecar/normalize.py`.
- **Design record / caveats:** `docs/CAR-Relations.md` § "email (no artefact yet — principles recorded for the first mapper)".
- **Evidence checked:** `data_store/processed/zeek/*` (DFIRdump, ME_FOR_1308, keylogging).

## Object at a glance

- **21 fields** · **5 actions**: `deliver`, `block`, `redirect`, `quarantine`, `delete`.
- Email events are defined **at the mail-server level**. Identity key (per CAR-Relations): `(source_host, smtp_uid, action, time)`.

## Headline finding

**`email` has NO live source in the store today.** Exactly one mapper exists — `zeek_smtp` — and it emits **only `deliver`** and **only when the SMTP row carries real content** (predicate `zeek_is_smtp_message`: any of `mailfrom`/`rcptto`/`from`/`to`/`subject`). No `smtp.json` exists in any processed capture; the DFIRdump capture carries only dns/ssh/ssl/http (0 SMTP-port connections), and per CAR-Relations "the one real smtp capture on hand is STARTTLS-encrypted — an empty `car_email` table is the honest output." So even the 11 fields the mapper *can* fill produce **zero rows** on current evidence.

- **11 fields have a live mapper** (all via `zeek_smtp`, all tier `direct`/`coalesced`/`derived`): `date, dest_address, dest_ip, dest_port, from, src_address, src_domain, src_ip, src_port, subject, to`.
- **10 fields are unmapped**: `action_reason, attachment_mime_type, attachment_name, attachment_size, message_body, message_links, message_type, return_address, server_relay, smtp_uid`.
- **4 of 5 actions are unmapped**: `block, redirect, quarantine, delete` have **no source wired at all** (they are mail-**server** security/audit verdicts, not wire-observable). Only `deliver` has a mapper.
- **No mail-store / mail-server parser is wired anywhere** (grep for pff/PST/OST/mbox/EML/maillog/Exchange/Postfix across `piiat_mitrecar/` returns nothing). Plaso adapters exist (`l2t_*`, `plaso_*`) but none map to `email`. No CAR sensor (sysmon/osquery/auditd/…) and no CAR analytic (`grep email/`) covers `email` upstream either. Suricata appears only as a signature/alert engine (`python/get_sybers_dxdfir/detect/rules/sig-suricata-alert.yml`), **not** as a CAR extraction source.

**Provenance tiers** (engine vocabulary): `[direct]` = verbatim native field · `[coalesced]` = first non-empty of several (`normalize.first`) · `[derived]` = computed (`domain_of`, `ext`, `epoch_ts`) · `[native/raw]` = retained in the `native` blob but **not** promoted to a canonical column · `[none]` = no source produces it.

## Source universe (shorthand used in the table)

| Source | What it is | In-repo status |
|---|---|---|
| **Zeek smtp.log** | Wire-observed SMTP transaction (headers + envelope, **no body**). Native fields: `ts, uid, trans_depth, helo, mailfrom, rcptto, from, to, cc, reply_to, msg_id, in_reply_to, date, subject, first_received, second_received, last_reply, path, user_agent, tls, fuids, x_originating_ip, is_webmail, id.orig_h/p, id.resp_h/p`. | **Mapped** (`zeek_smtp`, content-bearing rows → `deliver`; STARTTLS/contentless → raw). No live evidence. |
| **Zeek files.log** | File objects Zeek reconstructs from traffic; joined to the SMTP txn by `fuids`. Native: `filename, mime_type, seen_bytes, total_bytes, md5, sha1, sha256, source(=SMTP)`. | **Mapped to the `file` object** (`zeek_files`), **not** into `email.attachment_*`. |
| **Zeek conn.log** | 5-tuple / flow for the SMTP `uid`. | Mapped to `flow`; contributes src/dest ip/port to the smtp row via the shared `uid`. |
| **Exchange message-tracking** | `MessageTrackingLog` (EVENTID DELIVER/RECEIVE/FAIL/…, `InternalMessageId`, sender/recipient, subject). | Not wired. Would need a maillog/CSV parser. |
| **O365 / Defender for O365** | Unified Audit + `EmailEvents` / message-trace / `EmailAttachmentInfo` / `EmailUrlInfo` / `UrlClickEvents`. | Not wired. |
| **Google Workspace Gmail audit / BigQuery email logs** | Server-side delivery + security verdicts. | Not wired. |
| **Postfix / Sendmail / Exim maillog** | syslog lines (queue-id, `from=`/`to=`, `status=`, reject reason) → Plaso syslog parser. | Not wired. |
| **Plaso mail-store parsers** | PST/OST (`pff`), `mbox`, single-message EML/MSG, browser webmail cache. Full RFC5322 headers **and body**. | Not wired (no email mapper for any Plaso data_type). |
| **Mail-client process memory** | Decrypted body/headers resident in RAM. | Not wired; limited/heuristic. |
| **Suricata smtp events** | `eve.json` smtp (helo, mail_from, rcpt_to, from/to/subject). | Not wired as a CAR source. |

---

## Per-field provenance

Format: `field | sources (source → native field) | action(s) | currently mapped? | confidence & caveats`.

| # | field | sources (source → native field) | action(s) | currently mapped? | confidence & caveats |
|---|---|---|---|---|---|
| 1 | **action_reason** | Exchange transport-rule/DLP verdict; O365/Defender `EmailEvents.ThreatTypes`/`DetectionMethods`; mail-gateway (Proofpoint/Mimecast) disposition; Postfix maillog reject text → *(native reason string)* | block, redirect, quarantine (delete) | **NO** | **[none] today.** Inherently a mail-**server** security decision — **never wire-observable**, so Zeek can never supply it. Meaningful only for the 4 unmapped actions. Needs a gateway/server security-log parser. |
| 2 | **attachment_mime_type** | Zeek files.log → `mime_type` (libmagic, join by `fuids`); mail-store PST/OST/EML/MSG → attachment `Content-Type`; O365 `EmailAttachmentInfo.FileType` | deliver (Zeek); any (mail-store) | **NO** (Zeek `mime_type` lands on the `file` object, not `email.attachment_mime_type`) | Med. CAR calls this "declared, not actual"; Zeek's value is libmagic-**observed** (more trustworthy than the MIME header). Needs an email↔file bridge over `fuids`, or a mail-store parser. |
| 3 | **attachment_name** | Zeek files.log → `filename` (join by `fuids`); PST/OST/EML/MSG → attachment filename; O365 `EmailAttachmentInfo.FileName` | deliver; any | **NO** (Zeek `filename` → `file` object only) | Med. Same fuids-bridge gap. Zeek only names files its analyzers extracted from the (cleartext) stream. |
| 4 | **attachment_size** | Zeek files.log → `seen_bytes`/`total_bytes` (kept in the `file` map's `keep`, join by `fuids`); PST/OST/EML attachment size; O365 `EmailAttachmentInfo.FileSize` | deliver; any | **NO** | Med. CAR example "567 Kb" is loose text; ECS `email.attachments.file.size` wants bytes (projection notes coercion keeps unparseable text verbatim). |
| 5 | **date** | **Zeek smtp.log → `date`** (RFC5322 Date header); PST/OST/EML/MSG Date header / `PR_CLIENT_SUBMIT_TIME`; mbox Date | deliver | **YES** — `zeek_smtp`: `date [direct]` (`zeek_extra.py`; `sources/zeek_smtp.yaml`) | High as a header value; **but it is the client's header, forgeable — never the event timestamp** (the store's own `timestamp` = `ts`). |
| 6 | **dest_address** | **Zeek smtp.log → `rcptto` \| `to`** (envelope RCPT TO = real recipient); Exchange `RecipientAddress`; Postfix `to=`; O365 `RecipientEmailAddress`; PST/OST recipient table | deliver (all, at a server) | **YES** — `zeek_smtp`: `rcptto | to [coalesced]` | High. Envelope recipient is authoritative — this, not `to`, is the real delivery target. |
| 7 | **dest_ip** | **Zeek smtp.log → `id.resp_h`** (receiving MTA); Zeek conn.log `id.resp_h`; derivable from `server_relay` Received chain | deliver | **YES** — `zeek_smtp`: `id.resp_h [direct]` | High within the capture vantage — the observed next-hop server IP. |
| 8 | **dest_port** | **Zeek smtp.log → `id.resp_p`** (25/465/587); Zeek conn.log | deliver | **YES** — `zeek_smtp`: `id.resp_p [direct]` | High. |
| 9 | **from** | **Zeek smtp.log → `from`** (header From display); PST/OST/EML From; message-tracking (sometimes) | deliver (all) | **YES** — `zeek_smtp`: `from [direct]` | **FORGEABLE** (MITRE says so verbatim). Display sender — **never attribute** identity from it. |
| 10 | **message_body** | PST/OST (`pff`) message body; mbox; EML/MSG body; mail-client process memory; browser webmail cache. **Not** in Exchange/O365 audit. | any (mail-store) | **NO** | **[none] from network.** Zeek smtp.log carries no body, and real SMTP here is STARTTLS-encrypted. **Honest no-source under STARTTLS** — needs a mail-store artefact (or RAM). |
| 11 | **message_links** | Derived from body → same mail-store/memory sources as `message_body`; O365 `EmailUrlInfo.Url` / `UrlClickEvents` as a dedicated source | any | **NO** | **[none] from network** (body encrypted/not logged). O365 URL telemetry is the cleanest dedicated feed; otherwise derive after a body exists. |
| 12 | **message_type** | Body `Content-Type` (`text/html` vs `text/plain`) → PST/OST/EML/MSG, mbox | any | **NO** | **[none] from network.** Needs the body part's declared Content-Type. Projects to ECS `email.content_type`. |
| 13 | **return_address** | **Zeek smtp.log → `reply_to`** (Reply-To) / envelope Return-Path (`mailfrom`); PST/OST/EML Reply-To / Return-Path header | deliver (all) | **NO** — **available in Zeek `reply_to` but the map does not extract it** (not in `props`, not in `keep`) | **Lowest-hanging gap.** Attacker-chosen; a mismatch vs `src_address` is *signal, not identity*. A one-line `props` add fills it wherever an SMTP artefact exists. |
| 14 | **server_relay** | **Zeek smtp.log → `path` / `first_received` / `second_received`** (Received chain); PST/OST/EML full `Received:` header chain (most complete) | deliver | **NO** — `path` is retained `[native/raw]` in the map's `keep` but **not promoted** to the canonical column | Med. Trustworthy only from the observing server inward. Promotion of `path` fills it today; mail-store gives the whole chain. |
| 15 | **smtp_uid** | Exchange `InternalMessageId`/`MessageId`; Postfix queue-id (maillog hex id); O365 `NetworkMessageId`. Zeek smtp.log → `msg_id` (RFC5322 Message-ID — a **semantic-mismatch proxy**) | deliver (shared across actions at one server) | **NO** — map builds the store GUID from `uid`+`trans_depth`; **does not populate `smtp_uid`** (and `msg_id` is not even kept) | CAR `smtp_uid` = server-**local** queue/transaction id (the identity discriminator), **≠ RFC Message-ID**. True value comes from server logs; Zeek `msg_id` is only the closest proxy. |
| 16 | **src_address** | **Zeek smtp.log → `mailfrom` \| `from`** (envelope MAIL FROM = real sender); Exchange `SenderAddress`; Postfix `from=`; O365 `SenderMailFromAddress`; PST/OST Sender | deliver (all) | **YES** — `zeek_smtp`: `mailfrom | from [coalesced]` | High. Envelope sender authoritative (MAIL FROM spoofable at open relays — pairs with `src_ip`/`server_relay`). |
| 17 | **src_domain** | Derived `domain_of(mailfrom \| from)`; any source supplying `src_address` supplies this | deliver (all) | **YES** — `zeek_smtp`: `domain_of(mailfrom | from) [derived]` | High (mechanical derivation; inherits `src_address`'s forgeability). |
| 18 | **src_ip** | **Zeek smtp.log → `id.orig_h`** (connecting client/relay); Zeek conn.log; Zeek `x_originating_ip` (true client behind webmail); first `Received:` IP from `server_relay` | deliver | **YES** — `zeek_smtp`: `id.orig_h [direct]` | High at the capture vantage — but the connecting host may be a relay, not the true origin. `x_originating_ip` (unmapped) recovers the real client for webmail. |
| 19 | **src_port** | **Zeek smtp.log → `id.orig_p`**; Zeek conn.log | deliver | **YES** — `zeek_smtp`: `id.orig_p [direct]` | High but ephemeral — low forensic value. |
| 20 | **subject** | **Zeek smtp.log → `subject`**; PST/OST/EML Subject; Exchange `MessageSubject`; O365 `Subject` | deliver (all) | **YES** — `zeek_smtp`: `subject [direct]` | High (cleartext only; empty under STARTTLS). |
| 21 | **to** | **Zeek smtp.log → `to`** (header To display); PST/OST/EML To header | deliver (all) | **YES** — `zeek_smtp`: `to [direct]` | Header To **≠ recipient list** (the envelope `dest_address` is the real recipient); CC/BCC not represented. |

---

## Coverage summary

| | count | fields |
|---|---|---|
| **Mapped** (live mapper, `zeek_smtp` only) | 11 | date, dest_address, dest_ip, dest_port, from, src_address, src_domain, src_ip, src_port, subject, to |
| **Unmapped** | 10 | action_reason, attachment_mime_type, attachment_name, attachment_size, message_body, message_links, message_type, return_address, server_relay, smtp_uid |

- **Action coverage:** only `deliver` has a mapper. `block / redirect / quarantine / delete` (and their `action_reason`) have **no source wired** — they require mail-server/gateway security & audit logs, none of which are ingested.
- **Live-data coverage: 0 rows.** No `smtp.json` in the store; the only real SMTP capture is STARTTLS-encrypted. The 11 "mapped" fields are contract-tested but unpopulated.

## Unmapped gaps, ranked (what WOULD supply each)

1. **`return_address`** — *lowest-hanging.* Zeek smtp.log **already carries `reply_to`**; a one-line `props: {return_address: "reply_to"}` in the `zeek_smtp` map fills it wherever an SMTP artefact exists. High signal (Reply-To/Return-Path mismatch = phishing tell).
2. **`server_relay`** — Zeek `path` is **already captured raw** in the map's `keep`; promote `path`/`first_received`/`second_received` to the canonical column. Full `Received:` chain comes from a mail-store parser.
3. **`smtp_uid`** — Zeek `msg_id` is available now as a proxy (flag the RFC-Message-ID ≠ queue-id caveat); the *true* server-local id needs an Exchange message-tracking / Postfix maillog / O365 parser. Identity-relevant (the CAR discriminator).
4. **`attachment_name` / `attachment_mime_type` / `attachment_size`** — Zeek files.log **already extracts** name/mime/bytes onto the `file` object; needs an **email↔file bridge over `fuids`** to copy them into `email.attachment_*` (malware-triage critical). Mail-store parsers supply them directly.
5. **`action_reason`** — needs a **mail-server/gateway security-log parser** (Exchange transport-rule/DLP, O365 Defender `EmailEvents`, Proofpoint/Mimecast, Postfix reject). No wire source can ever supply it; unlocks the `block/redirect/quarantine` actions too.
6. **`message_body` / `message_links` / `message_type`** — **content fields, impossible from Zeek** (STARTTLS-encrypted; body never logged). Require a **mail-store parser** — Plaso PST/OST (`pff`), `mbox`, or EML/MSG — or, for links specifically, O365 `EmailUrlInfo`/`UrlClickEvents`. Mail-client process memory is a last-resort heuristic source.

**Bottom line:** to make `email` produce *any* rows, the pipeline needs a real content-bearing artefact — a cleartext SMTP capture (feeds the existing `zeek_smtp` map) or, better for depth, a mail-store parser (PST/OST/mbox/EML) or mail-server log parser (Exchange/O365/Postfix). The latter class is the only path to the 4 unmapped actions and to the content/security fields (`action_reason`, `message_body`, `message_links`, `message_type`) that Zeek can never see.
