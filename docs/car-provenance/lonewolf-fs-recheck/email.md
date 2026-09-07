# CAR `email` — FILESYSTEM / disk provenance audit (unmined mail stores)

Deep-audit of the MITRE CAR `email` object against **on-disk mail artefacts** — the
class the pipeline has *never* touched. Companion to the network-focused
`docs/car-provenance/email.md` (LS24: only `zeek_smtp`, STARTTLS → empty).
Grounded in the real LoneWolf Win10 image and the engine's actual routing.
**READ-ONLY audit — no code changed.**

## Headline

**`email` yields nothing from disk today, and that is a whole-source gap, not an honest null.**
The only email mapper in the engine is `zeek_smtp` (network; STARTTLS → 0 rows).
**No mail-store parser is wired anywhere** — confirmed three ways:

- `piiat_mitrecar/mappings/` and `sources/*.yaml` contain **no** pff / PST / OST / mbox / EML / MSG / ESE-mail / HxStore adapter.
- `pipeline.py` `ROUTES` (the filename→map dispatch): the only email route is `("smtp.json", ["zeek_smtp"])`. `.L2tEsedb` routes **only** to `l2t_srum`; `.L2tOlecf` → `plaso_olecf` (→ `file`). No pff/mbox/HxStore/store.vol route exists.
- `mappings/core.py` docstring, verbatim: *"email: principles documented; no artefact feeds it yet … so no map — an empty table is honest."*

On the LoneWolf disk the mail genuinely lives in **two on-disk stores and the Gmail
webmail cache**, and plaso recorded all of them as **`fs:stat` only** (path + size +
MFT timestamps) — their *contents* are never parsed, so **0 of 21 `email` fields are
populated from disk**.

## Ground truth — LoneWolf `DESKTOP-PM6C56D.jsonl`

Source: `/opt/github/DX_DFIR/data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl`
(6.6 GB, 4,169,774 rows). User = **`jcloudy` (Jim Cloudy)**. Mail client = **Windows 10
Mail app** (`microsoft.windowscommunicationsapps` / `Comms.Apps.Messaging` / `Unistore.dll`),
**not** classic Outlook.

**Plaso data_type distribution — ZERO mail data_types.** `grep '"data_type": "(pff|msg|mbox|eml|outlook|thunderbird)'` → **no matches**. The emitted types are `fs:stat` (1.97 M), `windows:registry:*`, `windows:evtx:record`, `pe_coff:file`, `chrome:cache:entry` (21.6 k), `chrome:history:page_visited` (2.3 k), `chrome:cookie:entry` (8.9 k), `chrome:autofill:entry` (802), `msie:webcache:*`, `olecf:*`, etc. **Plaso never ran its `pff` (PST/OST), `mbox`, or `msg` parser** — because none of those file types is on the disk, and the stores that *are* present are formats plaso has no mail plugin for.

**On-disk mail stores actually present (recorded as `fs:stat`, contents UNPARSED):**

| artefact on disk | path (LoneWolf) | size | what it holds | plaso saw it as |
|---|---|---|---|---|
| **Win10 Mail ESE store** `store.vol` (Unistore) | `\Users\jcloudy\AppData\Local\Comms\UnistoreDB\store.vol` | 6,291,456 B | message/contact/calendar **metadata**: from/to/subject, submit/delivery times, read-state, folder | `fs:stat` (file existence + MAC times) |
| **HxStore** `HxStore.hxd` | `\Users\jcloudy\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\HxStore.hxd` | 4,194,304 B | full messages: **body + transport headers + attachments** (also present in a **VSS2 shadow copy** → historical state) | `fs:stat` only |
| **Gmail webmail cache** | Chrome `Cache` / `History` / `Autofill` / cookies | — | account address, message URLs, cached fragments/titles | `chrome:cache:entry` / `history` / `autofill` → routed to **`http`**, never `email` |

**Recoverable account identity (a real `src_address` sitting unused in the store):**
`jimcloudy1@gmail.com` (2,032 occurrences), `JimCloudy@outlook.com` / `jimcloudy@outlook.com` (20), plus webmail hosts `mail.google.com` (162), `outlook.office*` (33), `outlook.live.com` (24). These land in `chrome:autofill:entry` / URLs / cookies, which the engine ingests via `plaso_web.py` **into the `http` object** — the address is never promoted to `email.src_address`.

**Absent on this disk (checked, honestly negative):** no PST/OST files (the `Outlook.File.ost.15` / `.pst` hits are HKLM file-type *registrations*, not data files); no loose `.eml`/`.msg` under `\Users`; no Thunderbird profile / `global-messages-db.sqlite`; no `Content.Outlook` / INetCache attachment temp; no classic Outlook-profile registry key. The `.dbx` files present are **Dropbox** SQLite, not Outlook Express. `FPEXT.MSG` is a SharePoint/FrontPage stub, not mail.

## Per-field provenance — filesystem mail stores

Legend for "mail-store artefact → native field": **PST/OST** = Outlook personal store via libpff (`pff`); **store.vol** = Win10 Mail Unistore ESE; **HxStore** = `HxStore.hxd`; **.eml/.msg** = loose RFC5322 / MAPI message files; **mbox+Gloda** = Thunderbird mbox + `global-messages-db.sqlite`; **webmail** = browser cache/history/autofill; **reg}** = mail-account registry. `mined?` is **NO** for every row — **no mail parser is wired** (see Headline). Actions per MITRE: block, delete, deliver, quarantine, redirect.

| field | mail-store artefact → native field | action(s) | mined? | conf & caveats |
|---|---|---|---|---|
| **from** | PST/OST `PR_SENDER_NAME`/`PR_SENDER_EMAIL_ADDRESS`; store.vol sender col; HxStore From; .eml/.msg `From:`; mbox `From `; Gloda `messenger`/`identity` | deliver | **NO** (no mail parser) | High as a value; **forgeable** (MITRE says so). Display sender, never attribution. |
| **to** | PST/OST `PR_DISPLAY_TO`; store.vol recipient row; HxStore To; .eml `To:`; mbox; Gloda | deliver | **NO** | High. Header To — a **display list, ≠ real recipients**; CC/BCC not represented here either. |
| **dest_address** | PST/OST recipient table (`PR_SMTP_ADDRESS`/`PR_RECEIVED_BY_*`); store.vol recipient EntryIDs; HxStore; .eml `To`/`Delivered-To` | deliver | **NO** | Med-High. A client store keeps **header/MAPI** recipients, not the SMTP-envelope RCPT — so this is "resolved recipient", not envelope-authoritative (that authority is only on the wire/server). |
| **src_address** | PST/OST `PR_SENDER_SMTP_ADDRESS`/`PR_SENT_REPRESENTING_SMTP_ADDRESS`; store.vol; HxStore; .eml `From`/`Sender`; mbox; Gloda; **webmail account** (`jimcloudy1@gmail.com`) from browser autofill/cache/cookies; reg} Mail-app / Outlook-profile SMTP address | deliver | **NO** | High. **Strongest value ALREADY on this disk** — the signed-in webmail account. For a received message the "sender" is the correspondent; for the account owner it's the webmail/profile address. |
| **src_domain** | `domain_of(src_address)` from any of the above | deliver | **NO** | High — mechanical derivation; inherits `src_address` forgeability. |
| **subject** | PST/OST `PR_SUBJECT`/`PR_NORMALIZED_SUBJECT`; store.vol subject col; HxStore; .eml `Subject`; mbox; Gloda `subject`; webmail cached page **titles** | deliver | **NO** | High. Cleartext on disk (unlike STARTTLS on the wire). |
| **date** | PST/OST `PR_CLIENT_SUBMIT_TIME` / `PR_MESSAGE_DELIVERY_TIME`; store.vol submit/delivery timestamps; HxStore; .eml `Date:`; mbox `Date`; Gloda `date` | deliver | **NO** | High as a header/MAPI value. Client `Date:` is **forgeable** and ≠ the store's own MAC timestamp; distinguish submit vs delivery time. |
| **message_body** | PST/OST `PR_BODY`/`PR_HTML`/`PR_RTF_COMPRESSED`; **HxStore.hxd body**; .eml body part; mbox; Gloda indexed body text; webmail cached message fragments | deliver | **NO** | High — **THE reason a disk source matters**: Zeek can't see the body under STARTTLS; a mail store holds it in cleartext. On this disk it is inside `store.vol`/`HxStore.hxd`. |
| **message_links** | Derived from body (all body sources above); **webmail message URLs** in `chrome:history`/`cache` | deliver | **NO** | Med. Derive after a body exists, or lift from the browser URL rows the engine already parses. |
| **message_type** | Body part `Content-Type` — PST/OST `PR_MSG_EDITOR_FORMAT` (html/plain/rtf); .eml part `Content-Type`; mbox; Gloda | deliver | **NO** | Med. Projects to ECS `email.content_type`. |
| **return_address** | PST/OST `PR_REPLY_RECIPIENT_ENTRIES` / `Reply-To` transport header; .eml `Reply-To:` / `Return-Path:`; mbox `Return-Path` | deliver | **NO** | Med. Phishing tell — Reply-To/Return-Path ≠ From is signal, not identity. |
| **server_relay** | **`Received:` chain** stored verbatim: PST/OST `PR_TRANSPORT_MESSAGE_HEADERS`; HxStore transport headers; **.eml raw headers**; mbox headers | deliver | **NO** | Med-High. **KEY insight: a stored message recovers a wire/server artefact the client-STARTTLS network view never gives.** The full relay chain (each hop IP+host+time) is in the message's own transport headers. |
| **attachment_name** | PST/OST `PR_ATTACH_LONG_FILENAME`/`PR_ATTACH_FILENAME`; HxStore attachment; .eml `Content-Disposition` filename; .msg `__attach_*` stream; **extracted attachment temp files** (`Content.Outlook`/INetCache) visible as `fs:stat` | deliver | **NO** | Med-High. Temp-extracted attachments are already `fs:stat`-visible (name) even with no mail parser → an attachment↔file bridge could seed this. |
| **attachment_size** | PST/OST `PR_ATTACH_SIZE`; HxStore; .eml part length; mbox; extracted temp file `fs:stat.file_size` | deliver | **NO** | Med. ECS `email.attachments.file.size` wants bytes; MAPI gives bytes directly. |
| **attachment_mime_type** | PST/OST `PR_ATTACH_MIME_TAG`; HxStore attachment part `Content-Type`; .eml/.msg part `Content-Type`; mbox | deliver | **NO** | Med. This is the **declared** MIME (per MITRE) — less trustworthy than libmagic; a stored message only has the declared value. |
| **smtp_uid** | PST/OST `PR_INTERNET_MESSAGE_ID` / `PR_SEARCH_KEY`; .eml `Message-ID:`; mbox `Message-ID` | deliver | **NO** | Low-fit. A client store has the **RFC Message-ID (a proxy)**, not the server-local queue/transaction id CAR actually means. True `smtp_uid` needs a mail-SERVER log. |
| **src_ip** | Only via the stored `Received:` chain (first hop) or an `X-Originating-IP` header — same header sources as `server_relay` | deliver | **NO** | Med **only through header parse**; otherwise a **wire artefact absent from a client store**. |
| **dest_ip** | Only via the last `Received:` hop in the stored header chain | deliver | **NO** | Low. Same caveat — recoverable only from the transport-header chain, else **honest null from disk**. |
| **src_port** | — (pure wire 5-tuple; never stored in a mail file) | — | **NO** | **Honest null from any disk mail store.** |
| **dest_port** | — (wire 5-tuple; a client "port" would be the IMAP/993 pull port, not the SMTP delivery port CAR means) | — | **NO** | **Honest null from disk** for CAR's meaning. |
| **action_reason** | At most a **Junk-folder placement** flag (store.vol folder id / HxStore spam flag); the *reason string* is a mail-SERVER/gateway verdict (Exchange DLP, O365/Defender `ThreatTypes`, Proofpoint/Mimecast) — **not on a client disk** | quarantine/block | **NO** | Low. A client store shows *that* a message was junked, never *why*. **Honest near-null from disk.** |

### Actions from a disk store

- **deliver** — every received message *in* the store IS a delivered message; the store's contents attest `deliver`. Fully derivable once any store is parsed.
- **delete** — Deleted Items folder / store soft-delete flag (store.vol/PST), mbox `X-Mozilla-Status` deleted bit, webmail Trash label, Recycle Bin / USN-journal entry for a message file. Recoverable from folder/flag + the USN we already ingest.
- **block / redirect / quarantine** — mail-**server / gateway** security verdicts. A client disk store gives at most a weak Junk-folder proxy for *quarantine*; `block`/`redirect` leave **no client-disk trace**. These + `action_reason` are the by-design no-source set for disk (they need Exchange/O365/gateway logs).

## Ranked UNMINED opportunities (filesystem)

1. **`store.vol` (Win10 Mail Unistore/ESE) + `HxStore.hxd` — PRESENT ON THIS EXACT EVIDENCE, 6 MB + 4 MB, plus a VSS2 shadow copy.** Currently `fs:stat` only. A Unistore/ESE mail plugin (metadata: from/to/subject/date/read-state/folder) + an HxStore parser (body/headers/attachments) would take `email` from **0 rows to a populated table on the flagship disk image**. Highest value because it is the real mail on the real evidence. *Caveat:* `HxStore.hxd` is a proprietary/undocumented format (hard; may need dedicated tooling); `store.vol` is ESE — plaso can open ESE but ships **no mail-aware plugin** for Unistore today, so a new plugin/adapter is required either way.
2. **Outlook PST/OST via the `pff` parser (libpff).** The canonical, best-documented mail-store path — fills *every* content field plus the **full `Received:` chain** (transport headers → `server_relay`, and `src_ip`/`dest_ip` via the hops). Not on this disk, but the primary parser to wire for the general case; once a plaso run emits `pff:*` data_types, a routing entry + map is low-cost. This is the single biggest coverage lever across hosts.
3. **Webmail account → `email.src_address` (already-ingested data).** `jimcloudy1@gmail.com` is sitting in `chrome:autofill:entry` / cookies / URLs that the engine **already parses** (`plaso_web.py`) — but routes to `http`. An email-account extractor over those rows (or the Mail-app/Outlook-profile registry) is the **cheapest possible win** to make `email.src_address`/`src_domain` non-empty. Signed-in identity, not forgeable header.
4. **`Received:`-header chain → `server_relay` (+ `src_ip`/`dest_ip`/`date`).** From **any** stored message (PST `PR_TRANSPORT_MESSAGE_HEADERS`, `.eml` raw headers, HxStore). The forensic point: **a disk store recovers server/wire artefacts (the relay chain) that the STARTTLS-encrypted network capture can never yield.**
5. **Loose `.eml` / `.msg` + extracted attachment temp.** `.msg` is an OLE compound file — plaso's `olecf` plugin *sees* it but only emits `summary_info → file`, never the MAPI mail fields; needs a real MSG/EML mail parser. Attachment temp files (`Content.Outlook`/INetCache) are already `fs:stat`-visible (name/size) → an **attachment↔file bridge** could seed `attachment_name`/`attachment_size` even before a full parser. (None present on *this* disk, but a standard artefact class.)
6. **Thunderbird mbox + `global-messages-db.sqlite` (Gloda).** mbox = raw RFC5322 (all header + body fields); Gloda = a full-text index (from/to/subject/body/date). Standard parser to add for cross-platform coverage. (Not present on this disk.)

## Honest no-sources from a client disk store

- **`src_port` / `dest_port`** — pure wire 5-tuple; never written to a mail file. Honest null.
- **`dest_ip` (and `src_ip` beyond the first Received hop)** — wire artefacts; recoverable *only* by parsing the stored `Received:` chain, otherwise null.
- **`action_reason` + the `block` / `redirect` / `quarantine` verdicts** — mail-SERVER/gateway security decisions (Exchange transport-rule/DLP, O365/Defender, Proofpoint/Mimecast). A client disk store records at most Junk-folder placement, never the reason. These need a server/gateway security-log parser, which no disk artefact can substitute for.
- **`smtp_uid` (server queue/transaction id)** — a client store has only the RFC `Message-ID` (a semantic-mismatch proxy). The true value is a mail-server log field.

## Bottom line

Email is a **whole-source gap on disk**: the pipeline ingests the LoneWolf image down to
1.97 M `fs:stat` rows and full browser cache/history, yet routes **none** of it to `email`
— no mail-store parser exists. The mail that is demonstrably present — `store.vol` (6 MB) +
`HxStore.hxd` (4 MB, with a shadow copy) and the Gmail webmail account `jimcloudy1@gmail.com`
— is recorded only as file metadata and web history. Wiring **(a)** a Unistore/ESE +
HxStore reader for this Win10-Mail evidence, **(b)** the `pff` PST/OST parser for the general
case, and **(c)** a trivial webmail-account extractor over already-parsed browser rows would
move `email` from a structurally-empty table to a populated one, and — via stored
`Received:` chains — even recover the relay/IP fields the STARTTLS network capture never could.
