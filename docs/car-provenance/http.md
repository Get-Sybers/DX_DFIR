# Property-Provenance Catalogue — MITRE CAR `http`

**Scope.** Every canonical field of the CAR `http` object, and every artefact/source in this
repo (and its realistic universe) that can supply it. Grounded in the CAR data model, the
DX_DFIR engine maps (`piiat_mitrecar.mappings`), the generated `sources/*.yaml`, the repo's
`docs/CAR-Relations.md`, OSSEM-CDM, and the actual processed evidence store. READ-ONLY analysis.

- Object semantics: `third_party/piiat-mitrecar/third_party/car/data_model/http.yaml`, `.../docs/data_model/http.md`, `car_data_model.json` (lines 173-201).
- OSSEM-CDM richer semantics: `third_party/piiat-mitrecar/third_party/car/OSSEM-CDM/schemas/entities/http.yml`.
- Engine maps (source of truth): `piiat_mitrecar/mappings/core.py` (zeek_http), `.../evtx_extra.py` (BITS), `.../plaso_web.py` (browser/cache/java), `.../_common.py`, `.../normalize.py`.
- Generated per-source coverage: `sources/{zeek_http,evtx_bits,l2t_msiecf,l2t_firefox_cache,l2t_firefox_places,l2t_javaidx}.yaml`.
- Design rationale/limits: `docs/CAR-Relations.md` §"http (← Zeek http.log)" (lines 57-87).
- Ground-truth records: `data_store/processed/zeek/DFIRdump_FOR_200_capture_pcap/http.json`.

**Actions:** `get`, `post`, `put`, `tunnel` (CONNECT). MITRE's action set is deliberately
incomplete — HEAD/OPTIONS/DELETE/PATCH/etc. have no canonical CAR action and stay raw
(`core.py` `default: None`; `CAR-Relations.md` line 85-87).

---

## 0. Canonical fields + MITRE definition caveats (READ THIS FIRST)

The upstream MITRE `http` data model carries three copy-paste defects that the repo has
already diagnosed. They matter because they corrupt the field *semantics*, not just docs:

| Field | MITRE's literal text | Reality (implement this) |
|---|---|---|
| `url_scheme` | "type of user that initiated the request." | **Copy-paste error.** Implement the field *name*: the URL scheme (`http`/`https`). Confirmed in `docs/CAR-Relations.md` line 77-78 and the map comment in `plaso_web.py`. |
| `user_agent_full` | example `HOST1\LOCALUSER1` | Example is a pasted *user* value, not a UA string. The field is the **full User-Agent header string**. |
| `user_agent_name` | example is the *entire* UA string `Mozilla/5.0 (...) Chrome/58...` | Example is swapped with `user_agent_full`. `user_agent_name` is meant to be the **parsed product name** (e.g. `Chrome`), `user_agent_version` the parsed version (`58.0.3029.83`), `user_agent_device` the parsed device (`SM-G930VC`). Splitting one UA string into name/version/device is a **heuristic parse** — see §3. |

The 17 canonical fields: `hostname`, `http_version`, `request_body_bytes`,
`request_body_content`, `request_referrer`, `requester_ip_address`, `response_body_bytes`,
`response_body_content`, `response_status_code`, `url_domain`, `url_full`, `url_remainder`,
`url_scheme`, `user_agent_device`, `user_agent_full`, `user_agent_name`, `user_agent_version`.

**Provenance-quality legend** (as used by the engine's generated `field_provenance`):
`[direct]` = 1:1 copy of a native field · `[derived]` = deterministic transform of one native
field (regex/label/host extraction) · `[coalesced]` = first-non-empty of alternatives ·
`[inferred]` = regex-parsed out of a compound field (url) · `[asserted]` = a constant the
observation itself proves (e.g. scheme `http` for a cleartext zeek transaction) ·
`[heuristic]` = a best-effort guess with real error rate (no source does this today).

---

## 1. Source universe

### 1a. Currently mapped (wired in the engine + regenerated `sources/*.yaml`)

| Map key | Tool / parser | Native log | Object/actions | Vantage of `hostname` |
|---|---|---|---|---|
| `zeek_http` (`core.py`) | Zeek | `http.log` (`http.json`) | http **get/post/put** (origin-form), **tunnel** (CONNECT) | *not mapped* — pcap has no endpoint identity; vantage carried by `source_host` |
| `evtx_bits` (`evtx_extra.py`) | EvtxECmd / Plaso winevt | Microsoft-Windows-Bits-Client/Operational **59/60** | http **get** | `Computer` (the endpoint that issued the transfer) |
| `l2t_msiecf` (`plaso_web.py`) | Plaso | `msiecf` (IE `index.dat`) | http **get** | `image_hostname` (imaged endpoint) |
| `l2t_firefox_cache` (`plaso_web.py`) | Plaso | `firefox_cache` | http **get/post/put** (from recorded method) | `image_hostname` |
| `l2t_firefox_places` (`plaso_web.py`) | Plaso | `sqlite/firefox_history` (`places.sqlite`) | http **get** | `image_hostname` |
| `l2t_javaidx` (`plaso_web.py`) | Plaso | `java_idx` (Java IDX download cache) | http **get** | `image_hostname` |

Routing confirmed in `pipeline.py` (`http.json`→zeek_http; `.L2tMsiecf`/`.L2tFirefoxCache`/
`.L2tSqlite`/`.L2tJavaIdx`→plaso web; `evtx_bits` in the EvtxECmd fan-out).

### 1b. Realistic sources that exist in the domain but are NOT mapped here

| Source | Where it lives | What it could supply | Status |
|---|---|---|---|
| **Suricata http EVE** (`eve.json` `event_type:http`) | `data_store/processed/signatures/suricata/` (dir present, **empty** in current evidence) | url/host/UA/method/status/referrer/body-lengths — near-Zeek parity, plus `http.request_headers`/`response_headers` | **UNMAPPED** (no map, no records) |
| **Proxy access logs** (Squid `access.log`, BlueCoat/ProxySG, Zscaler) | not in store | full URL, method, status, bytes, UA, referrer, client IP, **decrypted HTTPS** | **UNMAPPED** |
| **IIS / Apache / NGINX W3C access logs** | not in store | server-side: url_remainder, method, status, bytes, UA, referrer, client IP (`c-ip`), `cs-host` | **UNMAPPED** (OSSEM-CDM http schema explicitly names IIS/Apache/NGINX as http sources) |
| **WinINET/WinHTTP** (`WebCacheV01.dat` ESE, Sysmon/ETW) | not in store | url, host, downloaded bytes | **UNMAPPED** |
| **Chrome/Edge/Safari history & cache** (Plaso `chrome:history:page_visited`, `safari:history:visit`, `chrome_cache`) | possible under `.L2tSqlite` | url, referrer (chrome `from_visit`), visit metadata | **UNMAPPED** — `.L2tSqlite` routes only to `l2t_firefox_places`, whose predicate gates strictly on `data_type == "firefox:places:page_visited"`; Chrome/Safari rows fall through to raw |
| **Defender SmartScreen / DNS-Client (1014)** | not in store | requested url / queried host | **UNMAPPED** (SmartScreen carries url; DNS-Client only a hostname, weak fit) |
| **Browser process memory** (`memory.yaml` sensor) | `data_store/processed/volatility/` | url strings recovered from a browser process | **UNMAPPED for http** (memory sensor emits its own CAR pass-through, not via these maps) |
| **UA-string parser** (`ua_parser`/`woothee`/`user-agents`) | *nowhere in repo* | `user_agent_name` / `_version` / `_device` from `user_agent_full` | **UNMAPPED** — confirmed no UA-split code anywhere (`grep` for `user_agent_name/version/device` returns only the CAR schema + this catalogue). Would be `[heuristic]`. |

---

## 2. Per-field provenance (the catalogue)

Format: `source → native field [quality]`. "Currently mapped?" cites the exact map/source file.
Actions listed are those the mapping actually emits.

### `hostname` — host on which the request was *seen* (the vantage)

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | *(none)* | — | **NO — deliberate** (`core.py` L19-23, L110-113) | pcap carries no endpoint identity; the vantage is the sensor's `source_host`, not a client-forgeable Host header. Mapping it would fake host attribution. |
| evtx_bits | `Computer` → `host_label(Computer)` [derived] | get | **yes** — `evtx_extra.py` L63, `sources/evtx_bits.yaml` L39 | High. The endpoint that issued the BITS transfer *is* the http vantage. |
| l2t_msiecf | `image_hostname` [direct] | get | **yes** — `plaso_web.py` L91 | High. Imaged endpoint = the vantage the artefact was seen on. |
| l2t_firefox_cache | `image_hostname` [direct] | get/post/put | **yes** | High. |
| l2t_firefox_places | `image_hostname` [direct] | get | **yes** | High. |
| l2t_javaidx | `image_hostname` [direct] | get | **yes** | High. |
| Proxy/IIS/Suricata | proxy host / `s-computername` / sensor host | — | **NO** | Would be direct if mapped. |

### `http_version`

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `version` [direct] | get/post/put/tunnel | **yes** — `core.py` L116, `sources/zeek_http.yaml` L38 | High/direct. |
| Suricata http EVE | `http.protocol` (e.g. `HTTP/1.1`) | — | **NO** | Direct if mapped (needs `HTTP/`-strip). |
| Proxy/IIS | `cs-version` (IIS) | — | **NO** | Server-side, direct. |
| evtx_bits / all Plaso browser | — | — | **NO** | Not recorded by BITS or browser-history artefacts. Honest no-source. |

### `request_body_bytes`

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `request_body_len` [direct] | get/post/put/tunnel | **yes** — `core.py` L118 | High/direct. (For tunnel this is bytes of the CONNECT request, ~0.) |
| Suricata http EVE | `http.request_body_len` (if body-logging on) | — | **NO** | Direct if mapped. |
| Proxy | `cs-bytes` | — | **NO** | Direct. |
| evtx_bits / Plaso browser | — | — | **NO** | Not recorded. Honest no-source. |

### `request_body_content` — body of the HTTP request

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| **any source** | — | — | **NO — no source anywhere** | Zeek `http.log` records only body *length*, not content. Body *content* would come from Zeek file-extraction (`orig_fuids` → files.log → extracted file on disk) or a full-packet/proxy capture with body logging. `core.py` keeps `orig_fuids`/`orig_mime_types` in `keep` (join keys to `zeek_files`→`file`) but never asserts `request_body_content`. **Genuine gap; honest null.** |

### `request_referrer` — the referring URL (client-supplied, forgeable)

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `referrer` [direct] | get/post/put/tunnel | **yes** — `core.py` L122 | Direct, but **client-supplied** — never proof of real navigation (`CAR-Relations.md` L83-84). Note: rare in evidence — only 1 `referrer` field present across all captured `http.json` rows. |
| l2t_firefox_places | `from_visit` → `first(regex1(from_visit, ^\S+), from_visit)` [coalesced] | get | **yes** — `plaso_web.py` L142-144 | Medium. Firefox's recorded referring page ("url (host)" suffix stripped). Client-side recorded data, not navigation provenance. |
| Suricata http EVE | `http.http_refer` [direct] | — | **NO** | Direct if mapped. |
| Proxy/IIS | `cs(Referer)` | — | **NO** | Direct. |
| Chrome/Safari history | chrome `from_visit` / safari referrer | — | **NO** | Would be `[coalesced]`; blocked by the firefox-only `.L2tSqlite` predicate. |
| evtx_bits, l2t_msiecf, l2t_firefox_cache, l2t_javaidx | — | — | **NO** | Not recorded by those artefacts. Honest no-source. |

### `requester_ip_address` — IP the request was made from

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `id.orig_h` [direct] | get/post/put/tunnel | **yes** — `core.py` L119 | High/direct (connection-truth origin). |
| Suricata http EVE | `src_ip` [direct] | — | **NO** | Direct. |
| Proxy/IIS | `c-ip` / `cs(X-Forwarded-For)` | — | **NO** | Direct (`c-ip`); XFF is client-forgeable. |
| l2t_javaidx | *(only the server `ip_address` is recorded — kept native, NOT requester)* | get | **NO — deliberate** | The IDX cache records the *server* IP, not the requester; `plaso_web.py` L166 keeps it in `native_extract`, honestly not as `requester_ip_address`. |
| evtx_bits, other Plaso | — | — | **NO** | Endpoint-side artefacts don't record their own source IP here. Honest no-source. |

### `response_body_bytes`

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `response_body_len` [direct] | get/post/put/tunnel | **yes** — `core.py` L120 | High/direct. |
| evtx_bits | `bytesTransferred` [direct] | get | **yes** — `evtx_extra.py` L61, `sources/evtx_bits.yaml` L42 | Medium-High. Bytes *transferred* by the BITS job (0 at 'started', final at 'stopped'). Maps to *response* body (a download) — reasonable but note it is transfer-total, not strictly HTTP response-body length. |
| Suricata http EVE | `http.length` / `http.response_body_len` | — | **NO** | Direct if mapped. |
| Proxy/IIS | `sc-bytes` | — | **NO** | Direct. |
| Plaso browser (msiecf/ffcache/places/java) | `data_size`/`data_size` kept native, not asserted | — | **NO** | Cache `data_size` is cached-object size, not wire response bytes — correctly left native (`plaso_web.py` `native_extract`). |

### `response_body_content` — content of the response (no header)

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| **any source** | — | — | **NO — no source anywhere** | Like request body: Zeek records only length; actual content needs file-extraction (`resp_fuids`→files.log→extracted file) or full-packet/proxy body logging. `resp_fuids`/`resp_mime_types` are kept as join keys to `file`, never asserted as content. Firefox/IE cache *do* hold cached response bodies on disk, but the Plaso plugins used emit metadata rows only (size/count), not the object bytes. **Genuine gap; honest null.** |

### `response_status_code`

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `status_code` [direct] | get/post/put/tunnel | **yes** — `core.py` L121 | High/direct. Null `status_code` = **no response captured** → asserts no outcome (`CAR-Relations.md` L82), never a fake 0. |
| l2t_firefox_cache | `response_code` → `hex_int(regex1(response_code, "\s(\d{3})\s"))` [derived] | get/post/put | **yes** — `plaso_web.py` L122-123 | Medium. Parsed out of the cached status line `HTTP/1.1 200 OK`. Deterministic parse. |
| Suricata http EVE | `http.status` [direct] | — | **NO** | Direct. |
| Proxy/IIS | `sc-status` | — | **NO** | Direct. |
| evtx_bits, l2t_msiecf, l2t_firefox_places, l2t_javaidx | — | — | **NO** | Not recorded by those artefacts. Honest no-source. |

### `url_domain` — domain portion of the URL (the Host)

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `domain_of(host)` [derived] | get/post/put/tunnel | **yes** — `core.py` L114 | High. This is the client-sent **Host header** (lowercased) — client-forgeable (domain fronting); connection-truth destination is `id.resp_h`, kept native (`CAR-Relations.md` L74-76). |
| evtx_bits | `regex1(url, ^https?://([^/?#]+))` [inferred] | get | **yes** — `evtx_extra.py` L57 | Medium. Parsed from the full BITS url. |
| l2t_msiecf | `regex1(url, ^https?://([^/?#:]+))` [inferred] | get | **yes** — `plaso_web.py` `_http_props` | Medium. Null for non-URL targets (`about:Home`) — honest. |
| l2t_firefox_cache | same regex [inferred] | get/post/put | **yes** | Medium (after `HTTP:` prefix strip). |
| l2t_firefox_places | same regex [inferred] | get | **yes** | Medium. |
| l2t_javaidx | same regex [inferred] | get | **yes** | Medium. |
| Suricata/Proxy/IIS | `http.hostname` / `cs-host` [direct] | — | **NO** | Direct. |

### `url_full` — the full URL requested

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `concat("http://", host, uri)` [derived] | get/post/put **(NOT tunnel)** | **yes** — `core.py` L204 | Medium. **Reconstructed** from request-line + Host header, only origin-form. Null if any part missing. **NOT** emitted for tunnel (CONNECT target is authority-form, no URL). Scheme forced `http` — see caveat under `url_scheme`. |
| evtx_bits | `url` [direct] | get | **yes** — `evtx_extra.py` L55 | High/direct (BITS records the full remote url). |
| l2t_msiecf | `_IE_URL` = `first(regex1(url, ^Visited:\s*[^@]*@(.+)$), url)` [coalesced] | get | **yes** — `plaso_web.py` L75, L84 | Medium. IE history renders `Visited: user@<url>`; the real URL is extracted. |
| l2t_firefox_cache | `_FFC_URL` = `first(regex1(url, ^HTTP:(.+)$), url)` [coalesced] | get/post/put | **yes** — `plaso_web.py` L77 | Medium (strips cache `HTTP:` prefix). |
| l2t_firefox_places | `url` [direct] | get | **yes** | High/direct. |
| l2t_javaidx | `url` [direct] | get | **yes** | High/direct. |
| Suricata/Proxy/IIS | assembled `scheme://host + uri` / `cs-uri` | — | **NO** | Would be `[derived]`. |

### `url_remainder` — path after the root domain

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `uri` [direct] | get/post/put/tunnel | **yes** — `core.py` L115 | High/direct (the request-target path+query). |
| evtx_bits | `regex1(url, ^https?://[^/]+(/[^\s]*))` [inferred] | get | **yes** — `evtx_extra.py` L59 | Medium. |
| l2t_msiecf | same regex [inferred] | get | **yes** | Medium. |
| l2t_firefox_cache | same regex [inferred] | get/post/put | **yes** | Medium. |
| l2t_firefox_places | same regex [inferred] | get | **yes** | Medium. |
| l2t_javaidx | same regex [inferred] | get | **yes** | Medium. |
| Suricata/Proxy/IIS | `http.url` / `cs-uri-stem`+`cs-uri-query` [direct] | — | **NO** | Direct. |

### `url_scheme` — URL scheme (**NOT** "type of user" — see §0)

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `const("http")` [asserted] | get/post/put **(NOT tunnel)** | **yes** — `core.py` L203; `sources/zeek_http.yaml` L47 `[asserted]` | Medium. Zeek `http.log` sees **cleartext** HTTP only, so scheme is provably `http`; HTTPS payloads never appear here (they surface as `tunnel`/TLS). Not emitted for tunnel. |
| evtx_bits | `regex1(url, ^(https?))` [inferred] | get | **yes** — `evtx_extra.py` L58 | Medium (real https/http preserved from the BITS url). |
| l2t_msiecf / firefox_cache / firefox_places / javaidx | `regex1(url, ^(https?)://)` [inferred] | get(/post/put) | **yes** — `plaso_web.py` `_http_props` | Medium. Null for non-http targets — honest. |
| Suricata/Proxy/IIS | derived from url / `cs-uri-scheme` | — | **NO** | Direct/derived. |

### `user_agent_full` — the complete User-Agent header string

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| Zeek http | `user_agent` [direct] | get/post/put/tunnel | **yes** — `core.py` L122, `sources/zeek_http.yaml` L48 | Direct, but **client-supplied** — never proof of real client software (`CAR-Relations.md` L83-84). (Evidence sample: `masscan/1.0 (...)`.) |
| Suricata http EVE | `http.http_user_agent` [direct] | — | **NO** | Direct. |
| Proxy/IIS | `cs(User-Agent)` [direct] | — | **NO** | Direct. |
| evtx_bits, all Plaso browser | — | — | **NO** | BITS/history/cache artefacts don't retain the UA header. Honest no-source. |

### `user_agent_name` / `user_agent_version` / `user_agent_device` — parsed UA components

| Source | native → field | action(s) | Mapped? | Confidence & caveats |
|---|---|---|---|---|
| **(derived from `user_agent_full`)** | UA-string parse → name/version/device | — | **NO — no source anywhere** | **Genuine, highest-value gap.** No UA-parsing code exists in the repo (`grep` for these three field names hits only the CAR schema). Splitting one UA string into product name / version / device is a **`[heuristic]`** parse (regex or a `ua_parser`/`woothee` library) with a real error rate, especially for spoofed/embedded/webview UAs — hence honestly unmapped rather than faked. `user_agent_full` is available (from Zeek) to feed such a parser. |

---

## 3. Coverage matrix (source × field)

`Y`=mapped · `d`=deliberately not mapped (principled null) · `·`=no source in that artefact ·
`N*`=no source anywhere (see notes).

| field | zeek_http | evtx_bits | l2t_msiecf | l2t_ff_cache | l2t_ff_places | l2t_javaidx |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| hostname | d | Y | Y | Y | Y | Y |
| http_version | Y | · | · | · | · | · |
| request_body_bytes | Y | · | · | · | · | · |
| request_body_content | N* | · | · | · | · | · |
| request_referrer | Y | · | · | · | Y | · |
| requester_ip_address | Y | · | · | · | · | d |
| response_body_bytes | Y | Y | · | · | · | · |
| response_body_content | N* | · | · | · | · | · |
| response_status_code | Y | · | · | Y | · | · |
| url_domain | Y | Y | Y | Y | Y | Y |
| url_full | Y¹ | Y | Y | Y | Y | Y |
| url_remainder | Y | Y | Y | Y | Y | Y |
| url_scheme | Y¹ | Y | Y | Y | Y | Y |
| user_agent_full | Y | · | · | · | · | · |
| user_agent_name | N* | · | · | · | · | · |
| user_agent_version | N* | · | · | · | · | · |
| user_agent_device | N* | · | · | · | · | · |

¹ `url_full`/`url_scheme` for zeek are emitted on **get/post/put only**, never `tunnel` (CONNECT).

**Field mapped by ≥1 source:** 13 / 17.
**Fields with NO source anywhere (N\*):** `request_body_content`, `response_body_content`,
`user_agent_name`, `user_agent_version`, `user_agent_device` — 4 distinct field-classes (bodies ×2, UA-parse ×3).
**Principled deliberate nulls (`d`):** zeek `hostname` (pcap vantage), javaidx `requester_ip_address` (server IP only).

---

## 4. Analytics consumers

**None.** No shipped CAR analytic references the `http` object or any of its fields
(`grep` across all 102 analytics in `third_party/car/analytics/` for `object: http`,
`url_full`, `url_domain`, `user_agent*`, `response_status_code`, `request_referrer`,
`requester_ip_address`, `url_scheme`, `http_version` → 0 hits; the only "http" strings are
`http(s)://` URLs in prose). The `http` object is a data-model / provenance surface here,
not an analytic input — so provenance quality is the whole value.

---

## 5. Summary — coverage and ranked gaps

**Coverage.** 13/17 canonical fields have at least one wired source. Zeek `http.log` is the
spine (14 of 17 fields, all four actions, the only source for `http_version`,
`request_body_bytes`, `request_referrer`, `requester_ip_address`, `user_agent_full`).
Endpoint artefacts (BITS + 4 Plaso browser/cache/java maps) add the `hostname` vantage and
independent url/status evidence but are all url-centric. Byte counts, status, referrer, and
UA come almost exclusively from Zeek. The maps are honest: deliberate nulls (zeek `hostname`,
javaidx server-IP) and principled `default: None` (HEAD/OPTIONS, encrypted tunnels) are
documented, not faked.

**UNMAPPED gaps, ranked by value:**

1. **UA parsing → `user_agent_name` / `user_agent_version` / `user_agent_device` (3 fields, 0 sources).**
   Highest value: `user_agent_full` is already captured, the split is pure post-processing, and
   these three fields are otherwise permanently empty. Needs a `[heuristic]` UA parser
   (`ua_parser`/`woothee`) with the honest caveat that spoofed/webview UAs mislead it. Cheapest
   win, biggest field-count uplift.

2. **Proxy / IIS-Apache-NGINX access logs (0 sources today).** OSSEM-CDM explicitly lists these
   as first-class http sources. They deliver server-side `url_remainder`, `response_status_code`,
   bytes, referrer, UA, and `requester_ip_address` (`c-ip`) — and, uniquely, **decrypted HTTPS**
   that Zeek cannot see (Zeek only logs cleartext, forcing `url_scheme=http`). Directly closes the
   Zeek blind spot for TLS traffic.

3. **Suricata http EVE (`event_type:http`).** Directory scaffolded (`signatures/suricata/`) but
   empty; a map would give near-Zeek parity from an already-run sensor — low effort, and adds a
   second independent network vantage (status, referrer, UA, method, url).

4. **Browser-history depth beyond Firefox.** `.L2tSqlite` routes only to `l2t_firefox_places`,
   gated to `firefox:places:page_visited`. **Chrome/Edge/Safari** page-visit + download rows
   (which Plaso already parses) fall through to raw — a same-shape extension would add
   `url_full`/`url_domain`/`request_referrer`/`hostname` for the dominant browsers.

5. **Request/response body *content* (2 fields, 0 sources).** Genuinely hard: Zeek gives only
   lengths; content needs Zeek file-extraction (join via `orig_fuids`/`resp_fuids`→`file`) or
   full-packet/proxy body logging. The join keys are already kept native, so the plumbing exists
   — but asserting the content fields requires an extraction pipeline that isn't wired. Lowest
   priority; often infeasible for HTTPS anyway.

**Data-model hygiene note (not a source gap).** `url_scheme`, `user_agent_full`, and
`user_agent_name` carry upstream MITRE copy-paste defects (§0). The repo already implements the
*intended* semantics; any downstream doc/UI should render field *names*, not MITRE's pasted
descriptions/examples, for these three.
