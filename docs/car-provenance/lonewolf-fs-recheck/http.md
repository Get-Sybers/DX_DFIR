# CAR `http` — FILESYSTEM/DISK provenance audit (unmined web-history universe)

**Scope.** Every canonical field of CAR `http`, versus the **on-disk browser + download
artefacts** that could fill it — the filesystem web-history universe (Chrome/Edge History &
Cache & Downloads SQLite, IE/legacy WebCacheV01.dat ESE, Java IDX, registry TypedURLs, ADS
Zone.Identifier). READ-ONLY. This pass is the FS-artefact complement to the committed
`docs/car-provenance/http.md` (which is Zeek/BITS/network-centric); it grounds the "browser
depth beyond Firefox" gap (that doc's ranked item #4) in the **real LoneWolf Win10 image**.

- **Real evidence:** `data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl`
  (LoneWolf `LoneWolf.E01` via Plaso, 6.6 GB). Every count below is a full-file tally.
- **Engine http maps:** `third_party/piiat-mitrecar/piiat_mitrecar/mappings/plaso_web.py`
  (msiecf / firefox_cache / firefox_places / javaidx), `core.py` (zeek), `evtx_extra.py` (BITS).
- **Routing:** `pipeline.py` `ROUTES` (L49-96) + `adapters/l2t_split.py` `table_name()`.

## 0. The decisive finding: LoneWolf is a Chrome/Edge box, and 100% of its web history is UNMINED

The four Plaso http maps that DO exist (`l2t_msiecf`, `l2t_firefox_cache`, `l2t_firefox_places`,
`l2t_javaidx`) all hit **ZERO rows** on this image — there is no Firefox, no IE `index.dat`
(`msiecf`), no Java IDX. Every web artefact present is Chrome/Edge or the ESE WebCache, and
**none of them route to an http map.** Real tallies of the web/download universe:

| data_type | rows | Plaso parser | split file `table_name()` | route → | mined for http? |
|---|--:|---|---|---|---|
| `chrome:cache:entry` | **21,636** (18,145 w/ `http` url) | `chrome_cache` | `.L2tChromeCache` | **no ROUTES match → `[]`** | **NO — raw** |
| `chrome:cookie:entry` | 8,863 | `sqlite/chrome_17_cookies` | `.L2tSqlite` | `l2t_firefox_places` | NO (not http; not ff) |
| `chrome:history:page_visited` | **2,293** | `sqlite/chrome_27_history` | `.L2tSqlite` | `l2t_firefox_places` | **NO — pred rejects** |
| `msie:webcache:container` | **921** (183 w/ `response_headers`, 452 `Visited:` history) | `esedb/msie_webcache` | `.L2tEsedb` | `l2t_srum` | **NO — pred rejects** |
| `chrome:autofill:entry` | 802 | `sqlite/chrome_autofill` | `.L2tSqlite` | `l2t_firefox_places` | NO (not http) |
| `windows:registry:msie_zone_settings` | 90 | `winreg/msie_zone` | `.L2tWinreg` | registry maps | NO (config, no url) |
| `msie:webcache:cookie` | 134 | `esedb/msie_webcache` | `.L2tEsedb` | `l2t_srum` | NO (cookie) |
| `chrome:history:file_downloaded` | **42** | `sqlite/chrome_27_history` | `.L2tSqlite` | `l2t_firefox_places` | **NO — pred rejects** |
| `windows:registry:typedurls` | 15 | `winreg/windows_typed_urls` | `.L2tWinreg` | `plaso_registry` | NO (→ registry object, not http) |

**Why each is raw (confirmed in code, not inferred):**
- `l2t_split.table_name()` keys off the **top-level** parser segment. `sqlite/chrome_27_history`,
  `sqlite/chrome_17_cookies`, `sqlite/chrome_autofill` → **`.L2tSqlite`** → `ROUTES` sends that to
  `["l2t_firefox_places"]`, whose only predicate is `plasoweb_is_ff_visit` =
  `data_type == "firefox:places:page_visited"` (`plaso_web.py` L57-60). **Chrome rows fail it →
  `default: None` → raw.**
- `chrome_cache` (no `/`) → **`.L2tChromeCache`** → **no `ROUTES` pattern matches** → `route()`
  returns `[]` → raw. No map anywhere references `chrome_cache`/`chrome:cache` (grep of `mappings/`
  = 0 hits).
- `esedb/msie_webcache` → **`.L2tEsedb`** → `ROUTES` sends that to `["l2t_srum"]`, whose predicates
  gate `windows:srum:network_usage` / `application_usage` only (`plaso_srum.py` L41-46). **WebCache
  rows fail it → raw.** No map references `webcache` (grep = 0 hits).
- `winreg/*` → `.L2tWinreg` → `plaso_registry` maps `typedurls` as a **registry** object
  (`plaso_registry.py` L4), never as http.

## 1. Per-field provenance (FILESYSTEM artefacts)

Legend: `[direct]` 1:1 copy · `[inferred]` regex out of a compound field · `[derived]` transform ·
`[asserted]` constant the record proves. **Mined?** = does any wired map route+accept this row for http.

### `url_full` — the full URL requested
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| **chrome:history:page_visited** `url` [direct] | get | **NO** — `.L2tSqlite`→ff-only predicate rejects | High/direct. 2,293 rows. Same shape as the wired firefox_places map. |
| **chrome:history:file_downloaded** `url` [direct] | get | **NO** — same predicate | High/direct. 42 rows; source download URL (e.g. `https://s3browser.com/download/s3browser-7-6-9.exe`). |
| **chrome:cache:entry** `original_url` [direct] | get | **NO** — `.L2tChromeCache` unrouted | High/direct. 18,145 `http` urls of 21,636. A cache fetch = a GET. |
| **msie:webcache:container** `url` (`https://…` or `Visited: user@<url>`) [coalesced] | get | **NO** — `.L2tEsedb`→SRUM-only | Med/High. 183 direct `https` + 452 `Visited:` history (strip `Visited:\s*[^@]*@` exactly as `_IE_URL` already does). |
| **windows:registry:typedurls** `entries[i]` = `"urlN: <url>"` → strip `^url\d+:\s*` [inferred] | get | **NO** — routes to registry object | Med. 15 rows. User-typed address-bar URLs; strongest intent signal, weakest volume. |
| ADS **Zone.Identifier** `HostUrl=` | get | **NO SOURCE** | Plaso has no Zone.Identifier ADS decoder; 0 rows here (the 9 `zone.identifier` string hits are SmartScreen prefetch path-hints, not ADS content). Real-universe via MFT `$DATA:Zone.Identifier` extraction. |

### `url_domain` / `url_scheme` / `url_remainder` — parsed from the url
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| chrome history / downloads / cache, webcache | `regex1(url, …)` [inferred] | get | **NO** (as above) | Identical derivations to `plaso_web._http_props()` — `scheme=^(https?)://`, `domain=^https?://([^/?#:]+)`, `remainder=^https?://[^/]+(/[^\s]*)`. Would drop straight in. Chrome downloads/history/cache carry real `https` (LoneWolf), so scheme is genuinely `https` — unlike Zeek which is forced `http`. |

### `hostname` — the vantage (host the request was seen ON)
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| ALL of the above | `image_hostname` = `DESKTOP-PM6C56D` [direct] | get | **NO** (rows raw) | High. Every row carries the lane-stamped imaged host. Endpoint artefact = the imaged host IS the vantage (same principle as the wired browser maps). |

### `response_status_code`
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| **msie:webcache:container** `response_headers` → `regex1(rh, "HTTP/\d\.\d\s+(\d{3})")` [inferred] | get | **NO** — SRUM-only route | **Med/High. The only on-disk status source on this image.** All 183 header-bearing rows parse cleanly (all `200` here, but the parse is deterministic & status varies on richer images). |
| firefox_cache `response_code` | — | (wired, but 0 rows here) | The existing wired parse; no Firefox on LoneWolf. |
| chrome:cache:entry | — | **NO SOURCE** | This Plaso `chrome_cache` version emits only `original_url`+`payloads` — no status/method/content-type fields. Honest null. |

### `http_version`
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| **msie:webcache:container** `response_headers` → `regex1(rh, "HTTP/(\d\.\d)")` [inferred] | get | **NO** — SRUM-only route | Med/High. All 183 → `1.1`. **Only FS source for http_version anywhere** (Zeek is the only other). |

### `response_body_bytes`
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| **chrome:history:file_downloaded** `received_bytes` / `total_bytes` [direct] | get | **NO** — ff-only predicate | Med/High. 42 rows (e.g. `2483848` bytes). Downloaded-object size; maps to response body like BITS `bytesTransferred`, with the same "transfer total, not strict HTTP body-len" caveat. |
| **msie:webcache:container** `response_headers` → `regex1(rh, "content-length:\s*(\d+)")` [inferred] | get | **NO** — SRUM-only route | Med. 183 rows carry `content-length`. Wire response-body length. |
| chrome:cache:entry | `payloads` are data-file **offsets**, not sizes | — | **NO** | Cache-object size not exposed as a numeric field here. |

### `request_referrer`
| fs artefact → native field | action | mined? | conf & caveats |
|---|---|---|---|
| **chrome:history:page_visited** `from_visit` [coalesced] | get | **NO** — ff-only predicate | Med. Same `from_visit` referrer the wired firefox_places map already reads (`plaso_web.py` L142-144) — Chrome populates the identical column; blocked only by the data_type gate. Client-side recorded, not navigation proof. |
| chrome:history:file_downloaded | `downloads_url_chains` is in the SQL `query` but **not emitted** as a field | — | **NO SOURCE** | This Plaso version surfaces only the final `url`; the referrer chain isn't in the record. Honest null. |

### Fields with NO fs source anywhere (honest nulls)
| field | why | 
|---|---|
| `request_body_bytes`, `request_body_content` | No disk web-history artefact records request bodies. |
| `response_body_content` | Chrome `Cache_Data`/`data_N` blocks and WebCache `cached_filename` hold response bodies **on disk**, but neither Plaso plugin extracts the bytes — `chrome:cache:entry.payloads` are only offset pointers (`"data_3 (offset: 0x00002000)"`). Would need a cache-body extractor. |
| `requester_ip_address` | Endpoint artefacts don't record the client's own source IP. (WebCache/IDX record the *server*.) |
| `user_agent_full` / `_name` / `_version` / `_device` | No browser-history/cache artefact retains the request UA header. (UA-parse gap unchanged from the Zeek doc: `_full` exists only from Zeek, and name/version/device need a `[heuristic]` parser that exists nowhere.) |

## 2. Coverage matrix — FS artefacts × field (all UNMINED)
`U`=present-but-unmined · `·`=not recorded · `N*`=no fs source anywhere

| field | chrome:history | chrome:downloads | chrome:cache | msie:webcache | reg:typedurls |
|---|:--:|:--:|:--:|:--:|:--:|
| hostname | U | U | U | U | U |
| url_full | U | U | U | U | U |
| url_domain/scheme/remainder | U | U | U | U | U |
| request_referrer | U | · | · | · | · |
| response_status_code | · | · | · | **U** | · |
| http_version | · | · | · | **U** | · |
| response_body_bytes | · | **U** | · | **U** | · |
| request_body_* / response_body_content | N* | N* | N* | N* | N* |
| requester_ip_address | N* | N* | N* | N* | N* |
| user_agent_* | N* | N* | N* | N* | N* |

## 3. Ranked UNMINED opportunities (all found in real LoneWolf data)

1. **Chrome/Edge History → extend the `.L2tSqlite` route (2,293 visits + 42 downloads, highest volume).**
   Cheapest, highest-value win. The `l2t_firefox_places` map already derives exactly these fields;
   only its predicate (`data_type == firefox:places:page_visited`) blocks Chrome. Add a
   `chrome:history:page_visited` variant (url + from_visit referrer + `visit_count`/`typed_count`/
   `page_transition_type` native, `get`) and a `chrome:history:file_downloaded` variant
   (url + `received_bytes`/`total_bytes`→response_body_bytes + `full_path`→file link, `get`).
   Same for Edge (Chromium — identical `chrome:*` data_types). Downloads also cross-link to the
   `file` object via `full_path`.

2. **WebCacheV01.dat (ESE) → new `msie:webcache:container` map (uniquely gives status + version + bytes).**
   The **only on-disk source of `response_status_code`, `http_version`, and content-length** on a
   Windows box. Route: `.L2tEsedb` already reaches the plaso esedb lane but `l2t_srum` accepts only
   SRUM — add a `webcache` map (or a second predicate) parsing `response_headers`
   (`HTTP/(\d\.\d)\s+(\d{3})`, `content-length:\s*(\d+)`, content-type) + `url` (direct `https` **and**
   `Visited: user@<url>` history, reusing the existing `_IE_URL` strip). 183 header rows + 452 history
   rows here. Medium effort (new compound-field parse), unique field coverage.

3. **Chrome/Edge Cache → new `chrome_cache` route + map (18,145 url observations, biggest raw dump).**
   Add `(".L2tChromeCache", ["l2t_chrome_cache"])` to `ROUTES` and a map asserting url_full/domain/
   scheme/remainder + hostname + `get` from `original_url`. No status/method in this Plaso version, so
   url + vantage only — but it's 18k independent GET observations currently going 100% to raw.

4. **Registry TypedURLs → optional http cross-emit (15 rows, strongest intent).**
   Already captured as a `registry` object. If http coverage of user-typed navigation is wanted, a
   `get` http observation per `entries[i]` (strip `^url\d+:\s*`) with hostname=image_hostname; only the
   MRU (`url1`) carries the TypedURLsTime, the rest are timestamp-less. Low volume, low effort.

5. **ADS Zone.Identifier `HostUrl`/`ReferrerUrl` → download provenance (NO SOURCE in current pipeline).**
   The textbook mapping (`url_full`+`request_referrer` of a downloaded file). **Not reachable today:**
   Plaso emits no Zone.Identifier ADS record, and the pipeline doesn't extract MFT `$DATA:Zone.Identifier`
   stream content. Real-universe value is high (ties a file to its origin URL + referrer) but needs an
   MFT-ADS extraction step that doesn't exist. Highest effort, honest gap.

## 4. Honest no-sources (do NOT fabricate)
- **request/response body content & request bytes** — no fs web-history artefact records them; cache
  bodies exist on disk but neither Plaso plugin extracts the bytes.
- **requester_ip_address** — endpoint artefacts record server IP, never the client's own.
- **user_agent_* ** — browser history/cache/downloads keep no UA header; the name/version/device parse
  gap (needs `[heuristic]` `ua_parser`/`woothee`) is unchanged and still unmapped anywhere.
- **Network Action Predictor, Safari, Opera, WER URLs, Office/SharePoint MRU** — 0 rows on LoneWolf
  (Network Action Predictor has no Plaso data_type at all); genuine no-source here.
