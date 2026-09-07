# CAR property-provenance catalogue

A "find once, done" reference: for every MITRE CAR object, every canonical field,
and **every artefact/source in the DFIR pipeline that can supply it** — grounded
in the actual engine maps (not the upstream CAR sensor cards, which overclaim),
in PIIAT-Mem's memory maps, and in real processed evidence.

One file per object (all 13). Each has a per-field table
(`field | sources (source → native field) | action(s) | currently mapped? | confidence & caveats`)
plus a source×field coverage matrix.

| object | fields | active producers | headline |
|---|---:|---:|---|
| [process](process.md) | 29 | 13 (+1 inert) | `env_vars`/`uid`/`cwd` memory-only; `sid` from 4688/memory not Sysmon1; 67/102 analytics use it |
| [file](file.md) | 26 | 18 | best-covered; `timestomp`/`previous_creation_time` from $SI/$FN unused; 4663/5140 write path quarantined |
| [flow](flow.md) | 27 | 5 | endpoint identity (`exe`/`user`/`pid`) only from Sysmon 3 / memory / WFP 5156, never from pcap |
| [user_session](user_session.md) | 10 | 7 | `login_id` LUID is the cross-artefact join; `lock`/`login_successful=false` unsourced |
| [registry](registry.md) | 11 | 5 (+1 inert) | live writer (`pid`/`user`/`image_path`) only from Sysmon/4657; dead hives are honest nulls |
| [authentication](authentication.md) | 19 | 1 | ONE mapper (4624/4625/4672); Kerberos 4768/4769 + NTLM 4776 unwired (biggest gap) |
| [module](module.md) | 13 | 3 | `base_address` memory-only; injection (ldrmodules) + hash-hydration unused |
| [thread](thread.md) | 15 | 2 | stacks memory-only (TEB); `remote_create` Sysmon8; `src_tid`/`suspend`/`terminate` no-source |
| [service](service.md) | 10 | 3 | registry `Services` key → whole object from a dead disk is the big gap; `pid` svcscan-only |
| [driver](driver.md) | 11 | 2 | `base_address` memory-only, hashes Sysmon6-only; `unload`/`pid` structural no-source |
| [socket](socket.md) | 10 | 1 | memory netscan → `listen` only; WFP 5158 (`bind`) inert; `remote_*`/`close` by-design no-source |
| [http](http.md) | 17 | 6 | zeek_http spine; UA→name/version/device unparsed; no analytic consumes http |
| [email](email.md) | 21 | 1 | zeek_smtp only, STARTTLS → empty in practice; needs a mail-store/server-log parser |

## How to read it
- **"currently mapped?"** is the gap column — a `NO` where a genuine source exists is a completeness gap (see [COMPLETENESS-BACKLOG.md](COMPLETENESS-BACKLOG.md)); a `NO` with no source is an **honest null** (documented, never faked).
- Grounded in `piiat_mitrecar/mappings/` + `sources/*.yaml` (engine), `piiat-mem/piiat_mem/mappings.py` (memory), `to-be-validated/evtx_audit.yml` (the quarantined audit family), and `car_data_model.json`.
- **Do not trust the upstream `*.yaml` `coverage_map`s** — the agents found driver/thread/flow sensor cards overclaim (`pid`, `src_tid`, `uid` listed but not on the wire). The per-field tables here are ground truth.

Generated 2026-09-07 by a per-object deep audit; §1 of `docs/CAR-Extraction-Rules.md` (extract every field the artefact can supply) is the governing principle.
