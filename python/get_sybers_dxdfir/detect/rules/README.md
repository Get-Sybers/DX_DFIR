# Elastic detection rules-as-code (Byakugan)

The detections of the retired Kusto registry (`registry.py`, gone with the ADX
emulator), re-expressed for **Elastic's own Detection Engine** as data: one YAML
file per rule, ES|QL or EQL, each carrying the contract for the **tagged
evidence line** it produces. Loaded and validated by
[`../rules_loader.py`](../rules_loader.py), pinned by
`python/tests/test_rules.py`.

> **The Kusto path has retired (decision D1, done).** The registry, the runner
> in `detect/__init__.py`, the emulator and `kusto/schema/` are gone; this
> directory is what enabled that. The loader never imported the registry, so
> the rule set outlived it: the ids are pinned in `test_rules.py` (a detection
> can neither be dropped silently nor exist twice under different names), and
> each rule's `source` block keeps its provenance — the verbatim KQL or the
> jsonl matcher name it was ported from.

```bash
cd python && PYTHONPATH=. python -m get_sybers_dxdfir.detect.rules_loader   # JSON summary, exit 1 on a bad rule
cd python && PYTHONPATH=. python -m pytest tests/test_rules.py
```

## The rule file

| key | required | meaning |
|---|---|---|
| `id` | yes | the registry id — kebab-case, equal to the file stem (`<id>.yml`) |
| `name` | yes | rule title (no quotes / backslashes) |
| `status` | yes | `ported` (query is real) or `stub` (query is `null`, intent lives in `todo`) |
| `severity` | yes | `low` / `medium` / `high` / `critical` — Elastic's set; the registry's `info` maps to `low` |
| `risk_score` | no | 0..100; defaults to Elastic's canonical value per severity (21 / 47 / 73 / 99) |
| `attack` | yes | ATT&CK technique ids (`T1234`, `T1234.001`); may be empty |
| `tactics` | no | ATT&CK tactic ids (`TA0005`) |
| `created` | no (STIX export: yes) | ISO 8601 date the rule was authored (`"2026-09-02"`). `dxdfir stix export` makes it the indicator's `created` / `valid_from` — STIX 2.1 §3.2: `created` never changes, so it cannot be the export clock; a rule without it is skipped and counted |
| `updated` | no | ISO 8601 date of the last **material** change (query, name, ATT&CK mapping); defaults to `created`. It becomes the indicator's `modified`, which is what versions the object (STIX 2.1 §3.6) — bump it when the rule changes, never otherwise |
| `language` | yes | `esql` or `eql` — also the STIX indicator's `pattern_type` (a trust-group value beyond `pattern-type-ov`, see [`stix/README.md`](../../stix/README.md)) |
| `index` | yes | the data streams read (`logs-<dataset>-*`); an ES|QL `FROM` must read exactly these |
| `query` | ported | the ES|QL / EQL |
| `evidence` | yes | the tagged-evidence-line contract: `shape` (`line` / `aggregate`), `stamped_by` (`query` / `engine`), `fields` (what the line carries beyond the source document) |
| `car_join` | yes | how a hit reaches the car-detections lookup index: `key` (`event.id` / `process.entity_id`) and `via` (`direct` / `provenance` + the provenance fields) |
| `fields` | no | the ECS fields the query reads and the native lane field each comes from — the contract the ingest pipeline must satisfy |
| `source` | yes | provenance: `registry` id, `kind` (`kusto` / `jsonl`), the verbatim `kql` or the jsonl `match` function name |
| `todo` | stub | `query` (the intended ES|QL/EQL) and `blockers` (why it is still a stub) |

`rules_loader.validate()` mirrors `registry.validate()`: first problem raises
`ValueError` prefixed with the rule id. Beyond field validation it runs a
**structural** query check (`check_query()`, not a parser): an ES|QL query must
start with `FROM` over exactly the declared streams, chain only known commands,
request `METADATA _id, _index, _version` unless it aggregates with `STATS`, agree
with the declared evidence shape, and actually stamp (`EVAL x = ...` / `STATS ...
BY x`) every field its evidence contract promises; an EQL query must be a
`<category> where` / `sequence` / `sample` query and let the engine stamp;
both must balance brackets outside string literals and carry no KQL left-overs
(`| project`, `pack(`, `=~`, `tostring(` ...).

## Tagged evidence lines (Hayabusa-style)

There is no separate abstract alert envelope. **The alert is the matched
evidence document**, enriched inline:

- **ES|QL, `shape: line`** — the query reads with `METADATA _id, _index,
  _version`, which makes the Detection Engine raise **one alert per matched
  source document**, carrying every source field plus the columns the query
  `EVAL`s. The rule stamps `rule.id`, `rule.name`, `event.risk_score`,
  `threat.framework`, `threat.tactic.{id,name}`, `threat.technique.{id,name}`
  itself (`stamped_by: query`); several techniques ride as a multi-value
  `threat.technique.id` (`MV_APPEND`). Nothing from the source line is dropped
  (no `KEEP`).
- **ES|QL, `shape: aggregate`** — a `STATS ... BY` query has no single source
  document; the alert is the group row (key + aggregates), stamped the same way.
  Used where one hit per subject is the detection (`zeek-dns-oversized-query`:
  per querying host, not per query).
- **EQL** — EQL cannot `EVAL`; the alert is the source event (every field
  copied) and the engine stamps the rule's identity and ATT&CK mapping under
  `kibana.alert.*` (`stamped_by: engine`; `evidence.fields` lists those).

The Detection Engine additionally copies every rule's `threat` block to
`kibana.alert.rule.threat` in both cases; the inline `threat.*` fields are what
make the line self-describing outside Kibana (exports, the CAR join, OpenCTI
exchange).

## Data streams and ECS fields

Rules read the Byakugan data streams: **`logs-dxdfir.<type>-<namespace>`** for
delivered native evidence (`<type>` = the processed lane: `evtx`, `plaso`,
`zeek`, `volatility`, `hayabusa`, `suricata`, `yara` — the directory name the
shipper stamps into `labels.type`) and **`logs-car.<object>-<namespace>`** for
CAR (`logs-car.*-*` reads every object). Rules are written in **ECS** terms
(`event.code`, `winlog.channel`, `dns.question.name`, ...): each rule's `fields`
block records which native lane field each ECS field comes from, which is the
contract the ECS-normalisation ingest pipelines (a later phase) must satisfy.
Until those pipelines exist the streams hold native field names and the ported
rules match nothing — the rules are the specification, not the pipelines.

## The `car-detections` lookup index and `LOOKUP JOIN`

[`car-detections/`](car-detections/) is the contract as data:

- [`car-detections.index-template.json`](car-detections/car-detections.index-template.json)
  — an Elasticsearch index template (`PUT _index_template/car-detections`) with
  **`index.mode: lookup`** (single shard, what makes an index joinable), strict
  mappings for the join keys, the stamped `rule.*` / `threat.*` fields and the
  `detection.*` provenance. `_id` is `<detection.id>:<event.id>`.
- [`join-keys.yml`](car-detections/join-keys.yml) — which CAR/ECS field joins to
  which lookup-index key, what the join stamps, who writes the index, and the
  reference query.

**Model.** The CAR `guid` travels into Elastic as ECS **`event.id`** on every CAR
object and as **`process.entity_id`** on process (names owned by the CAR->ECS
projection of the Byakugan engine; this contract only depends on them).
`LOOKUP JOIN` needs the same field name on both sides, so the lookup index maps
the keys under those ECS names. Any ES|QL over the CAR streams then flags the
CAR rows a detection matched, inline:

```esql
FROM logs-car.*-* METADATA _id, _index, _version
| LOOKUP JOIN car-detections ON event.id
| WHERE detection.id IS NOT NULL
```

Joining `ON process.entity_id` instead cascades a process-level detection onto
the rows that process owns (module, thread, file, socket ...), since they carry
the owning process guid under the same name. `LOOKUP JOIN` emits one row per
matching lookup row, so a guid hit by two detections yields two stamped lines;
`STATS ... BY event.id` collapses them when one row per CAR event is wanted.

**Writer.** A sweep step (the phase-2 runner) reads the Detection Engine's
alerts (`.alerts-security.alerts-*`) and upserts one document per
(detection, guid). A rule that ran over `logs-car.*` has `event.id` on its
evidence line already (`car_join.via: direct`); a rule over native evidence
(`logs-dxdfir.*`) resolves the guid through its declared `car_join.provenance`
fields against the CAR row's flattened native bag (`via: provenance`) — e.g.
`log.file.path` + `winlog.record_id` for an EVTX-sourced rule. Requires
Elasticsearch 9.x (`LOOKUP JOIN` GA; technical preview in 8.18); Basic licence.

## The CTI indicator-match rule (`cti/`)

[`cti/cti-indicator-match.yml`](cti/cti-indicator-match.yml) is the one
Detection Engine **`threat_match`** rule: it compares `logs-dxdfir.*` /
`logs-car.*` evidence fields (`source.ip`, `destination.ip`, `dns.question.name`,
`url.original`, `file.hash.*`, `process.hash.*`, `registry.key`) with the
`threat.indicator.*` atomics of the **`cti-*`** index — the Elasticsearch copy
of OpenCTI's STIX indicators that `dxdfir stix pull` writes
([`stix/cti/cti.index-template.json`](../../stix/cti/cti.index-template.json);
which STIX comparison lands where is
[`stix/cti/pattern-mapping.yml`](../../stix/cti/pattern-mapping.yml)). Same
file shape as the rules above plus the threat-match keys: `type: threat_match`,
`language: kuery` (Elastic's name for the Kibana query language), `threat_index`,
`threat_query`, `threat_indicator_path`, `threat_mapping` (each list item an OR
alternative, its entries ANDed). The alert is the matched evidence document
plus the engine's `threat.enrichments[]` (the indicator's fields and
`matched.{field,atomic,id,index}`), which `dxdfir stix sightings` turns into
STIX sightings of the platform's own indicator.

It is Byakugan-native, not a registry port, so it lives beside the top-level
rule set (whose ids the tests pin) rather than in it:
[`rules_loader.load_cti_contract()` / `validate_indicator_match()`](../rules_loader.py)
check it against the cti-* template — every `threat_mapping` value must be a
field the copy fills, every `threat_index` pattern one the template covers —
and the loader's CLI validates it alongside the rule set.

## Coverage: KQL -> ES|QL / EQL

Every detection the retired registry carried, ported or stub (the tests fail if
one goes missing):

| registry id | Kusto source | Elastic | reads | status | note |
|---|---|---|---|---|---|
| `win-eventlog-cleared` | `host.EvtxEcmdJson` | EQL | `logs-dxdfir.evtx-*` | **ported** | `any where` over `event.code` / `winlog.channel` (`:` = the KQL `=~`); engine-stamped |
| `win-defender-tamper` | `host.EvtxEcmdJson` | ES\|QL line | `logs-dxdfir.evtx-*` | **ported** | `WHERE ... IN`, inline `threat.*` via `EVAL` |
| `win-service-suspicious-path` | `host.EvtxEcmdJson` | ES\|QL line | `logs-dxdfir.evtx-*` | **ported** | `COALESCE(winlog.event_data.ImagePath, ServiceFileName)`; KQL `(?i)` regex -> `TO_LOWER` + Lucene `RLIKE` (no `\b`: end-or-non-alnum instead) |
| `win-prefetch-dualuse-tool` | `host.L2tPrefetch` | ES\|QL line | `logs-dxdfir.plaso-*` | **ported** | anchored regex -> `TO_UPPER(process.name) IN (...)`; two techniques as multi-value |
| `zeek-notice-promoted` | `network.Zeek (notice)` | ES\|QL line | `logs-dxdfir.zeek-*` | **ported** | `event.dataset == "zeek.notice"`; no ATT&CK, identity stamp only |
| `zeek-dns-oversized-query` | `network.Zeek (dns)` | ES\|QL aggregate | `logs-dxdfir.zeek-*` | **ported** | `summarize by` -> `STATS ... BY source.ip`; `take_any()` -> `MAX()` |
| `vol-malfind-injection` | `memory.VolatilityJson` | ES\|QL aggregate | `logs-dxdfir.volatility-*` | stub | `make_set()` -> `VALUES()` (technical preview); `volatility.*` projection not yet defined |
| `sig-hayabusa-high` | `signatures/hayabusa` (jsonl) | ES\|QL line | `logs-dxdfir.hayabusa-*` | stub | promotion of `hayabusa.level`; per-hit `MitreTags` -> `threat.technique.id` belongs in the ingest pipeline |
| `sig-suricata-alert` | `signatures/suricata` (jsonl) | ES\|QL line | `logs-dxdfir.suricata-*` | stub | `suricata.eve.event_type == "alert"`; `mitre_technique_id` lift belongs in the ingest pipeline |
| `sig-yara-match` | `signatures/yara` (jsonl) | ES\|QL line | `logs-dxdfir.yara-*` | stub | `yara.*` projection and `strings[].data` trimming not yet defined |

6 ported (5 ES|QL, 1 EQL), 4 stubs. A stub keeps the intended query in
`todo.query`, says why in `todo.blockers`, and keeps the source KQL / matcher
name in `source`, so nothing is silently dropped.

## What is deliberately not here yet

- **Pushing rules into Kibana.** The YAML is one `to_kibana()` away from the
  Detection Engine's NDJSON (`rule_id`, `type`/`language`, `query`, `index`,
  `threat`, `severity`, `risk_score`); that exporter and the deploy step land
  with the runner in phase 2.
- **Ingest pipelines** (native -> ECS) for the `logs-dxdfir.*` streams — the
  `fields` blocks are their specification.
- **Sigma compiled to Elastic at build time** — a later phase; it will add rule
  files here in the same shape.
