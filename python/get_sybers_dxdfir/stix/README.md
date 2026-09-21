# STIX 2.1 exchange (`dxdfir stix`)

The exchange interface of Byakugan: detections out as STIX 2.1, Byakugan's STIX
projection passed through, OpenCTI as the wire. The engine stays Elastic; this
package never imports Byakugan and never re-derives what Byakugan already projected.
What it emits follows the OASIS *STIX Best Practices Guide v1.0* (cn01) — the
section references below are to it (BP) and to the STIX 2.1 specification.

```bash
dxdfir stix export --hits detections.jsonl --out bundle.json
dxdfir stix export --hits alerts.json --bundle byakugan-case.json --case CASE-17 --push
```

## What a hit becomes

| hit field | STIX |
|---|---|
| `DetectionId` / `rule.id` / `detection.id` / `kibana.alert.rule.rule_id` | `indicator` (one per rule, global id). Its `pattern` **is** the rule's `query` from the rules-as-code directory (default: the package's own [`detect/rules`](../detect/rules/README.md); `--rules-dir` overrides), `pattern_type` the rule's `language`, `pattern_version` the Elastic stack version; `created` / `valid_from` / `modified` are the rule's `created` / `updated`; the detection id is a `dxdfir` external reference. A hit whose rule is a stub, undated or missing is **skipped and counted** (`summary.hits.skipped`) — a pattern is never invented |
| `AttackIds` / `threat.technique.id` / `kibana.alert.rule.threat` | `indicator --indicates--> attack-pattern` SROs whose `target_ref` is **MITRE's own** ATT&CK object id (BP §5.2 / §2.2; [`data/attack-index.json`](data/attack-index.json)). No attack-pattern is minted locally. The rule's techniques are `relationship_class: declared`, a technique only the hit carries is `derived`; a revoked technique resolves to its replacement (reported under `summary.hits.techniques.substituted`), an unknown one is reported, not invented. The rule's techniques are also `mitre-attack` external references and `kill_chain_phases` on the indicator |
| the row itself | `sighting` of the indicator (case-scoped id): `created` = the detection time, `first_seen` / `last_seen` = the hit time; identical rows collapse into one sighting with `count` |
| `host.name` / `Details.Computer` | `identity` (`identity_class: system`) in `where_sighted_refs` |
| `source.ip` / `destination.ip` (+ `source.port` / `destination.port`, `network.transport` / `network.protocol`) or an `"A -> B:port"` entity | a **connected** observation (STIX 2.1 §4.14, BP §5.9): a `network-traffic` SCO (`src_ref`, `dst_ref`, ports, `protocols`) and its two address SCOs in one `observed-data`; a lone address in its own |
| `file.name` / `file.hash.*` | `file` SCO (id over one hash, MD5 > SHA-1 > SHA-256 > SHA-512, plus the name) in its own `observed-data` |
| `event.id` (the CAR guid), `RunId`, the case, severity, evidence source | the DX_DFIR **property extension** on the sighting (below). The raw evidence row (`Details`) is not exported |

Every SCO carries the spec's deterministic id (§2.9: uuid5 under the SCO
namespace over the id-contributing properties), so any conformant producer
derives the same id for the same address, hash or connection.

Inputs (`--hits`, repeatable): `dxdfir detect --jsonl-out` JSON Lines, a JSON
array, a single document, or an Elasticsearch `_search` response
(`hits.hits[]._source`). Documents that name no detection are skipped and
counted, never guessed.

## Ids and versioning (decision D4; STIX 2.1 §2.9, §3.2, §3.6)

- **Global, content-keyed**: indicator (by detection id), identities and
  relationships — uuid5 under the DX_DFIR namespace (the spec's SHOULD is
  UUIDv4; deterministic ids make a re-export merge on the platform instead
  of duplicating, as the platform itself does; the SCO namespace is never
  used for them) — and every SCO (§2.9).
- **Case-scoped**: sighting and observed-data — uuid5 under a namespace derived
  from `--case` (default: the hits' run id). Re-exporting a case is idempotent;
  two cases never collide.
- **Stable times.** A deterministic id makes every export a *version* of the
  same object, so `created` never comes from the export clock (§3.2: "MUST NOT
  be changed when creating a new version of the object"): an indicator and
  its relationships are dated by the rule file (`created` / `updated`), an
  observation by its observation time, identities and the extension
  definition by a fixed release date (`objects.IDENTITY_*`,
  `objects.EXTENSION_*`). Re-exporting the same hits yields byte-identical
  objects; bumping a rule's `updated` is what versions its indicator.

## The DX_DFIR extension (STIX 2.1 §7.3; BP §2.3, §9)

No `x_` custom property and no `x-` custom object type is produced — both are
deprecated in STIX 2.1. What the spec cannot express travels in ONE
**property extension**, `extension-definition--0a37fc5b-cf2b-5ae9-84aa-933110a32190`
(uuid5 under the DX_DFIR namespace), whose definition object rides in every
bundle and whose JSON schema is
[`extension/dxdfir-extension.schema.json`](extension/dxdfir-extension.schema.json):

| object | extension properties |
|---|---|
| `indicator` | `detection_id`, `severity`, `status` (`ported` / `stub`) |
| `sighting` | `case_id`, `run_id`, `detection_id`, `severity`, `source`, `car_guid`; an indicator-match sighting also carries `feed`, `matched {field, atomic, index, id}`, `indicator {type, name, provider}`, `alert_ids` |
| `relationship` | `relationship_class`: `declared` (by a rule author) / `derived` (from evidence) |

Bump `EXTENSION_VERSION` and `EXTENSION_MODIFIED` in [`objects.py`](objects.py)
together when the schema changes.

## Markings (BP §3.5)

`--tlp` (default `amber`) puts the spec's fixed TLP marking id in
`object_marking_refs` of every SDO, SRO and observed-data. The
marking-definition object itself is never shipped (every STIX implementation
knows the four), and SCOs are never marked ("it makes no sense to restrict
the sharing of an IP address").

## Pattern types (BP §8.1)

`pattern_type` takes the rule's `language`: `esql`, `eql` (and `kuery` /
`lucene` for Kibana-language rules). They are not in the spec's
`pattern-type-ov` (`stix`, `pcre`, `sigma`, `snort`, `suricata`, `yara`); they
are this exchange's **trust-group values**, agreed here, with
`pattern_version` naming the Elastic stack the pattern is known to run on
(config `stack_version`, default the stack this repo deploys — pinned to the
ansible default by the tests). A consumer without Elastic cannot evaluate
them; the sightings still tell it what fired and where.

## Pass-through (`--bundle`, repeatable)

Byakugan projects its CAR stores (its materialised CAR JSONL + native) to STIX itself —
SCOs, observed-data, and SROs for both relationship classes, labelled
`declared` / `derived`. A Byakugan bundle is merged object-for-object with ids
untouched; a duplicate id keeps the newest `modified`. The summary counts
relationships per class (DX's from the extension, Byakugan's from its labels).

## Validation

`validate_bundle()` gates every export and push: structure is an error (ids,
required properties, dated objects and markings, SRO endpoints that are not
SDOs / SCOs, sighting references that are not what §5.2 allows); a reference
that resolves neither in the bundle nor in MITRE's ATT&CK repository is a
warning, as are relationship names or targets the spec's tables do not list
(§5.1, BP §5.12), deprecated `x_` properties / `x-` types (a pass-through
producer's, never ours), marked SCOs and an extension used without its
definition.

## Output and OpenCTI

`--out` (or config `out`) writes the bundle; without either it goes to stdout
and the summary to stderr. `--push` uploads the same bundle through
[`opencti.py`](opencti.py): endpoint and token come from `DXDFIR_OPENCTI_URL` /
`DXDFIR_OPENCTI_TOKEN` (or `opencti.url` / `opencti.token` in a `--config`
JSON/YAML file that is **not committed**). There is deliberately no `--token`
flag. The transport is an interface (`post(url, headers, body, timeout)`), so
the push is tested with a stub and no platform — see
[`test_stix_export.py`](../../tests/test_stix_export.py).

Config precedence: file < environment (`DXDFIR_OPENCTI_URL`,
`DXDFIR_OPENCTI_TOKEN`, `DXDFIR_OPENCTI_CONNECTOR_ID`, `DXDFIR_STIX_CASE`,
`DXDFIR_STIX_TLP`, `DXDFIR_STIX_RULES_DIR`, `DXDFIR_STIX_ATTACK_INDEX`,
`DXDFIR_STIX_STACK_VERSION`, `DXDFIR_STIX_CONTACT`, `DXDFIR_STIX_CONFIDENCE`,
`DXDFIR_CTI_INDEX`) < flags. See [`config.py`](config.py) for the file shape:
`contact` is the producer identity's `contact_information` (BP §3.4, default
the repository's issue tracker), `confidence` an optional STIX confidence
(0..100, BP §4.8) stamped on indicators and sightings.

## The ATT&CK index

[`data/attack-index.json`](data/attack-index.json) is a compact index of
MITRE's enterprise-attack STIX bundle — technique id -> `attack-pattern` id,
name, kill-chain phases, `revoked-by` — so the export can reference the
authoritative objects offline. Regenerate it from a downloaded bundle:

```bash
cd python && PYTHONPATH=. python -m get_sybers_dxdfir.stix.attack_index enterprise-attack.json
```

`DXDFIR_STIX_ATTACK_INDEX` / config `attack_index` points at another index or
straight at an ATT&CK STIX bundle.

## CTI: OpenCTI indicators in, sightings back out (`pull` / `sightings`)

OpenCTI stays the wire; the matching is Elastic's own indicator-match rule.
The CTI direction runs through the same client and the same stubbed transport:

```bash
dxdfir stix pull --out cti.ndjson [--since 2026-08-01T00:00:00Z] [--bundle-out pulled.json]
curl -sS -XPOST "$ES/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @cti.ndjson
dxdfir stix sightings --alerts alerts.json --case CASE-17 --push
```

1. **Pull** — `OpenCTIClient.pull_indicators()` pages the platform's STIX 2.1
   indicators (with the creator identities and the non-spec markings they
   reference; the spec's TLP instances are referenced, never shipped) into
   one bundle; `--since` makes it incremental (`modified` after the watermark).
2. **Copy** — [`cti/indicators.py`](cti/indicators.py) breaks every pattern
   into its `=` comparisons and lands each value under the ECS
   `threat.indicator.*` field that [`cti/pattern-mapping.yml`](cti/pattern-mapping.yml)
   names (`[ipv4-addr:value = '…']` -> `threat.indicator.ip`,
   `file:hashes.'SHA-256'` -> `threat.indicator.file.hash.sha256`, …), plus
   `threat.indicator.{id,type,name,confidence,provider,marking.tlp,…}`,
   `stix.{pattern,valid_from,valid_until,revoked,…}` and
   `opencti.{id,score,detection}`. Out come `_bulk` lines keyed on the STIX id
   (`_id`, so a re-pull upserts) for the `cti-*` index that
   [`cti/cti.index-template.json`](cti/cti.index-template.json) describes
   (`PUT _index_template/cti`; strict mapping — the copy refuses to emit a
   field the template does not map). YARA/Sigma patterns, CIDRs and unmapped
   observables are skipped and counted. `--from-bundle` normalises an
   already-pulled bundle offline, no platform needed.
3. **Match** — the indicator-match rule
   [`detect/rules/cti/cti-indicator-match.yml`](../detect/rules/cti/cti-indicator-match.yml)
   compares `logs-dxdfir.*` / `logs-car.*` evidence fields with `threat.indicator.*`
   (`threat_mapping`); its alerts carry `threat.enrichments[]` — the indicator's
   fields and `matched.{field,atomic,id,index}`.
4. **Sightings back** — [`cti/sightings.py`](cti/sightings.py) turns those
   alerts into one `sighting` per (indicator, host, matched value) whose
   `sighting_of_ref` is the platform's own indicator id (the indicator is not
   re-emitted), each alert's matched value as the spec's SCO in its own
   `observed-data`, the host as `where_sighted_refs`, alerts of the same match
   collapsed into `count` / `first_seen` / `last_seen` with their ids in the
   extension's `alert_ids`; `created` is the earliest observation, `modified`
   the latest alert. Case-scoped ids, pushed through `push_bundle`.

`cti.index` / `DXDFIR_CTI_INDEX` / `--index` names the concrete `cti-*` index
the bulk lines target (default `cti-opencti`). Both verbs are exercised in
[`test_cti.py`](../../tests/test_cti.py) against recording transports — no
platform, no Elasticsearch, no secrets.

```bash
cd python && python -m pytest tests/test_stix_export.py tests/test_cti.py
```
