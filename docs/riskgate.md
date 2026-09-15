# Byakugan Phase-0 risk gate

Byakugan's Elastic-native detection design rests on two assumptions that nothing
in the repository had yet demonstrated on the target stack. This gate proves
them — or fails loudly and says which fallback to take — before anything is
built on top of them:

1. **A detection can be run on demand over an evidence-time window.** DFIR
   evidence is dead-box: the `@timestamp` of a CAR row is when the thing
   happened on the host, typically months or years before the case. A rule must
   be executable over that historical range, and the stack must not silently
   drop, re-stamp or age out old data on the way in.
2. **`LOOKUP JOIN` works.** An ES|QL query can `LOOKUP JOIN` the
   `car-detections` lookup index against `logs-car.*` and bring every CAR row a
   detection matched back stamped in place — the tagged-evidence-line model of
   the [rules-as-code contract](/python/get_sybers_dxdfir/detect/rules/README.md)
   — on Elasticsearch 9.4.3, Basic licence.

The harness lives in [`.github/tests/elastic-riskgate/`](/.github/tests/elastic-riskgate/README.md).
It was **authored without a cluster**: the scripts are written to run as-is once
`stacks/elastic` is up, and an offline `selftest` pins the fixture, the queries
and the expected tables to each other and to the contract. The first live run
is the gate.

## Run it

Prerequisites: the Byakugan Elastic stack (`stacks/elastic/`, wave 1) up and
healthy — its README covers `.env`, `vm.max_map_count` and `docker compose up`.
`python3` on the host; `docker` if the CA is to be fetched automatically.

```bash
# 0. sanity, no cluster needed: fixtures, queries and expected tables agree
./.github/tests/elastic-riskgate/riskgate.sh selftest

# 1. the gate: load the fixture, proof 1, proof 2, the probe, clean up
./.github/tests/elastic-riskgate/riskgate.sh

# variants
./.github/tests/elastic-riskgate/riskgate.sh --keep       # leave the fixture for inspection in Kibana
./.github/tests/elastic-riskgate/riskgate.sh clean        # remove it (add --drop-template to drop the contract template too)
./.github/tests/elastic-riskgate/riskgate.sh load         # or proof1 | proof2 | probe, one step at a time
```

The wrapper reads `ELASTIC_PASSWORD` from `stacks/elastic/.env` and copies the
CA out of the running `elasticsearch` container (`certs` volume); override with
`ES_URL`, `ES_USER`, `ES_PASSWORD`, `ES_CA` (a PEM file) or, loopback-only and
as a last resort, `RISKGATE_INSECURE=1`. Exit code 0 means every gated check
passed; 1 means at least one failed (each names itself and its reason); 2 means
the harness could not run at all (cluster unreachable, no credentials).

Everything the run creates is namespaced **`riskgate`**: the data streams
`logs-car.process-riskgate` and `logs-car.file-riskgate` and the lookup index
`car-detections-riskgate`. The one shared object it writes is the contract's own
`car-detections` index template, `PUT` verbatim from
[`car-detections.index-template.json`](/python/get_sybers_dxdfir/detect/rules/car-detections/car-detections.index-template.json)
— idempotent, and exactly what the deploy step will do. Running the gate against
a cluster holding a real case adds and removes only the `riskgate` objects.

## The fixture

Synthetic, never real evidence. Four CAR rows on host `WS01`, all dated
**2019-04-12** (the dead-box bar every stored row must clear is `< 2020`), shaped
per the CAR->ECS projection (`guid -> event.id`, `owning_guid ->
process.entity_id`, constants `event.module: car`, `car.object`, the native bag
under `car.native`):

| stream | `event.id` (guid) | what | owner (`process.entity_id`) | link |
|---|---|---|---|---|
| `logs-car.process-riskgate` | `{…3c02}` | `notepad.exe` create, 09:15 — benign | itself | definitive |
| `logs-car.file-riskgate` | `WS01-Sysmon-4702` | `notes.txt` create, 09:16 — benign | `{…3c02}` | definitive |
| `logs-car.process-riskgate` | `{…3c01}` | `wevtutil cl Security`, 13:37 — **the hit** | itself | definitive |
| `logs-car.file-riskgate` | `WS01-filestat-000ef2a1` | `Security.evtx` modified, 13:37:05 (Plaso filestat) | `{…3c01}` | heuristic (0.5) |

Three rows in the lookup index, one per (detection, guid), `_id` =
`<detection.id>:<event.id>`, fields strictly those the contract template maps:

| `_id` | keys | `join_via` | what it stands for |
|---|---|---|---|
| `win-eventlog-cleared:{…3c01}` | `event.id` + `process.entity_id` | provenance | the ported EQL rule's 1102 hit on `logs-dxdfir.evtx-*`, resolved to the CAR guid |
| `riskgate-wevtutil-clear:{…3c01}` | `event.id` + `process.entity_id` | direct | proof 1's own hit, as the sweep would write it |
| `riskgate-evtx-modified:WS01-filestat-000ef2a1` | `event.id` only | direct | a file-level detection — no process key |

The `riskgate-*` rule ids are local to the harness; they are not part of the
rule set. The streams are created on first write by Elasticsearch's built-in
`logs-*-*` template (no template of our own), exactly as the CAR loader will
find them.

## Proof 1 — a manual detection run over an evidence-time window

A scheduled Detection Engine rule looks back from *now* and can never see
2019. The runner therefore executes the rule the way the phase-2 runner will:
`POST /_query` with the evidence window written into the `WHERE` clause
([`queries/10-manual-detection-window.esql`](/.github/tests/elastic-riskgate/queries/10-manual-detection-window.esql)
— a line-shaped Byakugan rule: `METADATA _id, _index, _version`, identity and
ATT&CK mapping `EVAL`'d inline, the trailing `KEEP` proof-only).

| check | demonstrates | pass bar |
|---|---|---|
| 1.1 | the streams accept rows dated 2019 | bulk of 4 rows, no item errors |
| 1.2 | `@timestamp` is kept as the evidence time — nothing dropped, nothing re-stamped to ingest time | `_count` = 4 and `_count` with `@timestamp < 2020-01-01` = 4 |
| 1.3 | nothing will age the evidence out later | no data-stream-lifecycle retention (`effective_retention` absent), no ILM delete phase on the streams |
| 1.4 | the rule, run over `2019-04-12` explicitly, hits | exactly this table |
| 1.5 | the window is honoured: the same rule over the last 24 h | no rows |

Expected table for 1.4 ([`expected/10-manual-detection-window.json`](/.github/tests/elastic-riskgate/expected/10-manual-detection-window.json)):

| @timestamp | event.id | host.name | process.name | process.command_line | rule.id | rule.name | event.risk_score | threat.tactic.id | threat.technique.id |
|---|---|---|---|---|---|---|---|---|---|
| 2019-04-12T13:37:00.000Z | `{…3c01}` | WS01 | wevtutil.exe | wevtutil cl Security | riskgate-wevtutil-clear | wevtutil clearing an event log | 73.0 | TA0005 | T1070.001 |

**Proof 1 passes** when 1.1–1.5 all pass. What that establishes: the runner
path — ES|QL over an explicit `@timestamp` range through `_query` — is a
sound way to run any rule of the set over dead-box evidence, and the built-in
`logs-*-*` stream behaviour (logsdb mode, `logs@default-pipeline`, lifecycle)
does not interfere with evidence time. The Detection Engine's own
historical-range facility (Kibana's *manual rule run* over a start/end date)
is the same thing behind the UI; it is not scripted here because pushing the
rules into Kibana is phase 2.

## Proof 2 — `LOOKUP JOIN` on Elasticsearch 9.x

The contract as data: `car-detections.index-template.json` (`index.mode:
lookup`, strict mappings) and
[`join-keys.yml`](/python/get_sybers_dxdfir/detect/rules/car-detections/join-keys.yml)
(`event.id` on every CAR object, `process.entity_id` for the process cascade).
The gate PUTs the template verbatim, writes the three lookup rows and runs the
joins.

| check | demonstrates | pass bar |
|---|---|---|
| 2.1 | the contract template is valid on this cluster | `PUT _index_template/car-detections` acknowledged |
| 2.2 | the lookup index really is a lookup index | created from the template on first write; `index.mode: lookup`, 1 shard, 3 rows |
| 2.3 | join-key type parity | `event.id` and `process.entity_id` are `keyword` on both CAR streams and on the lookup index (the CAR side is mapped by the built-in `ecs@mappings`) |
| 2.4 | the **direct join** `ON event.id` flags exactly the detected rows, stamped, with evidence time and owner link intact ([`queries/20`](/.github/tests/elastic-riskgate/queries/20-lookup-join-flag.esql)) | exactly the table below |
| 2.5 | the **cascade join** `ON process.entity_id` reaches the process row and the file it owns; a lookup row without the key joins nothing ([`queries/21`](/.github/tests/elastic-riskgate/queries/21-lookup-join-cascade.esql)) | 4 lines: both process-level detections on `{…3c01}` and on `WS01-filestat-000ef2a1` |
| 2.6 | fan-out semantics: one line per matching lookup row, collapsed by `STATS … BY event.id` ([`queries/22`](/.github/tests/elastic-riskgate/queries/22-lookup-join-collapse.esql)) | `{…3c01}`: 2 detections / 2 rules; `WS01-filestat-000ef2a1`: 1 / 1 |

Expected table for 2.4 ([`expected/20-lookup-join-flag.json`](/.github/tests/elastic-riskgate/expected/20-lookup-join-flag.json)):

| @timestamp | event.id | car.object | host.name | process.entity_id | detection.id | detection.severity | detection.join_via | rule.id | threat.technique.id |
|---|---|---|---|---|---|---|---|---|---|
| 2019-04-12T13:37:00.000Z | `{…3c01}` | process | WS01 | `{…3c01}` | riskgate-wevtutil-clear | high | direct | riskgate-wevtutil-clear | T1070.001 |
| 2019-04-12T13:37:00.000Z | `{…3c01}` | process | WS01 | `{…3c01}` | win-eventlog-cleared | high | provenance | win-eventlog-cleared | T1070.001 |
| 2019-04-12T13:37:05.000Z | WS01-filestat-000ef2a1 | file | WS01 | `{…3c01}` | riskgate-evtx-modified | medium | direct | riskgate-evtx-modified | T1070.001 |

`notepad.exe` and `notes.txt` are absent: the join flags, it does not filter
by anything else.

**Proof 2 passes** when 2.1–2.6 all pass. What that establishes: on this
stack the contract's lookup index is joinable, the CAR streams need no mapping
of their own for the keys, both join keys behave as `join-keys.yml` says, and
a flagged line keeps every source field it had.

### Field shadowing — why the proof queries stash and restore

`LOOKUP JOIN` replaces every source field that the lookup index *also maps*
with the lookup row's value. On this contract that is the join key (same value,
harmless) and the intended stamps (`detection.*`, `rule.*`, `threat.*`,
`event.risk_score`) — and two fields that must **not** change:

- **`@timestamp`** — the template maps it and a writer will naturally set it to
  the detection time. Joined naively, the flagged evidence line reports 2026,
  not 2019: the evidence time is silently overwritten, the very failure the
  gate exists to catch.
- **`process.entity_id`** — the cascade key. A file-level lookup row does not
  carry it; joined naively `ON event.id`, the file row's owning-process link is
  at risk of being replaced with null. Conversely, joined `ON
  process.entity_id`, the lookup row's `event.id` (the *detected* guid)
  replaces the child row's own `event.id`.

The proof queries therefore `RENAME` those fields aside before the join and
restore them after it (`20`, `21`); the cascade query keeps the row identity as
`car.guid` and leaves `event.id` meaning "the guid the detection cascaded
from". The **probe** ([`queries/29`](/.github/tests/elastic-riskgate/queries/29-lookup-join-shadowing-probe.esql),
informational, never gated) runs the naive contract shape and reports what this
cluster actually does to the two fields, so the decision below is taken on
facts rather than on the documentation:

- if the probe reports `@timestamp` **shadowed** — either every joining query
  carries the stash/restore, or the writer never sets `@timestamp` on lookup
  rows (`detection.detected_at` already holds the detection time) and the
  template stops mapping it. The second is the smaller contract amendment.
- if the probe reports the **owner link lost** — every join `ON event.id` must
  stash/restore `process.entity_id`, since a file-level row can never carry a
  process key. If the link is kept, only the cascade direction needs the
  `event.id` stash.

Either way `join-keys.yml`'s `example_query` should gain the stash/restore (or
the template amendment) — a recommendation for the contract's owner, not a
change this gate makes.

## If it fails

The gate fails a check, names it and prints why. The fallback per check:

**0.1 — version.** Elasticsearch below 9.x: `LOOKUP JOIN` is a technical
preview in 8.18 and absent before; upgrade the stack (`ELASTIC_VERSION` in
`stacks/elastic/.env`). A 9.x other than 9.4.3 runs the gate but the result is
indicative — re-pin and re-run before relying on it.

**1.1 — the streams reject the rows.** Read the item error. A mapping conflict
in the built-in `logs-*-*` template (a CAR field colliding with an
`ecs@mappings` type) means the CAR loader needs its own `logs-car.*-*` index
template layered on top (a `logs-car@custom` component, or a higher-priority
template with the projection's mappings) — the loader's deliverable, not a
design change.

**1.2 — old data dropped or re-stamped.** A count short of 4: an ingest
pipeline on the stream discarded rows — check `index.default_pipeline` on the
backing index and the `logs@custom` pipeline. Rows counted but not `< 2020`: a
pipeline set `@timestamp` to ingest time; the loader must write the evidence
time to `@timestamp` and, if a load time is wanted, to `event.ingested`. Never
re-stamp evidence.

**1.3 — retention present.** A default data-stream retention
(`data_streams.lifecycle.retention.default`) or an ILM policy with a delete
phase would age a case out from under the analyst. Fallback: a `logs-car@custom`
component template that sets `lifecycle: {}` with no `data_retention` (or an
ILM policy without a delete phase) so the CAR streams are exempt — and note the
cluster setting in `stacks/elastic/config/elasticsearch.yml`.

**1.4 — the window query does not hit.** With 1.1–1.3 green the row is there
with its 2019 time, so the query is at fault: check the two `TO_DATETIME`
bounds (UTC), that `process.name` / `process.command_line` are mapped as
keyword/wildcard (a `text`-only mapping breaks `==` — the fallback of 1.1
applies), and the result's error text. If ES|QL itself cannot express a rule of
the set, that rule runs through the Detection Engine's manual run instead (see
proof 1) — the runner path and the Kibana path are interchangeable per rule.

**1.5 — rows returned outside the window.** `@timestamp` was re-stamped after
all (1.2 should have caught it) or the query's window literal is wrong. Fix the
loader / the query; never widen the window to make it pass.

**2.1 / 2.2 — `index.mode: lookup` rejected, or the index is not lookup-mode.**
The cluster predates lookup indices or a higher-priority template claimed the
`car-detections-*` name. Check `GET _index_template` for overlaps (raise the
contract's `priority`) and the version. If lookup indices are genuinely
unavailable, the two fallback branches for the join model are:
(a) an **`ENRICH` policy** on `event.id` (Basic licence; needs `_execute` after
every sweep, so the index is a snapshot, not live), or
(b) the sweep **stamps in place** — an `_update_by_query` that appends the
detection to a `detections` array on the CAR document (a mapping the CAR
template must then carry). (b) keeps the tagged-evidence-line model without any
join; (a) keeps the join with an extra refresh step.

**2.3 — key type mismatch.** `event.id` or `process.entity_id` is not
`keyword` on a CAR stream (the built-in dynamic mapping did not apply, or a
`logs-car@custom` template mapped it otherwise). `LOOKUP JOIN` needs the same
type on both sides: give the CAR streams an explicit template mapping both keys
`keyword` (the 1.1 fallback), reload, re-run.

**2.4 — the direct join flags the wrong set, or fields changed.** A parse
error names the construct (`RENAME … AS`, `LOOKUP JOIN`, `DROP`); a wrong row
set means the join matched on something other than `event.id` — compare with
2.6. `@timestamp` or `process.entity_id` wrong on a flagged line means the
stash/restore itself failed — read the probe's report and take the matching
branch under *Field shadowing*.

**2.5 — the cascade does not reach the owned rows.** The file row's
`process.entity_id` does not equal the process guid (the loader's `owning_guid
-> process.entity_id` projection is wrong), or the lookup rows lack
`process.entity_id`. Both are writer/loader defects, not join defects; the
direct join (2.4) still holds and the cascade can be rebuilt client-side (two
queries) until fixed.

**2.6 — fan-out differs.** More lines than lookup rows means duplicate lookup
documents (the writer must upsert by `<detection.id>:<event.id>`); fewer means
2.4 already failed.

**The probe reports shadowing.** Not a failure — a decision, spelled out under
*Field shadowing*.

## What the gate does not prove

Pushing rules into Kibana and running them through the Detection Engine (phase
2), the native -> ECS ingest pipelines for `logs-dxdfir.*`, the sweep that writes
the lookup index, Fleet, performance at case scale (the fixture is four rows),
or behaviour on any Elasticsearch other than the one it ran against. It proves
the two assumptions the rest is built on, on the pinned stack, with a fixture
small enough to reason about by hand.
