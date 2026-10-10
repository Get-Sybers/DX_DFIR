# Enrich policies

Match-enrich policies that back the `enrich` processors in the winlog derived
layer — the Windows Event Log lookup tables that have a clean ECS home, held as
Elasticsearch enrich. One policy per `*.policy.json`; its source rows are the
sibling `*.ndjson`.

| policy | source index | key | enriches | fills |
|---|---|---|---|---|
| `windows-signature` | `logs-dxdfir-enrich-windows-signature` | `signature_id` (= `winlog.event_id`) | `signature`, `action`, `result`, `category_string` | ECS `message` |

(The failed-logon `event.reason` is **not** an enrich policy: its lookup was a
20×20 Status×Sub_Status product of just 20 base phrases, so it is composed
inline in `logs-dxdfir-winlog` from a 20-entry code→phrase map —
`phrase[Status] + " " + phrase[SubStatus]`.)

## Deploy contract (ordering matters)

An `enrich` processor **fails pipeline creation if its policy does not yet
exist**, so the `dxdfir_stack` deploy must, for each policy here, do this
**before** it puts the `logs-dxdfir-*` pipelines:

1. Create the source index (`logs-dxdfir-enrich-<name>`) and bulk-load
   `<name>.ndjson` into it.
2. `PUT _enrich/policy/<name>` with the body in `<name>.policy.json`.
3. `POST _enrich/policy/<name>/_execute` to build the enrich index.

On a refresh of a lookup table: replace the `<name>.ndjson` rows, reload them,
re-execute the policy (it builds a new backing index and atomically repoints),
and the pipelines pick it up with no change. Each ndjson is one JSON doc per
row, first row wins per key.

## Not projected to ECS

Some Windows Event Log lookups have **no clean ECS field**, so they are
deliberately not enriched into ECS (that would mean inventing field names): the
privilege names (for 4672/4673/4674) and the category/task-category strings.
Their raw inputs stay in `winlog.*` (`winlog.data.PrivilegeList`, `winlog.task`,
…). The natural home, if wanted, is a native `winlog.*` field rather than ECS —
a decision left open.
