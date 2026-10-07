# The Elastic config tree

The **operator-editable configuration of the analysis stack**, in one place:
what Filebeat ingests, how each evidence type is parsed on the way in
(ingest pipelines — date normalisation, grok, ECS projection), the index
templates behind the `logs-dxdfir.*` data streams, and the Kibana objects
(data views, searches, dashboards). The `dxdfir_stack` role **deploys this
tree verbatim** on every `dx deploy stack` / `dx update stack`: read first,
changed only when a file differs from what the cluster holds.

This tree is *configuration as data*. The role carries no pipeline or
dashboard bodies of its own; edit here, re-converge, done. The path is wired
through the inventory (`dxdfir_elastic_config_dir` in
`ansible/collections/get_sybers.dxdfir/playbooks/group_vars/all.yml`), the
single source of truth every consumer references.

```
elastic/
├── filebeat/filebeat.yml      # the shipper: processed tree → logs-dxdfir.<type>-<ns>
├── pipelines/                 # ES ingest pipelines, one file per pipeline (name = filename)
│   ├── logs-dxdfir-router.json        # default_pipeline: routes on labels.type
│   ├── logs-dxdfir-zeek.json          # per-type parsing lives one level down
│   └── …
├── templates/
│   ├── component/             # component templates (deployed first)
│   └── index/                 # index templates (composed of the above)
└── dashboards/                # Kibana saved objects (*.ndjson), imported on deploy
```

## How a record flows in

1. **Filebeat** ([filebeat/filebeat.yml](filebeat/filebeat.yml)) tails
   `/ingest/*/**/*.json[l]` (the mounted `data_store/processed/` tree),
   parses each line as NDJSON, and dissects the first path segment into
   `labels.type` — `zeek`, `windowlicker`, `daemonhunter`, `anamnesis`,
   `log2timeline`, `detections`, … Every JSON/JSONL file under `processed/`
   ships, except the CAR stores (`byakugan/`, `byakugan-load/` — those land
   ECS-projected in `logs-car.*` via `dx byakugan load`) and the `_`-prefixed
   staging trees.
2. The record lands in the **`logs-dxdfir.<type>-<namespace>`** data stream.
   The [index template](templates/index/logs-dxdfir.json) mirrors the
   built-in `logs-*-*` behaviour (logsdb, ECS dynamic mappings) and adds the
   [`logs-dxdfir@custom`](templates/component/logs-dxdfir@custom.json)
   component: field mappings plus `index.default_pipeline` →
   **`logs-dxdfir-router`**.
3. The [router pipeline](pipelines/logs-dxdfir-router.json) stamps
   `event.ingested` and hands the record to its **per-type pipeline**, which
   owns the parsing: evidence time → `@timestamp` (never re-stamped — the
   dead-box rule the [risk gate](../docs/riskgate.md) enforces for CAR holds
   here too; a record without a usable evidence time keeps the ingest time),
   `event.module` / `event.dataset`, grok over composite strings, and the
   cheap ECS copies (`source.ip`, `host.name`, …). A parse failure never
   drops evidence: the pipeline's `on_failure` indexes the record as-is with
   the error in `labels.pipeline_error`.

## Editing

- **A new evidence type**: it already ships — Filebeat routes any
  `processed/<type>/` into `logs-dxdfir.<type>-*` untouched. To parse it,
  add `pipelines/logs-dxdfir-<type>.json` and a routing entry in
  [the router](pipelines/logs-dxdfir-router.json).
- **Grok**: lives in the per-type pipeline (see the `display_name` grok in
  [logs-dxdfir-log2timeline.json](pipelines/logs-dxdfir-log2timeline.json)
  for the pattern to copy). Test with `_ingest/pipeline/_simulate` before
  deploying.
- **Mappings**: add to the
  [`logs-dxdfir@custom`](templates/component/logs-dxdfir@custom.json)
  component template. Template changes apply to a stream's **next** backing
  index (rollover) — existing indices keep their mappings.
- **Dashboards**: export from Kibana (*Stack Management → Saved Objects*)
  into `dashboards/*.ndjson`. Deploy imports with `overwrite=true`, gated on
  a content hash, so hand-edits in Kibana survive until the tree changes.

Pipeline and template **names are the filenames** (minus `.json`); keep the
`logs-dxdfir-` / `logs-dxdfir@` prefixes so the stack's objects stay
recognisable and never collide with built-ins. `logs-car.*` is deliberately
not configured here: that family is the CAR→ECS projection, owned by the
Byakugan engine's contract (`dx byakugan load`).
