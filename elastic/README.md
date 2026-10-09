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
    └── malcolm/               # a Kibana SPACE: space.json + its own *.ndjson (see dashboards/malcolm/README.md)
```

## How a record flows in

1. **Filebeat** ([filebeat/filebeat.yml](filebeat/filebeat.yml)) tails
   `/ingest/*/**/*.json[l]` (the mounted `data_store/processed/` tree),
   parses each line as NDJSON, and dissects the first path segment into
   `labels.type` — `zeek`, `windowlicker`, `daemonhunter`, `anamnesis`,
   `log2timeline`, `detections`, … Every JSON/JSONL file under `processed/`
   ships, except the CAR stores (`byakugan/`, `byakugan-load/` — those land
   ECS-projected in `logs-car.*` via `dx byakugan load`), the `_`-prefixed
   staging trees and the lanes' run summaries. Files are identified by
   inode, not by a content fingerprint (two Plaso timelines of different
   images open with the same event). Zeek's `http.log` alone goes through
   a second input that nests the record under `zeek_http`: Filebeat writes
   its own `host.name` over any top-level `host`, and that column is the
   HTTP Host header.
2. The record lands in the **`logs-dxdfir.<type>-<namespace>`** data stream.
   The [index template](templates/index/logs-dxdfir.json) mirrors the
   built-in `logs-*-*` behaviour (logsdb, ECS dynamic mappings) and adds the
   [`logs-dxdfir@custom`](templates/component/logs-dxdfir@custom.json)
   component: field mappings plus `index.default_pipeline` →
   **`logs-dxdfir-router`**.
3. The [router pipeline](pipelines/logs-dxdfir-router.json) stamps
   `event.ingested`, drops Filebeat's `host.name` (the shipper's container,
   never the evidence host; `agent.*` still names the shipper) and hands the
   record to its **per-type pipeline**, which owns the parsing: evidence
   time → `@timestamp` (never re-stamped — the dead-box rule the
   [risk gate](../docs/riskgate.md) enforces for CAR holds here too; a
   record without a usable evidence time keeps the ingest time),
   `event.module` / `event.dataset`, `labels.case` and `labels.item` (the
   case and the capture/image/dump, from the path), `host.name` from the
   evidence (the GoDFIR envelope, an EVTX `Computer`, Plaso's `hostname`,
   else the image or dump the row came from), grok over composite strings,
   and the cheap ECS copies (`source.ip`, `rule.name`, `message`, …) next
   to the tool's own fields, which stay in place — except a native name
   that collides with an ECS object (Zeek's string `source`, `id`, `host`;
   YARA's `rule`), which moves under the tool's own prefix (`zeek.*`,
   `yara.*`). A parse failure never drops evidence: the pipeline's
   `on_failure` indexes the record as-is with the error in
   `labels.pipeline_error`. A record Elasticsearch rejects (a mapping
   conflict) lands in the stream's **failure store**
   (`logs-dxdfir.<type>-<ns>::failures`), kept 365 days by the index
   template — evidence waiting for a mapping fix and a re-ingest.

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
  component template: pin any field whose type must not depend on which
  record lands first (Zeek's `id` tuple, the SRUM `AppId`), and map a
  free-form or recursive tree `flattened` (Plaso's `values`, Hayabusa's
  `Details`, journald's `Fields`) — it then costs one mapper whatever its
  keys. Template changes apply to a stream's **next** backing index —
  existing indices keep their mappings. Deploy rolls over every existing
  `logs-dxdfir.*` stream when the component template changed, and once
  when a stream's write index is not yet on the router pipeline, so the
  change applies from the next document on. Documents already indexed keep
  what they were indexed with; to replay them (and the failure stores) run
  the deploy with `dxdfir_stack_reingest: true` — it stops Filebeat, deletes
  the `logs-dxdfir.*` streams and the shipper's registry, and Filebeat
  reads the whole tree again (the `dxdfir_stack` role README).
- **Dashboards**: export from Kibana (*Stack Management → Saved Objects*)
  into `dashboards/*.ndjson`. Deploy imports with `overwrite=true`, gated on
  a content hash, so hand-edits in Kibana survive until the tree changes.
- **A Kibana space**: a directory `dashboards/<id>/` holding `space.json`
  (the space's id, name, initials, colour and disabled features, as Kibana's
  spaces API takes them) and that space's saved objects as `*.ndjson`. Deploy
  creates the space when missing, updates it when a field differs, and
  imports the directory's objects into it the same way as the default
  space's, gated on their own content hash. The [`malcolm`](dashboards/malcolm/README.md)
  space, 36 dashboards derived from cisagov/Malcolm over the Zeek and
  Suricata streams, is one.

Pipeline and template **names are the filenames** (minus `.json`); keep the
`logs-dxdfir-` / `logs-dxdfir@` prefixes so the stack's objects stay
recognisable and never collide with built-ins. `logs-car.*` is deliberately
not configured here: that family is the CAR→ECS projection, owned by the
Byakugan engine's contract (`dx byakugan load`).
