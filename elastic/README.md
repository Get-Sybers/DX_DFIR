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
│   ├── logs-dxdfir-router.json           # default_pipeline: routes on labels.type
│   ├── logs-dxdfir-windowlicker.json     # a lane PARENT: common work, then dispatch
│   ├── logs-dxdfir-windowlicker-goevtx.json  # a SUBMODULE: one tool's shaping
│   ├── logs-dxdfir-winlog.json           # shared: the Windows Event Log normaliser
│   └── …
├── templates/
│   ├── component/             # component templates: one logs-dxdfir@<lane> model each
│   └── index/                 # one index template per lane (logs-dxdfir-<lane>) + a logs-dxdfir.* fallback
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
   images open with the same event). Zeek's `http.log` and `websocket.log`
   go through their own inputs that nest the record under `zeek_http` /
   `zeek_websocket`: Filebeat writes its own `host.name` over any top-level
   `host`, and that column is the Host header — the zeek pipeline hoists the
   record back and moves it to `url.domain`.
2. The record lands in the **`logs-dxdfir.<type>-<namespace>`** data stream.
   Each lane has its **own index template** (`templates/index/logs-dxdfir-<lane>.json`,
   `priority: 500`, matching `logs-dxdfir.<lane>-*`) that mirrors the built-in
   `logs-*-*` behaviour (logsdb, ECS dynamic mappings) and composes only the
   components that lane needs: the base plus `@settings` (which carries
   `index.default_pipeline` → **`logs-dxdfir-router`** and the stack-wide
   backstops) plus its own `@<lane>` model — and `@winlog`, the shared Windows
   Event Log model, wherever a lane projects onto `winlog.*` (`log2timeline`
   and `windowlicker` normalise EVTX onto it, `detections` via Hayabusa).
   There is no `winlog` stream of its own — it is a shared model, not a lane. A lane's fields are composed **only into its
   own stream**, so a bare per-protocol name (Zeek's `user`, `tls`, `severity`)
   never merges into another lane's mapping and collides with that lane's ECS
   or Suricata objects. The remaining [`logs-dxdfir.json`](templates/index/logs-dxdfir.json)
   (`priority: 200`, matching `logs-dxdfir.*-*`) is the fallback for the streams
   without a dedicated template — `anamnesis` and any brand-new
   `processed/<type>/` evidence — giving them the base plus `@settings` alone.
3. The [router pipeline](pipelines/logs-dxdfir-router.json) stamps
   `event.ingested`, drops Filebeat's `host.name` (the shipper's container,
   never the evidence host; `agent.*` still names the shipper) and hands the
   record to its **lane parent pipeline**, which owns the parsing. A parent
   does the work common to its lane then dispatches to a **submodule
   pipeline** per sub-tool (`logs-dxdfir-windowlicker` → its `goevtx`,
   `gomft`, `goese`, `gojle` submodules; `logs-dxdfir-log2timeline` → its
   `winevtx` submodule); the EVTX submodules (`goevtx`, `winevtx`) normalise
   onto the shared winlog model and hand off to **`logs-dxdfir-winlog`**, so a
   Plaso-parsed event and a goevtx-parsed one land under the same
   `winlog.*` field names. The parsing sets: evidence
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
  add a lane parent `pipelines/logs-dxdfir-<lane>.json` and a routing entry
  in [the router](pipelines/logs-dxdfir-router.json); give a multi-tool lane
  one submodule `pipelines/logs-dxdfir-<lane>-<tool>.json` per tool that
  needs its own shaping, dispatched from the parent. An EVTX source maps
  onto the shared [winlog model](templates/component/logs-dxdfir@winlog.json)
  and calls [logs-dxdfir-winlog](pipelines/logs-dxdfir-winlog.json) rather
  than inventing its own Windows fields.
- **Grok**: lives in the lane/submodule pipeline (see the `display_name`
  grok in
  [logs-dxdfir-log2timeline.json](pipelines/logs-dxdfir-log2timeline.json)
  for the pattern to copy). Test with `_ingest/pipeline/_simulate` before
  deploying.
- **Mappings**: add to the owning lane model
  `templates/component/logs-dxdfir@<lane>.json` (shared Windows fields to
  [`logs-dxdfir@winlog`](templates/component/logs-dxdfir@winlog.json),
  stack-wide backstops to
  [`logs-dxdfir@settings`](templates/component/logs-dxdfir@settings.json)):
  pin any field whose type must not depend on which
  record lands first (Zeek's `id` tuple, the SRUM `AppId`), and map a
  free-form or recursive tree `flattened` (Plaso's `values`, Hayabusa's
  `Details`, journald's `Fields`) — it then costs one mapper whatever its
  keys. A bare name a lane adds must not clash with another lane's — but since
  each lane's model is composed **only into its own stream** (per-lane index
  template), a name only has to be unique within its own lane. A new lane needs
  its own `templates/index/logs-dxdfir-<lane>.json` (copy an existing one;
  `composed_of` the base + `@settings` + the new `@<lane>`, `priority: 500`,
  `index_patterns: ["logs-dxdfir.<lane>-*"]`); a lane that just reuses the base
  (like `anamnesis`) needs none — the `logs-dxdfir.*-*` fallback covers it.
  Template changes apply to a stream's **next** backing index —
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
