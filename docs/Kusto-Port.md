# 🧊 The Kusto emulator — the analysis backend

> **Status: run against a live emulator.** Stages 1-3 (deploy, apply, ingest)
> and the five sourced CAR objects have now been exercised end-to-end on the
> real `kustainer-linux` engine — see
> [docs/Runtime-Validation.md](/docs/Runtime-Validation.md). That run fixed four
> "parsed in review, failed on first contact" defects (reserved-word `network`
> database name, the `0L` literal in `CarCoverage`, the two name parsers, and an
> unmapped-`action` gap in `CarFile`) and resolved the `pid` hex-conversion
> unknown ([issue #14](https://github.com/Get-Sybers/DX_DFIR/issues/14) item 6).
> Plaso was run for real on three `.E01` images; the Zeek and EvtxECmd **engines**
> remain unrun here (egress policy blocks the `zeek/zeek` image and there is no
> standalone `.evtx` in the corpus), so their ingest/mapping/CAR paths were
> proven with format-accurate fixtures. Three sources are still not wired up —
> see [What is not done](#what-is-not-done).
>
> **This began as a port alongside Splunk and is now the SIEM.** The Splunk
> stack was retired; the emulator is the only analysis backend. The
> Splunk-vs-Kusto comparisons below are kept because they explain why each
> design decision was taken.
>
> Everything below is sourced from Microsoft's documentation rather than from
> assumption — see [Sources](#sources). The one time this project designed a
> container control from a search result instead of the vendor's own words, it
> shipped an isolation mechanism that made the UI unreachable.

## What we run on

The **Azure Data Explorer Kusto emulator** (`kustainer`) — the real Kusto query
engine in a Linux container. No Azure, no account, no network once pulled.

```bash
docker run -e ACCEPT_EULA=Y -m 4G -d -p 8080:8080 \
  -t mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
```

Query and management over HTTP; the management endpoint is
`http://localhost:8080/v1/rest/mgmt`, which means the whole port can be driven
by `curl` from shell scripts with no client library.

Against the ADX free cluster it is the better choice for this project by a wide
margin:

| | Emulator | Free cluster |
|:---|:---|:---|
| Storage | Limited only by host capacity | ~100 GB |
| Databases | 10,000 | 10 |
| Tables per database | 10,000 | 100 |
| External tables | To local files | Not supported |
| Network required | No | Yes |

"Limited only by host capacity" and "external tables to local files" are the
two that matter for dead-box forensics.

## Two decisions the docs overturn

### 1. Do **not** persist the database. Re-ingest instead.

The reflex is to copy `deploy-splunk.sh` and mount a volume, because Splunk
keeping no persistent state was this project's worst defect. **The emulator
docs recommend against it:**

> "Data persistence outside containers isn't recommended due to potential
> incompatibility between emulator versions and lack of extent merging"

Two distinct problems. Emulator versions may not read each other's on-disk
format, so pulling a newer image can orphan the data. And with no extent
merging, ingested data accumulates as unmerged shards that are never compacted
— it degrades rather than settling.

This is fine here, and it is the opposite of Splunk's situation, because
**`data_store/processed/` is already the source of truth.** Splunk's fishbucket
mattered because re-ingesting a large case was expensive and duplicated events.
Kusto re-ingest is `.ingest into` from local files: fast, deterministic, and
idempotent by construction if the table is recreated.

So the default is **ephemeral: destroy the container, redeploy, re-ingest.**
`--persist` exists because the install doc documents the mount, but it is
opt-in and carries the caveat above.

> ⚠️ **Trap.** `.create database <name> persist(...)` **fails if the target
> folders already exist.** A persistent redeploy therefore cannot blindly
> re-run database creation — it has to detect an existing database and skip it.
> This is exactly the class of bug that made `deploy-splunk.sh` report success
> having deployed nothing.

### 2. Isolation is not optional here, it is the only control

Splunk at least has authentication. The emulator has **none at all**:

> "Doesn't provide any security features, including: Authentication, Access
> control, Encrypted connections; connection is through an HTTP connection,
> Encryption at rest"

Plaintext HTTP, no auth, no encryption at rest, on a container holding
evidence. The localhost binding is mandatory, not a default to be overridden
casually — `deploy-kusto.sh` requires typing `expose` to bind anywhere else,
because that binding is the only control there is.

## Concept mapping

How each Splunk-era concept was re-expressed — the design contract of the
schema, kept for the reasoning even though the Splunk side is retired.

| Splunk | Kusto | Notes |
|:---|:---|:---|
| Index | **Database** | `host`, `network`, `memory`, `misc`, `mitre` → 5 databases |
| Sourcetype | **Table** | Kusto entity names cannot contain `:`, so a colon-bearing sourcetype like `zeek:conn` → `ZeekConn` |
| `props.conf INDEXED_EXTRACTIONS` | **Ingestion mapping** | JSON ingestion mappings, precreated and referenced |
| `props.conf` FIELDALIAS / EVAL | **Function**, or update policy | See below |
| `transforms.conf` | **Update policy** | Only where a materialised second table is wanted |
| `inputs.conf` monitor stanza | `.ingest into` | No monitoring. Batch, script-driven |
| Data model + eventtype/tag | **Functions** returning the CAR schema | See below |
| SPL | KQL | |

### Why CAR becomes functions, not update policies

An update policy writes a transformed copy into a second table on ingestion.
Its constraint is strict:

> "The update policy function schema and the target table schema must match in
> their column types, and order"

For CAR that is the wrong shape. The nine CAR objects are *views* over the same
underlying rows — a 4688 event is simultaneously a raw `EvtxEcmdJson` row and a
`car_process` row. Materialising each object doubles storage, forces exact
schema lockstep across 123 field definitions, and makes every mapping fix an
ingestion-time change rather than a query-time one.

`.create-or-alter function` gives the same result, costs nothing to iterate on,
and matches how the Splunk-era data model worked: a view, not a second copy. Update policies stay available for the one case they suit — a
genuinely expensive parse worth doing once at ingestion.

### Schema is applied with `.execute database script`

Multiple management commands in one call. Two properties matter:

- `ContinueOnErrors` — default `false`, stops at the first error
- `ThrowOnErrors` — default `false`

It is explicitly **not transactional**: "Script execution is sequential, but
non-transactional, and no rollback is performed upon error." So the docs
recommend, and we will use, **idempotent command forms** — `.create-merge
table`, `.create-or-alter function` — so a re-applied schema converges rather
than failing halfway and leaving a partial state.

### Tables must exist before ingestion

> "This command doesn't modify the schema of the table being ingested into. If
> necessary, the data is 'coerced' into this schema during ingestion."

No schema inference. Every table needs explicit DDL, which means the port has
to decide column types for each source up front — Plaso json_line, Zeek JSON,
EvtxECmd JSON, Velociraptor and Volatility JSON. That is the bulk of Stage 2's work.

One `.ingest into` locator is one file; multiple files go in one command as
multiple locators, or via an external table over the directory.

## Staging

Each stage is independently useful and independently verifiable. Nothing in a
later stage is needed to get value from an earlier one.

| Stage | Deliverable | Gated on |
|:--|:---|:---|
| **1** | ✅ `scripts/deploy-kusto.sh` — container lifecycle, isolation, readiness, both-direction reachability check | — |
| **2** | ✅ `kusto/schema/` — 5 databases, tables, ingestion mappings, applied by `scripts/apply-kusto-schema.sh` | 1 |
| **3** | ✅ `scripts/ingest-kusto.sh` — Plaso, EvtxECmd, Zeek (conn typed + all other logs generic), Volatility 3 and Velociraptor wired | 2 |
| **4** | ✅ `kusto/schema/40-mitre.kql` — **all 9** CAR objects as KQL functions over MITRE's `car_data_model.json` | 3 |
| **5** | ✅ Docs, checks, `THIRD_PARTY_NOTICES.md` entry | 1-4 |

## What is not done

Stated plainly so it is not mistaken for working:

- **CAR coverage is 9 of 9.** `driver`, `module` and `thread` — long empty
  because nothing *dead-box* produces driver loads, image loads or thread
  creation — are now sourced from **Sysmon** (Microsoft-Windows-Sysmon/
  Operational events 6/7/8), which rides the EvtxECmd path into
  `host.EvtxEcmdJson`. Sysmon also enriches `process` (1/5), `flow` (3),
  `registry` (12/13/14) and `file` (11/23). `registry` additionally keeps its
  Velociraptor/RECmd source. `CarCoverage()` returned real rows for all nine on
  the live engine.
- **All ~69 Zeek log types are ingested.** `conn` is typed into `ZeekConn` by
  JSON path (the processor emits `use_json=T`), every other log lands in the
  generic `Zeek` dynamic table via a `{LogType, SourceFile, Record}` wrapper.
- **Deploy/apply/ingest and all nine CAR objects have run against a real
  emulator** — see [docs/Runtime-Validation.md](/docs/Runtime-Validation.md).
  What is *still* unverified: the Zeek/EvtxECmd/Sysmon/Volatility-Windows/
  Velociraptor **engines** producing that input (deterministic fixtures stood in
  for the parts egress policy blocks or the corpus lacks), and a Windows disk
  image through Plaso (only filesystem test images were run, so
  `CarProcess`-from-Plaso is unexercised). The remaining list, ranked by blast
  radius, is [issue #14](https://github.com/Get-Sybers/DX_DFIR/issues/14).

  An earlier version of this document claimed the scripts were "verified"
  against a fake HTTP endpoint. That was an overclaim: the fake returned
  success for everything, so it proved the request shapes and the KQL surviving
  JSON escaping, and validated nothing about semantics. A code review then
  found a dozen real defects the fake could never have surfaced — including
  `kusto_scalar` sending control commands to the query endpoint, which made a
  perfect schema apply report failure every time.

  What IS now tested, behaviourally, in `tests/run-checks.sh`: `kusto_failed`
  against five real response shapes including a partially-failed
  `.execute database script`; and Zeek routing run against JSON fixtures
  (conn.json to the typed table, other logs to the generic table, no
  double-load). The TSV column-order guard it replaced is gone with the TSV
  path — a JSON path mapping cannot shift columns. Everything else remains
  unverified.

- **`pid` conversion is now verified.** `tolong()` accepts a `0x`-prefixed
  string at run time on the live emulator (`tolong("0x1a4")` = 420), so `pid` is
  populated for EvtxECmd 4688/4689 rows. `pid_hex` stays as the always-correct
  raw form because the un-prefixed form (`tolong("1a4")`) is null. See
  [docs/Runtime-Validation.md](/docs/Runtime-Validation.md) and the note in
  `40-mitre.kql`.

### Stage 1 detail

`deploy-kusto.sh` routes its container lifecycle through
`scripts/lib/docker-lifecycle.sh`, which encodes several defects' worth of
hard-won behaviour (much of it paid for on the retired Splunk path):

- refuses to collide with an existing container; polls by **container ID**, not
  name
- detects a container that dies during startup instead of waiting out the clock
- verifies **both directions** — that the container has no useful egress, *and*
  that the endpoint actually answers. Checking only egress is what once shipped
  an unreachable UI
- stops its own background log stream before printing diagnostics
- `--purge` / `--purge-only` distinction

Readiness is a real health check: instead of grepping container logs for a
magic string, poll the management endpoint with `.show version`.

## What this does not change

The processing pipeline is untouched. Plaso, Zeek and EvtxECmd still write to
`data_store/processed/`, and that directory remains the source of truth; the
backend only reads from it. The CAR object model is vendor-neutral — the KQL
functions express it, and `car_data_model.json` (MITRE's own file) stays in
the repo with the check harness pinning the coverage against it.

## Licensing — read before any engagement

The emulator carries obligations this project must record the same way it
records KAPE's:

- **"Provided *as-is*, without any support or warranties"**
- **"generally unsuitable for production workloads"**
- The licence terms prohibit benchmarking
- `ACCEPT_EULA=Y` auto-accepts on your behalf — `deploy-kusto.sh` and the
  README both say so

All of this is recorded in `THIRD_PARTY_NOTICES.md`. Treat commercial use as
an open question, exactly as with KAPE Solo.

## Sources

- [Kusto emulator overview](https://learn.microsoft.com/en-us/azure/data-explorer/kusto-emulator-overview) — capability comparison, ingestion model
- [Kusto emulator limitations](https://github.com/MicrosoftDocs/dataexplorer-docs/blob/main/data-explorer/includes/kusto-emulator-limitations.md) — the nine limitations quoted above
- [Install the Kusto emulator](https://learn.microsoft.com/en-us/azure/data-explorer/kusto-emulator-install) — run commands, volume mount, `.create database ... persist`
- [`.ingest into` command](https://learn.microsoft.com/en-us/kusto/management/data-ingestion/ingest-into-command) — syntax, one-locator-per-file, schema coercion
- [`.execute database script`](https://learn.microsoft.com/en-us/kusto/management/execute-database-script) — non-transactional, idempotent-form recommendation
- [Update policy](https://learn.microsoft.com/en-us/kusto/management/update-policy) — schema-match constraint
- [Ingestion mappings](https://learn.microsoft.com/en-us/kusto/management/mappings) — CSV and JSON mapping forms
