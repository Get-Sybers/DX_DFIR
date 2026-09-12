# The DX_DFIR CAR pipeline — how it works

*Companion docs: [CAR-Relations.md](CAR-Relations.md) (per-object
identity/join/inheritance/limit rules), [CAR-Extraction-Rules.md](CAR-Extraction-Rules.md)
(the extraction principles) and [riskgate.md](riskgate.md) (the Elastic-native
backend: the CAR→ECS projection and the Phase-0 proofs it rests on).*

## 1. What it is

`piiat_mitrecar` (via `get_sybers_dxdfir.mitrecar`) turns each ingested evidence **source** into finished
**MITRE CAR** — every extractable record becomes a CAR **object** performing an
**action** at a **timestamp**, carrying that object's canonical **properties** —
and emits it as **JSON** — one `car_<object>.jsonl` per object, the materialised
CAR every sink reads.

The design is deliberately small and **repeatable**. One recipe, run per source:

```
input source ──▶ artefact map(s) ──▶ normalize ──▶ its own car.db ──▶ enrich
   (a file        (object/action/      (raw row →     (SQLite, one     (self-
    or a dir)      property rules)      CAR event)     table/object)    contained)
                                                                          │
                                                        JSON out ◀────────┘
                                                   car_<object>.jsonl → the backend (CAR→ECS)
```

It is the pipeline-wide application of what shipped in **[PIIAT-Mem](https://github.com/Get-Sybers/PIIAT-Mem) v1.0.0** for
memory: the mapping/inference logic lives in the processor we own, the store is
finished CAR, and the query layer just reads the model instead of re-deriving it.

## 2. The isolation rule — one source, one database

**Each evidence source gets its OWN `car.db`, enriched only within itself.** A
source is a coherent evidence set:

| source | what counts as "the source" |
|---|---|
| Windows event logs (a host) | all `*_EvtxECmd_Output.json` for that host, OR the host's Plaso `winevtx` output |
| Zeek | one capture's per-protocol logs (`conn.json`, `http.json`, …) together |
| log2timeline | one image's `.jsonl` (a container of many parsers, split internally) |
| memory | PIIAT-Mem's finished `car.db` (passed through 1:1) |

No source ever depends on another being present, and nothing is mixed.
Cross-source ("final") enrichment is a **separate, optional end-stage** over the
aggregate — never part of the per-source product (see §9).

Run it:

```
dxdfir build-car                              # batch: build every source under data_store/processed/
dxdfir build-car --rebuild                    # re-derive existing stores too (after a map/coverage change)
dxdfir build-car --in <file-or-dir> --out <dir> [--host NAME] [--artefacts k1,k2]   # one source
# → <dir>/car.db + <dir>/superset.db + <dir>/car_<object>.jsonl (one JSONL per populated object)
```

A source whose `car.db` already exists is left as-is; `--rebuild` re-derives it,
which is required after new maps land or the existing (stale) stores would keep
skipping the newly-covered events. (`dxdfir build-car` fronts the same engine as
`python -m get_sybers_dxdfir.mitrecar`.)

## 3. Components (the vendored `third_party/piiat-mitrecar` submodule)

The engine is the standalone public **[byakugan](https://github.com/Get-Sybers/byakugan)** tool
(formerly PIIAT-MitreCar), vendored as a submodule and driven via its CLI by the thin
`get_sybers_dxdfir/mitrecar.py` lane — exactly the PIIAT-Mem pattern.

**Recursive submodules (required).** The engine reconstructs its object model
LIVE from its OWN pinned submodules (`third_party/car` = the CAR model,
`third_party/attack-datasources` = the ATT&CK data-sources superset + relationship
vocabulary) — nothing is committed as a copy. So the submodule must be initialised
**recursively**: `git submodule update --init --recursive third_party/piiat-mitrecar`.
The `mitrecar.py` lane self-plumbs this (recursive init on first run) and errors
clearly if it can't.

**Two stores per source.** The lane produces, beside each `car.db`: a
`superset.db` (the CAR+ATT&CK superset model + the relationship-instance timeline
linking the car.db rows) and its `car_relationships.jsonl`, plus a `sources.yaml`
manifest declaring what the source yields and how it was derived.

| module | role |
|---|---|
| `piiat_mitrecar/carmodel.py` | the 13 CAR objects, reconstructed live from the `car` submodule |
| `build_data_model.py` | CAR (13) + the CAR+ATT&CK superset (~38) + the relationship catalogue, from the pinned submodules |
| `mappings/` | per-artefact declarative maps (one file per family; auto-discovered; shared helpers in `mappings/_common.py`) |
| `normalize.py` | the marker engine: `normalize(artefact, record) → CAR event`, or `None` if unmapped |
| `adapters/` | format adapters (Plaso winevt(x) → EvtxECmd shape; l2t container split; jump lists) |
| `enrich.py` | the within-source relationship + inheritance cascade (identity, joins, inheritance, dedupe, canonical accounts) |
| `superset.py` | the `superset.db`: superset model + relationship-instance timeline |
| `store.py` | the per-object SQLite CAR store + `export_jsonl()` |
| `readers.py` | input readers: `iter_mapped()` (raw → normalize) and `load_piiat_car()` (memory passthrough) |
| `pipeline.py` | orchestration: route → normalize → enrich → store (car.db + superset.db) → JSON |

## 4. The CAR data model (13 objects)

`car_data_model.json` is a **verified exact match** to `car.mitre.org` — every
object, action, and field (diffed 13/13, 0 missing, 0 extra). The 13 objects:
authentication, driver, email, file, flow, http, module, process, registry,
service, socket, thread, user_session.

The store keeps **one table per object**. Each row = one CAR event: a minimal
header (`timestamp, car_action, guid, owning_guid, link_confidence,
source_artefact, source_host, native`) + that object's MITRE fields. Header
columns beyond MITRE are the deliberate, labelled additions a materialized
multi-source store needs; `parent_guid` is a process-only column (MITRE defines
it only there); `owning_guid` is the one non-MITRE field we add — the definitive
spoke→process link. `native` (JSON) holds evidence with no CAR home — never
faked into a canonical column.

## 5. Artefact coverage (source → CAR objects)

| artefact | map(s) | CAR objects filled |
|---|---|---|
| **Windows event logs** (EvtxECmd *and* Plaso winevtx — same maps) | `evtx_security`, `evtx_security_sessions`, `evtx_process`, `evtx_services`, `evtx_bits`, `evtx_rdp`, `evtx_sysmon` | authentication, user_session, process, service, http (BITS), module, driver, thread, registry, file, flow (Sysmon) |
| **Zeek** | `zeek_conn`, `zeek_http`, `zeek_smtp`, `zeek_files` | flow, http, email, file |
| **Plaso execution** | `plaso_exec_prefetch/winreg/cron` | process |
| **Plaso filesystem + Linux** | `l2t_filestat/mft/usnjrnl/utmp/utmpx/text` | file, user_session |
| **EZ-Tools registry + SRUM** (the Zimmerman lane's output) | `recmd`, `plaso_registry`, `plaso_srum` | registry, flow, process |
| **Memory** (PIIAT-Mem) | passthrough | all 10 memory objects (finished CAR) |

Windows event-log EventIds covered: 4624/4625/4634/4647/4672/4688 (Security),
7045/4697 (service), BITS 59/60, TerminalServices 21/24/25, Sysmon
1/3/5/6/7/8/11/12/13/23. **The same maps serve both EvtxECmd and log2timeline** —
a Plaso record is adapted to the EvtxECmd shape and run through the identical
maps (verified: Plaso-parsed LoneWolf → byte-identical CAR to the EvtxECmd run,
including definitive Sysmon ProcessGuid links).

SRUM and RECmd are now covered: the **Zimmerman lane** (`get_sybers_dxdfir.zimmerman`)
produces the real EZ-tool output — RECmd's batch JSON and, for SRUM, plaso's
`esedb/srum` parse of `SRUDB.dat` (SrumECmd is .NET-only) — which the `recmd`,
`plaso_registry` and `plaso_srum` maps turn into registry / flow / process CAR.

Honest non-coverage: `email` has no live source yet (the only smtp capture is
STARTTLS-encrypted); Zeek dns/ssl/x509/dhcp/ntp/snmp/ocsp/weird/pe have no
dedicated CAR object (flow-detail, routed to `[]` explicitly).

## 6. The mapping engine

A map declares, per artefact (and per *variant* where one artefact splits across
objects): the CAR `object`, `action`, `ts`, the identity that becomes `guid`,
`props` (CAR field → source), `keep`/`native_extract` (native evidence + join
keys), and a `host` (the enrich scope). **Markers** do the small transforms and
nest freely: `first`, `const`, `basename`, `ext`, `lower`, `regex1`,
`domain_of`, `epoch_ts`, `map_value`, `concat`, `exe_path`, `hex_int`, `at`
(positional), `payload`/`userdata` (EvtxECmd shapes), `host_label`.

**Extract maximally; never fake.** Map any record that carries a valid CAR
object/action/property; a canonical field with no honest source is left null
(not a near-miss); a record with no valid CAR action stays raw (e.g. 7040 — the
service object has no `modify` action). Companion events are mapped as their own
entries (e.g. 4672 → authentication with `user_role=administrator`); the cascade
sorts out how they relate.

## 7. The enrichment cascade (`enrich.py`)

Runs once over the whole (per-source) store — data enriching itself, PIIAT-Mem
style. All joins are **scoped per evidence host**, never across hosts.

- **Identity.** `guid` is the reuse-proof identity (memory: the `_EPROCESS`
  offset; Sysmon: `ProcessGuid`; event-record events: `<host>-<channel>-<recordid>`).
- **Owner links, two tiers.** A spoke resolves its owning process: **definitive**
  when it natively carries the owner's guid (Sysmon `ProcessGuid`); else
  **heuristic** by the `(pid, create-time window)` join — the latest process
  created at-or-before the event (a later process can't own an earlier event).
  Marked in `link_confidence`.
- **Parent links.** `ParentProcessGuid` (definitive) → `ppid`-window (heuristic).
- **The LUID cascade.** Authentication ↔ user_session join on `(host, LUID)`;
  definitive except the per-boot well-known LUIDs; a *failed* auth never opens a
  session.
- **Inheritance fills only nulls** — a spoke inherits owner context for fields
  its object has; a natively-extracted value is never overwritten.
- **Dedupe** on `(host, object, guid, action, target_guid, access_level)`,
  most-populated wins; identity-less rows never collapse.
- **Canonical accounts** — well-known SIDs render the same everywhere, without
  overwriting real evidence (e.g. a machine account).

The full per-object identity/join/inheritance/**limit** rules — and the MITRE
wording that grounds each — are in `CAR-Relations.md`.

## 8. Output contract (JSON → the backend)

`store.export_jsonl()` writes one `car_<object>.jsonl` per populated object (plus
`car_relationships.jsonl` for the superset edges) under
`data_store/processed/car/<source>/`; each line is a flat CAR event — the common
header (`timestamp`, `car_action`, `guid`, `owning_guid`, `link_confidence`,
`source_artefact`, `source_host`), `native` as a JSON object, then the object's
CAR fields as strings. That JSON **is** the contract: `dxdfir verify-car` gates
it, and the Elastic-native path projects it to ECS (`guid → event.id`,
`owning_guid → process.entity_id`, … — see [riskgate.md](riskgate.md)) into the
`logs-car.*` data streams. The shape is the engine model's own, so it cannot
drift from what the engine emits.

## 9. Cross-source correlation (deferred)

Correlating across the per-source `car.db`s (memory + disk + network) is an
optional, later aggregate stage that never mixes into the per-source products —
see [CAR-CrossSource.md](CAR-CrossSource.md).
