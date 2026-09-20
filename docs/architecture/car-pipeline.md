# CAR pipeline

After the [lanes](processing-lanes.md) process evidence, the CAR pipeline **normalises**
every processed source into one common shape — the
[MITRE CAR](https://car.mitre.org/data_model/) data model — so evidence from a PCAP, a
memory image and an event log describe the same entities in the same vocabulary.

The normalisation itself is done by the **external [Byakugan engine](https://github.com/Get-Sybers/byakugan)**,
which runs entirely inside the hardened `get-sybers/byakugan` container — cloned + built
into the image at the `sources.yml` pin (`docker/GoDFIR-toolz/byakugan/Dockerfile`) by `dxdfir
build-docker`, never vendored. DX_DFIR is a thin front over it: one Ansible role,
`dxdfir_byakugan`, with three actions. Each action is one confined `docker run` of the
engine image, built by the shared `dxdfir_lane` skeleton from the image's contract
(`docker/GoDFIR-toolz/byakugan/contract.yml`) — `byakugan build` / `byakugan timeline`
driven by their `BYAKUGAN_<SUBTOOL>_*` variables, the processed evidence mounted
read-only and the `byakugan/` output read-write. DX_DFIR holds **no CAR logic itself**.

```
processed/ ──build──▶ byakugan/<source>/car.db + car_<object>.jsonl ──timeline──▶ timeline.jsonl
                             │
                          verify  (the correctness gate)
```

## Build

```bash
dxdfir build-car [--rebuild]
```

Turns each processed **source** into its **own** CAR store (the isolation rule: one
source, one database). Per source: input → artefact map → normalise → its own `car.db`
(SQLite, one table per CAR object) + `superset.db` (the CAR + ATT&CK superset model and
the relationship-instance edges linking the `car.db` rows) → enrich (within the source
only) → export. `store.export_jsonl()` writes one `car_<object>.jsonl` per populated
object plus `car_relationships.jsonl` under `data_store/processed/byakugan/<source>/`.

By default it batches every source under `data_store/processed/`; a source whose store
already exists is left alone unless you pass `--rebuild`.

The **13 CAR objects**: `authentication`, `driver`, `email`, `file`, `flow`, `http`,
`module`, `process`, `registry`, `service`, `socket`, `thread`, `user_session`.

> Which source field populates each CAR column — and which are honestly-unmapped gaps —
> is documented per object in the Byakugan engine's [CAR provenance ledger](https://github.com/Get-Sybers/byakugan/blob/main/docs/car-provenance/README.md).
> The overview is [CAR-Pipeline.md](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-Pipeline.md); extraction rules in
> [CAR-Extraction-Rules.md](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-Extraction-Rules.md).

## Verify

```bash
dxdfir verify-car
```

The **correctness gate** over the materialised tree — the engine's own `byakugan.verify`,
run inside the image over the tree mounted read-only. It reads what `build-car` wrote and
asserts:

- every exercised object has rows, and key fields are **populated**;
- values are **sane** — IPs are IPs, ports are ports, SIDs are SIDs;
- `car_action` is in that object's **vocabulary** (reconstructed from the engine's own
  model, never hardcoded);
- every row **traces to one artefact** (non-empty `source_artefact`);
- relationship edges reference real endpoints.

An object with no rows is reported *not exercised*. Extraction faithfulness itself is
proven in the [engine's own test suite](https://github.com/Get-Sybers/byakugan); this
gate checks the materialised output. **Run it before you trust the CAR.**

## Timeline

```bash
dxdfir build-timeline data_store/processed/byakugan [--out-dir DIR] [--after ISO] [--before ISO]
```

Unions the **object events** (`car.db` — every populated field plus the `native`
evidence) and the **relationship instances** (`superset.db` — source→verb→target with
confidence/method) into a single timestamp-ordered stream, `timeline.jsonl` — the
behaviour timeline, written beside the stores (or under `--out-dir`). Point it at one
source's car dir, or a parent tree to aggregate every source beneath it. An existing
`timeline.jsonl` is kept unless `--force`. You can also read it live in the
[Timeline tab](../getting-started/the-interface.md#timeline).

## Cross-source linkage

Because every source lands in the same object model, entities converge: the same host,
process GUID, IP or identity seen across a PCAP, a memory image and an event log link up.
How the join keys work is documented in the Byakugan engine's
[CAR-CrossSource.md](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-CrossSource.md) and
[CAR-Relations.md](https://github.com/Get-Sybers/byakugan/blob/main/docs/CAR-Relations.md).

## From CAR to detections

The materialised CAR feeds the [analysis stack](the-stack.md): it's projected to ECS
into `logs-car.*` data streams where ES|QL/EQL rules-as-code flag matching evidence
lines, and `dxdfir stix export` turns detection hits into STIX 2.1 sightings. See
[the stack → detections](the-stack.md#detections-and-stix).
