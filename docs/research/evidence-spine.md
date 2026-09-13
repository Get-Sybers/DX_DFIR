# Evidence Spine — a raw-evidence ownership graph (CASE/UCO)

> A design proposal for the **raw-evidence management layer**: how DX_DFIR tracks
> acquired evidence and its processing, *before* and *separate from* the
> CAR/analysis engine. The numbered arc in this directory
> ([01](01-linkage-volume-guid.md)–[09](09-behaviour-sightings.md)) works the
> **analysis** layer — resolving entities across CAR rows and lining detections
> up against them. This note works the layer *beneath* it: the physical/logical
> structure of the evidence itself.

**Status:** proposal / design — no code yet. A course of action, not a merged step.

---

## 1. The problem

Evidence is tracked in three disconnected ways, and the middle is tracked by
nothing but filesystem convention:

| Stage | Tracked with | Identity used |
|---|---|---|
| **Intake** (`collection.py`) | SQLite `.registry.db` (collections / files / events) + shadow files (`.collection`, `.collection.log`, `.collection.hashes`), SHA-1 | `name + relpath` |
| **Processing** (lanes / roles) | *nothing* — bare files in shared `processed/<source>/<host>/`, discovered by extension-glob + hard-coded output-path contracts in Go | `host` / capture string |
| **CAR** (Byakugan) | per-source `car.db` + `superset.db` + JSONL | `source_artefact` filename |

The intake layer is well built; the gap is **reach** — that discipline stops at
the edge of `raw/`. Concrete failure modes on the raw side:

- **FM-1 — processing throws away the storage structure.** There is no
  host / disk / volume / file model. A file's disk serial and volume offset are
  known at extraction (Plaso even emits them, see §5) but never recorded as
  anything queryable or traversable.
- **FM-2 — outputs are keyed by a host *string*, so cases collide.** Output lands
  in shared `processed/<source>/<host>/` (or `unspecified_host`). Two disks whose
  host is named `DESKTOP-1` overwrite each other — silent contamination.
- **FM-3 — state is reverse-engineered from disk.** The CLI reconstructs what is
  done by globbing output paths; there is no record of which tool version /
  container ran on which evidence, so no resumability, no audit, no
  reproducibility.

**Connection to [Step 01](01-linkage-volume-guid.md).** That step had to *mine*
the volume GUID out of CAR `native` text after the fact, because "the real
cross-source keys survive only as text inside `native`." The raw-evidence layer
records the disk serial, volume GUID and host **authoritatively at acquisition**,
so the spindle identity is *known*, not reverse-engineered downstream. The two
layers stay separate (this one never writes CAR); they simply describe the same
physical world from opposite ends.

---

## 2. Scope — raw data only

A hard boundary. This is the plumbing *under* processing, not the analysis on top
of it.

| In scope | Out of scope |
|---|---|
| Acquisition intake (disks, memory, captures, loose files) | The analysis graph — `car.db`, `superset.db`, the 13 CAR objects |
| Storage structure — disks → volumes, serials, offsets | Detection / ES\|QL, `logs-car.*`, STIX sightings |
| Files — extracted per volume, with hashes | Any link *into* CAR |
| Extraction / processing runs — which tool, on what, producing what | Cross-source correlation (the engine's job — the 01–09 arc) |
| Provenance of processed outputs (the handoff to the engine) | |
| Chain of custody of raw evidence | |

**The clean seam:** this layer's output is the set of *processed artefacts + their
provenance*. The engine (Byakugan) picks those up and builds CAR from them. The
two graphs meet at the artefact and nowhere else — so this layer can be designed,
shipped and reasoned about on its own.

---

## 3. Prior art

The tree we want is exactly:

- **The Sleuth Kit object hierarchy** — every image / volume / file is an object
  with a parent (`tsk_objects.par_obj_id`); lineage *is* the tree.
- **X-Ways evidence objects** — a case holds evidence objects (disk, image,
  memory); each owns a *volume snapshot* of its items, metadata and hashes.
- **CASE/UCO** — the forensics standard that already models all of this
  (Disk / Volume / File facets, `Relationship`, `InvestigativeAction`,
  `ProvenanceRecord`), in the same JSON-LD, object-plus-relationship world as the
  STIX 2.1 the project already emits.

We **adopt CASE/UCO** rather than invent a vocabulary: court-readiness and tool
interchange come free instead of as a future port, and it stays consistent with
the STIX exchange (`stix/`).

---

## 4. The model — an ownership graph

Definitive containment, top to bottom. No heuristics for the spine.

```
host   DESKTOP-1                                    // hostname from SYSTEM hive
  └─ disk   WD-WX21A9…            owns              // serial + image sha256
       └─ volume  Volume{9f3c…}   owns              // offset 0x100000, NTFS
            ├─ file  \Windows\System32\winevt\Logs\Security.evtx   // sha256
            └─ file  \pagefile.sys                                 // state-on-disk (§6)
       extraction  evtxecmd@1.2   produces ▸  windows_logs/DESKTOP-1/Security_EvtxECmd_Output.json
```

Each object is keyed by something **intrinsic**, so the same disk imaged twice is
the same disk and ownership is decidable from the identifiers alone:

| Our object / edge | CASE/UCO construct | Identity anchor |
|---|---|---|
| host | `ObservableObject` (Device) + hostname | hostname |
| disk | `ObservableObject` + **Disk** + **ContentData** facet | serial + image sha256 |
| volume | `ObservableObject` + **Volume / DiskPartition** facet | disk serial + offset |
| file | `ObservableObject` + **File** + **ContentData** facet | volume + path + sha256 |
| extraction | **InvestigativeAction** (`instrument`=Tool, inputs, results) | tool + version + container digest |
| artefact | `ObservableObject` (File) + **ProvenanceRecord** | output path + sha256 |
| owns / contained-in | **Relationship** · `kindOfRelationship: Contained_Within` | — |
| collection | **Investigation / Grouping** (members linked) | case name |

*(Exact facet spellings pinned to the current CASE release at build time; the
shapes are right.)*

**We already emit most of this.** `dev-scripts/plaso/l2t_json_dxdfir.py` stamps
`image_hostname`, `disk_id`, `volume_id` and `volume_offset` on every Plaso event
— that *is* the host ← disk ← volume ← file chain, sitting in the output as
fields. "Mapping what's clear" is mostly lifting those fields into CASE objects
and `Contained_Within` relationships. (Device serials survive extraction thanks
to the REG_BINARY byte-preservation from [Step 04](04-plaso-binary-loss.md).)

### The collection — the invisible string

A collection is one edge type, `member-of` (a CASE `Investigation` / `Grouping`),
attached **only at the top** of a tree. Tag the `host` (or a lone `disk`) into a
case, and every volume, file and artefact beneath it is in that case **by
inheritance down the `owns` edges**. You never tag a file. The string is tied
once and the hierarchy carries it — which is exactly "only where it needs to."
Its one real job is grouping roots that share *no* structural link (a suspect's
laptop disk and a server's pcap); everything derivable from structure is left to
structure.

---

## 5. Keeping CASE compact

CASE's bulk is a serialization choice in the *examples*, not the model. It is
JSON-LD, so how terse it reads is up to the `@context` we ship.

```jsonc
// VERBOSE — example-style CASE (~16 lines/object): prefixes, uuid @ids, nested typed hashes
{ "@context": { "uco-core":"…/core/", "uco-observable":"…/observable/", "uco-types":"…/types/", "kb":"…/kb/" },
  "@graph": [ { "@id":"kb:2b1e8f…-uuid", "@type":"uco-observable:ObservableObject",
    "uco-core:hasFacet": [
      { "@type":"uco-observable:FileFacet", "uco-observable:fileName":"Security.evtx",
        "uco-observable:filePath":"\\Windows\\…\\Security.evtx" },
      { "@type":"uco-observable:ContentDataFacet", "uco-observable:sizeInBytes":20971520,
        "uco-observable:hash":[{ "@type":"uco-types:Hash",
          "uco-types:hashMethod":{"@value":"SHA256"}, "uco-types:hashValue":{"@value":"a1b2c3…"} }] } ] } ] }
```

```jsonc
// LEVER A — compact CASE: shared @context declared once per case, sparse, one object per line.
//           Still valid CASE; expands losslessly.
{"id":"file-a1b2c3d4e5f6","type":"ObservableObject","facets":[
  {"type":"FileFacet","fileName":"Security.evtx","filePath":"\\Windows\\…\\Security.evtx"},
  {"type":"ContentDataFacet","sizeInBytes":20971520,"hash":[{"type":"Hash","hashMethod":"SHA256","hashValue":"a1b2c3…"}]}]}
```

```jsonc
// LEVER B — our bare shape; GENERATED to/from CASE deterministically (optional, if one-liners are wanted)
{"id":"file-a1b2c3d4","type":"File","name":"Security.evtx","path":"\\Windows\\…\\Security.evtx","size":20971520,"sha256":"a1b2c3…"}
```

The levers (all keep it valid CASE):

- **One shared, tuned `@context`** (referenced, not inlined): drop the `uco-*:`
  prefixes, alias `@id`→`id` / `@type`→`type`, set `@vocab` + `@base`.
- **Flat graph, one object per line** — the existing `car_<object>.jsonl` idiom:
  diffable, streamable, git-friendly. Objects link by id, never nest.
- **Short deterministic ids** — `disk-<serial>`, `file-<sha256[:12]>`: readable,
  stable, and "same disk imaged twice = same object" (free dedupe).
- **Sparse; reference, don't inline** — only the facets the spine needs; the Tool
  declared once and referenced.

**The call:** lead with **Lever A** — the stored files *are* CASE (no second
source of truth, no drift) and are already terse. Keep **Lever B** in the back
pocket for bare one-liners; it just makes CASE a *generated* export instead of the
stored form. Either way it expands losslessly to full, valid CASE for court or
interchange. Containment stays a real (one-line) `Relationship` object.

---

## 6. Map what's clear — then extend

It does not need to be perfect. Model the obvious spine now; name the unknowns so
they are a backlog, not a surprise.

**Map now (all definitive — cannot produce a wrong link):**

- host / disk / volume / file as CASE observables + `Contained_Within`
  (already in the Plaso fields);
- disk by serial, volume by offset, file by path + sha256;
- extraction as an `InvestigativeAction` (tool, version, container, inputs,
  outputs); a `ProvenanceRecord` per processed artefact;
- collection = `Investigation` / `Grouping` at the root, inherited down;
- compact CASE serialization (Lever A) from day one.

**Extend later (a new root type or a softer edge on the same spine — none require
redoing the core):**

- memory captures & pcaps as roots — owned by host, not disk→volume→file shaped
  (CASE has facets for these; see the network work in
  [Step 03](03-network-identity.md));
- loose / logical acquisitions — files with no volume parent;
- `pagefile.sys` / `hiberfil.sys` ↔ memory — the state-on-disk bridge
  (`requires` the originating spindle);
- VSS / snapshots, embedded & spanned volumes, RAID across spindles;
- heuristic cross-evidence links — same exe on two hosts, time windows
  (confidence-scored); this is where it hands off to the analysis arc's
  entity convergence.

---

## 7. Decisions locked

| Question | Decision |
|---|---|
| Vocabulary | **Adopt CASE/UCO** — the standard, in the same JSON-LD world as STIX 2.1. |
| Verbosity | **Compact serialization** — Lever A (shared context, flat, one object/line); Lever B available. |
| Identity | **Deterministic CASE ids** from the natural key (`disk-<serial>`, `file-<sha256>`) — stable, free dedupe. |
| Storage | **CASE bundles are the source of truth** (files); a DB, if ever added, is a rebuildable index — never a second copy. Answers the original "half database / half files". |
| Existing code | **Kept.** `collection.py`'s registry becomes the `Investigation` / `Grouping` layer; the graph adds objects beneath it. No rip-and-replace. |

---

## 8. Next step (not yet done)

Turn "map now" into a concrete implementation plan against the real files:

1. the shared compact `@context` (a versioned `dxdfir-case.jsonld`);
2. where objects get written — promote the `disk_id` / `volume_id` /
   `volume_offset` / `image_hostname` fields the Plaso lane already emits into
   CASE observables + `Contained_Within` relationships, and record each lane run
   as an `InvestigativeAction` + `ProvenanceRecord`;
3. the CLI reading the graph (status, lineage, resumability) instead of globbing
   output paths (`go/internal/lanes`);
4. per-case output scoping to close FM-2.

## References

- Current tree: `python/get_sybers_dxdfir/collection.py` (registry + shadows),
  `go/internal/lanes/` (glob-based state),
  `dev-scripts/plaso/l2t_json_dxdfir.py` (emits disk_id / volume_id /
  volume_offset), [`../Dir-Structure.md`](../Dir-Structure.md).
- Companion analysis arc: [`README.md`](README.md),
  [Step 01 — Volume GUID](01-linkage-volume-guid.md),
  [Step 04 — REG_BINARY preservation](04-plaso-binary-loss.md),
  [Step 06 — behaviour timeline / the layer distinction](06-behaviour-timeline.md).
- Standards: CASE/UCO (caseontology.org), The Sleuth Kit database schema,
  X-Ways Forensics volume snapshot.
