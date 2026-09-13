# Step 09 — Behaviour sightings (detections as Sightings of ATT&CK over the spindle)

> Part of the CAR cross-source linkage & detection research arc — see [README](README.md) for the full map.

**Status:** implemented (`python/get_sybers_dxdfir/stix/behaviour.py`, CLI `dxdfir stix behaviour-sightings`); demonstrated end-to-end on `ls24-sample`.

## The gap

[Step 08](08-detection-correlation.md) proved the correlation *by hand* — a
suricata alert on `100.101.0.42` lines up with the CAR flow that resolves it to
`scoring-c2.berylia.org`; a hayabusa T1059 record lines up with a CAR process.
But nothing *emitted* that join. The engine already projects its **own** CAR
analytics as STIX Sightings of ATT&CK attack-patterns over the spindle
observed-data (`byakugan/stix.py` + `analytics.py`) — but the DX detection
lanes (suricata / hayabusa / yara) were never fused onto that behaviour axis. The
DX exchange's `stix export` sights the rule *indicator* over observed-data minted
from the detection's **own** fields, carrying the CAR guid only as an extension
string — it never anchors to the spindle entity.

The north star wants the other shape: **emit the detection↔CAR-entity joins as
STIX Sightings of the ATT&CK attack-patterns, over the spindle-identified
observed-data — the behaviour timeline as the primary axis.**

## What was built

A bridge — `dxdfir stix behaviour-sightings --car <car.db|tree> --detections
<dir> --case <id>` — that:

1. **Parses the raw lane output.** suricata EVE `alert` events (technique from
   `alert.metadata.mitre_technique_id`), hayabusa timeline (technique from
   `MitreTags`/`OtherTags`, ProcessGuid from `Details.PGUID`), YARA
   memory/disk/file matches.
2. **Joins each to the CAR entity it touches**, against the finished `car.db`
   stores: suricata → the `flow` for the alert's **connection pair** (both
   endpoints), hayabusa → the `process` by ProcessGuid (case-folded, else
   `(host, pid)`), YARA → the `process` by pid or the `file` by hash.
3. **Emits one Sighting per (detection, entity, technique)** whose
   `sighting_of_ref` **is the ATT&CK attack-pattern** — MITRE's authoritative id
   (via the committed `attack_index`), referenced not shipped (BP §5.2) — over an
   `observed-data` **keyed on the matched CAR row's spindle `guid`** (so every
   detector that touches an entity references the *same* observation), with the
   host as `where_sighted_refs`. A flow observation resolves the C2 IP to its
   `dest_fqdn` as a `domain-name` SCO with `resolves_to_refs` — the alert read
   beyond its own source.

It reuses the exchange's object builders, bundle assembly and validation
(`stix/objects.py`, `stix/export.py`), so a behaviour bundle merges
object-for-object with the `stix export` and PIIAT bundles. Nothing is invented:
a detection that names no resolvable technique, or joins no CAR entity, is
counted and skipped — never given a fabricated attack-pattern or entity. Root
pytest **373**, including 8 golden-vector tests for the bridge.

## What we found on `ls24-sample`

Joined the three detection lanes (`data_store/processed/signatures/`) to the
ls24 CAR stores (zeek `flow`, evtx `process`, memory `process`):

- **100 detections, every one joined a CAR entity** — 85 distinct entities
  flagged across the network, evtx and memory sources. The cross-source join is
  total: the pipeline names an entity for every alert.
- **1 Sighting of an ATT&CK attack-pattern:** hayabusa RecordID **5261**
  (`Cmd.EXE Missing Space Characters Execution Anomaly`, the DOSfuscated
  execution) → a **Sighting of `attack-pattern--970a3432…` (T1059.001)** over the
  evtx process's spindle observed-data (the `cmd.exe` file SCO, SHA-256), where
  sighted on **`DESKTOP-M913391`**. The bundle validates with **0 errors, 0
  warnings** (ATT&CK ids resolve as the permitted non-local references).
- **99 joined, but no ATT&CK tag to sight.** The 14 suricata alerts all join the
  **specific C2 connection** `10.27.33.61 ↔ 100.101.0.42` — the flow that
  resolves to `scoring-c2.berylia.org` — but the ET Open rules that fired
  (`ET INFO SSH-2.0-Go…`, `ET SCAN … Masscan`) carry no `mitre_technique_id`, so
  there is nothing to sight; the join is recorded, not invented into a technique.
  The 85 info-level hayabusa records and the YARA memory matches (DetectRaptor —
  e.g. a `DisableAntiSpyware` Defender-tamper indicator in `svchost`) likewise
  join a process without an ATT&CK tag.

The one attack-pattern sighting *is* the north star realised end-to-end on real
data: a threat detection, lit up as a **behaviour** (T1059.001), anchored to the
cross-source-resolved CAR entity rather than to the evtx record it came from.

## What it enables

The bundle is the substrate for the **generative** half of the project. Each
Sighting is a behaviour observed over the cascade; the shapes these sightings
take — a technique over a spindle entity with its resolved network/host/memory
context — are exactly what new CAR analytics should be **generated into**,
codified against the broader mapped data sources rather than the ones MITRE's
stock analytics assume.

## Follow-ups

- **A technique-sparse corpus.** Only 1 of the 100 ls24 detections named a
  resolvable ATT&CK technique. Richer sightings need either ATT&CK-tagged
  rulesets (ET Open PRO / Sigma with `tags`) or the engine's own CAR analytics
  feeding the same bridge — both slot in without a shape change.
- **The `lonewolf` disk line-up.** This run is `ls24-sample` (network + evtx +
  memory). The single-host `lonewolf` disk line-up ([Step 06](06-behaviour-timeline.md))
  needs a **mount-enabled host** (`/dev/fuse`) so hayabusa image-EVTX extraction
  and yara-on-disk can run against its `car.db`; the bridge itself is ready for
  it unchanged.
- **Joined-but-untagged detections.** The 99 joins are real cross-source links
  that today produce only a report count; emitting them as evidence (observed
  behaviour without an attack-pattern) is a candidate extension.
