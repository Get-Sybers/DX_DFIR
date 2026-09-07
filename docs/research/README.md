# CAR cross-source linkage & detection — research arc

A running journal of how the pipeline's cross-source join layer was rebuilt on
**real** identifiers instead of the engine's minted synthetic ids. Each step is
grounded in the cross-dataset value hunt under
[`../car-provenance/crosslink/`](../car-provenance/crosslink/) — the read-only
grep/sqlite sweep of `data_store/processed/` that measured which distinctive
values actually converge across artefacts, and which survive only as un-mined
text inside `native`.

## The through-line

CAR's `guid` is *the* cross-source join key — it travels to Elastic as ECS
`event.id` on every object and `process.entity_id` on process rows, and
`LOOKUP JOIN car-detections ON event.id|process.entity_id` is the whole
convergence contract (`detect/rules/car-detections/join-keys.yml`). But the
value hunt found that of **44,327** non-null values across the CAR
`guid`/`owning_guid`/`parent_guid`/`target_guid` columns, **zero** are canonical
`{8-4-4-4-12}` GUIDs — every one is a synthetic id the engine mints itself
(`proc-…`, `file-…`). Every real cross-source key — volume GUID, MachineGuid,
MAC, device serial, IP, domain — was surviving only as lexical text in `native`,
invisible to any join.

These steps promote those real keys to first-class, queryable CAR header columns
and teach the cross-source stage to converge on them.

## Steps

| Step | Backlog | Title | Status |
|---|---|---|---|
| [01](01-linkage-volume-guid.md) | B1 | Volume GUID as a first-class join key | merged (#57, #58/#59) |
| [02](02-linkage-mac.md) | B3 | MAC address from v1 GUIDs | merged (#60) |

## Source material

- [`crosslink/SUMMARY.md`](../car-provenance/crosslink/SUMMARY.md) — the value-hunt synthesis and the B1–B5 backlog these steps draw from.
- [`crosslink/guids.md`](../car-provenance/crosslink/guids.md) — the per-class GUID linkage evidence (real values, counts, data_types).
- [`crosslink/unnormalised-values.yar`](../car-provenance/crosslink/unnormalised-values.yar) — the consolidated YARA ruleset that flags present-but-unnormalised values across future datasets.
