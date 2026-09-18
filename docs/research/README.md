# DX_DFIR research notes

Design notes and research write-ups that sit behind the pipeline. The CAR
property-provenance catalogues and the cross-source-linkage arc are owned by the
[Byakugan](https://github.com/Get-Sybers/byakugan) engine (which owns the CAR
model and extraction) — see its
[car-provenance ledger](https://github.com/Get-Sybers/byakugan/blob/main/docs/car-provenance/README.md).

## Proposals

Forward-looking design — a course of action, not yet built.

| Note | What it covers |
|------|----------------|
| [Evidence Spine — a raw-evidence ownership graph (CASE/UCO)](evidence-spine.md) | how raw evidence is tracked and passed to processing (host → disk → volume → file → extraction), before and decoupled from the CAR engine |

## Research journeys

Completed arcs — one doc per step — recording how a capability was built.

| Journey | What it delivered |
|---------|-------------------|
| [CAR cross-source linkage & detection](https://github.com/Get-Sybers/byakugan/blob/main/docs/research/cross-source-linkage/README.md) — in the [Byakugan](https://github.com/Get-Sybers/byakugan) engine repo | the nine-step arc that turned the engine from *"emits CAR objects"* into *"resolves entities across sources and lines detections up against them"* |
