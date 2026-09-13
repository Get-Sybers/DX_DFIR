# DX_DFIR research notes

Design notes and research write-ups that sit behind the pipeline. The raw findings
and per-object provenance catalogues live in
[`../car-provenance/`](../car-provenance/).

## Proposals

Forward-looking design — a course of action, not yet built.

| Note | What it covers |
|------|----------------|
| [Evidence Spine — a raw-evidence ownership graph (CASE/UCO)](evidence-spine.md) | how raw evidence is tracked and passed to processing (host → disk → volume → file → extraction), before and decoupled from the CAR engine |

## Research journeys

Completed arcs — one doc per step — recording how a capability was built.

| Journey | What it delivered |
|---------|-------------------|
| [CAR cross-source linkage & detection](cross-source-linkage/README.md) | the nine-step arc that turned the engine from *"emits CAR objects"* into *"resolves entities across sources and lines detections up against them"* |
