# CAR cross-source linkage & detection — research journey

This directory records, one doc per step, the arc of work that turned the
PIIAT-MitreCar engine from *"emits CAR objects"* into *"resolves entities across
sources and lines threat detections up against them."* It is the narrative
companion to the raw findings in [`../../car-provenance/`](../../car-provenance/) (the
per-object provenance catalogues and the `crosslink/` value hunt).

## The north star

> A timeline based on **behaviour rather than artefacts** — cascade many
> sources into CAR objects, wind a deterministic STIX-minted **spindle identity**
> onto every row, converge the same entity across sources, and let threat-intel
> detections light up behaviour over that cascaded data.

Two problems stood in the way, and the value hunt named them precisely:

1. **The join key was synthetic-only.** Of 44,327 non-null values across the CAR
   `guid`/`owning_guid`/`parent_guid`/`target_guid` columns, **zero** were
   canonical `{8-4-4-4-12}` GUIDs — the real cross-source keys (volume GUID, MAC,
   MachineGuid, domain↔IP) survived only as text inside `native`. Steps 1–3 lift
   them into first-class, converge-able keys.
2. **Detection was hollow.** The detection lane produced nothing but hayabusa on
   a sorted collection — the lanes weren't wired to the collection and had no
   rulesets. Step 7 fixes the pipeline; Step 8 is the payoff: real IDS/EDR
   detections joined to the resolved CAR data.

## The steps

| # | Step | What it delivers |
|---|------|------------------|
| 1 | [Volume GUID as a first-class join key](01-linkage-volume-guid.md) | the strongest disk key (6 data_types) mined from native + a queryable column |
| 2 | [MAC address from v1 GUIDs](02-linkage-mac.md) | the NIC MAC decoded out of DLT/volume GUID nodes → a device-linkage key |
| 3 | [Network identity: DNS/SSL/x509 → resolved flows](03-network-identity.md) | a bare C2 IP reads as its domain + certificate (the C2 chain, resolved) |
| 4 | [Preserving REG_BINARY bytes in the plaso lane](04-plaso-binary-loss.md) | device serials/MACs survive extraction instead of collapsing to `(N bytes)` |
| 5 | [A YARA ruleset for unnormalised values](05-yara-unnormalised.md) | flags distinctive values the pipeline hasn't yet normalised |
| 6 | [The behaviour timeline (and psort vs CAR)](06-behaviour-timeline.md) | 2.7M-event behaviour timeline over the full LoneWolf disk; the layer distinction |
| 7 | [Wiring the detection lanes into the collection](07-detection-lane-wiring.md) | `process all --fetch` runs suricata/yara/hayabusa on the collection's evidence |
| 8 | [Detection ↔ CAR correlation](08-detection-correlation.md) | suricata + hayabusa alerts joined to the resolved/normalized CAR entities |
| 9 | [Behaviour sightings](09-behaviour-sightings.md) | the join emitted — detections as STIX Sightings of ATT&CK attack-patterns over the spindle observed-data |

## How the pieces compose

```
raw evidence ─▶ per-source maps ─▶ CAR objects (spindle identity)
                                     │
        native linkage keys ────────┤  volume_guid / mac_address / dest_fqdn / cert
        (Steps 1–4)                  │
                                     ▼
                          cross-source convergence  ─▶  one entity, many artefacts
                                     │                    (crosssource.py)
                                     ▼
                          behaviour timeline (Step 6)  ◀── the north-star view
                                     ▲
        threat detections ──────────┘  suricata + hayabusa + yara
        (Steps 5,7,8)                   joined by IP / ProcessGuid / hash / domain
```

## Companion strand — the raw-evidence layer

The arc above (01–09) works the **analysis** layer: resolving entities across CAR
rows and lining detections up against them. A separate design note works the layer
*beneath* it — how raw evidence is tracked and passed to processing, before CAR:

| Doc | What it proposes |
|-----|------------------|
| [Evidence Spine — a raw-evidence ownership graph (CASE/UCO)](../evidence-spine.md) | a compact CASE/UCO graph (host → disk → volume → file → extraction) for the raw-data layer; decoupled from `car.db`/`superset.db`, meeting the analysis graph only at the processed artefact |

It is a proposal (no code yet), and it is where the spindle identity the arc above
*mines out of CAR `native`* would instead be recorded authoritatively at intake.

## Provenance & scope caveat

The processed corpus is **multi-host** — three collections, different machines:

- **`lonewolf`** — the LoneWolf disk image (`DESKTOP-PM6C56D`); disk only. Source
  of the full CAR `car.db` / behaviour timeline (Step 6).
- **`ls24-sample`** — pcaps (incl. the DFIRdump C2 capture), a memory image, a
  VMDK, and a Sysmon `log.evtx` (`DESKTOP-M913391`); the network + evtx detection
  story (Steps 3, 8).
- **`2019-narco`** — a further disk collection.

Cross-source convergence is naturally **host-scoped**: it lights up *within* a
host, so the richest single-host line-up is the `lonewolf` disk (a follow-up),
while `ls24-sample` carries the network + host detections used in Step 8.

## PR ledger

- **Engine (PIIAT-MitreCar):** #57/#58/#59 volume GUID, #60 MAC, #61 DNS + #65
  SSL, #66 x509, #63/#65 timeliner robustness, #54 behaviour layer (prior).
- **DX_DFIR:** #153 plaso byte-preservation, #152/#154 YARA ruleset, #159/#161/#162
  detection-lane wiring, #163 this research journey, the behaviour-sightings bridge
  (`stix/behaviour.py`) + the yara memory-lane renderer fix, plus the submodule pin
  bumps that carried each engine change onto `main`.
