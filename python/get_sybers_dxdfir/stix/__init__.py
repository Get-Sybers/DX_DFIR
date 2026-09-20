"""STIX 2.1 exchange — sightings/indicators out of detections, OpenCTI as the wire.

The engine stays Elastic; this package is the EXCHANGE interface of Byakugan
(decision D4). It does two things and deliberately nothing else:

1. **Detection hits -> STIX.** Every detection firing becomes a ``sighting`` of
   an ``indicator`` — the rule itself, its query as the pattern — linked
   ``indicates`` -> MITRE's own ATT&CK ``attack-pattern`` ids for the
   techniques the rule and the hit carry (:mod:`.attack_index`), with the
   evidence as connected observations (a ``network-traffic`` root and its
   addresses, a file). Hits are read from ``dxdfir detect --jsonl-out`` (the
   ``misc.Detections`` envelope) or from Elastic documents — a Detection
   Engine alert, a query-stamped evidence line, a ``car-detections`` lookup
   row, or a whole ``_search`` response (:mod:`.hits`).
2. **Byakugan bundles pass through.** Byakugan projects its CAR stores to STIX itself
   (SCOs / observed-data / SROs derived from car.db + superset.db + native, both
   relationship classes labelled ``declared`` / ``derived``). DX never re-derives
   them and never imports Byakugan: a Byakugan bundle is merged object-for-object,
   ids untouched, into the same output bundle (:mod:`.export`).

Ids follow D4: content-keyed objects (indicator, identity, relationship,
every SCO) get deterministic GLOBAL ids; observations (sighting,
observed-data) get CASE-scoped ids (:mod:`.objects`). The output follows the
OASIS STIX Best Practices Guide: every time on an object comes from stable
data (never the export clock, so a re-export is the same version), DX_DFIR's
own properties travel in one extension definition, TLP is referenced never
shipped, SCOs are never marked — see ``README.md``.

Output is config-driven (:mod:`.config`): a bundle file and an optional push to
OpenCTI through a thin client whose transport is an interface, so the exchange
is unit-testable without a live platform (:mod:`.opencti`). Endpoint and token
come from the environment / a config file, never from the tree.

The CTI direction runs through the same client (:mod:`.cti`): OpenCTI's STIX
indicators are pulled and copied into the Elastic ``cti-*`` index — atomics
under ECS ``threat.indicator.*`` — for Elastic's own indicator-match rule to
flag evidence against, and the alerts that rule raises go back as sightings of
the platform's indicators. The engine is Elastic's; OpenCTI is the wire.

    dxdfir stix export --hits detections.jsonl --bundle byakugan.json --out bundle.json [--push]
    dxdfir stix pull --out cti.ndjson
    dxdfir stix sightings --alerts alerts.json --out sightings.json [--push]
"""
from .config import StixConfig, load_config
from .export import build_bundle, run_export, validate_bundle
from .hits import Hit, hit_from_document, read_hits
from .opencti import OpenCTIClient, PullResult, PushResult, Transport
from .cti import run_pull, run_sightings, to_cti_docs

__all__ = [
    "Hit", "OpenCTIClient", "PullResult", "PushResult", "StixConfig", "Transport",
    "build_bundle", "hit_from_document", "load_config", "read_hits",
    "run_export", "run_pull", "run_sightings", "to_cti_docs", "validate_bundle",
]
