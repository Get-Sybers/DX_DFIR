"""MITRE ATT&CK technique ids -> the AUTHORITATIVE ``attack-pattern`` ids.

STIX Best Practices §5.2: "STIX content that references ATT&CK or CAPEC should
leverage the authoritative Attack Pattern objects", and §2.2 (common object
repositories): MITRE publishes ATT&CK as STIX 2.1, so "only identifier
references need to be shared". A STIX exporter therefore never mints an
``attack-pattern`` of its own: an ``indicates`` relationship targets MITRE's
object id for the technique, and the object itself stays where it lives (the
consumer's ATT&CK import — OpenCTI's MITRE connector — holds an exact copy).

The pipeline runs offline, so a compact index of that bundle is committed
beside this module (``data/attack-index.json``): technique external id ->
attack-pattern id, name, kill-chain phases and revocation; tactic id -> phase
name (for ``kill_chain_phases``). Its deploy-side consumer is
:mod:`.car_detections` (technique names and ``threat.tactic.*`` for the
lookup rows); the STIX/CTI exchange keeps its own copy in the Byakugan
engine (``byakugan.exchange``). Regenerate this one from a downloaded
bundle::

    python -m get_sybers_dxdfir.detect.attack_index enterprise-attack.json

``dxdfir stamp-detections --attack-index`` points a run at another index, or
straight at an ATT&CK STIX bundle (told apart by its ``type``).

A rule that names a REVOKED technique resolves to the replacement MITRE points
at (the ``revoked-by`` relationship, as ATT&CK's own tooling does); the
substitution is reported. An unknown id resolves to nothing — no object is
invented for it, the summary counts it.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INDEX_PATH = os.path.join(_HERE, "data", "attack-index.json")
DEFAULT_SOURCE = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
                  "enterprise-attack/enterprise-attack.json")
KILL_CHAIN_NAME = "mitre-attack"        # the kill chain name ATT&CK's own objects use
INDEX_FORMAT = 1


@dataclass(frozen=True)
class Technique:
    external_id: str                    # T1070.001
    id: str                             # attack-pattern--<MITRE's uuid>
    name: str
    phases: tuple[str, ...]             # kill-chain phase names (tactic shortnames)
    revoked: bool = False
    deprecated: bool = False
    revoked_by: str | None = None       # external id of the replacement, when revoked


@dataclass(frozen=True)
class Resolved:
    technique: Technique
    requested: str                      # the id the rule named (differs when a revoked id was followed)

    @property
    def substituted(self) -> bool:
        return self.requested != self.technique.external_id


def external_id(obj: dict) -> str | None:
    """The ATT&CK id of a MITRE object (its ``mitre-attack`` external reference)."""
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == KILL_CHAIN_NAME and ref.get("external_id"):
            return str(ref["external_id"])
    return None


# ----------------------------------------------------------------------- build
def build_index(bundle: dict, source: str = DEFAULT_SOURCE) -> dict:
    """The index document for an ATT&CK STIX bundle (deterministic: the same
    bundle always yields the same document)."""
    objs = [o for o in bundle.get("objects") or [] if isinstance(o, dict)]
    by_id = {o["id"]: o for o in objs if isinstance(o.get("id"), str)}
    revoked_by: dict[str, str] = {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            if isinstance(o.get("source_ref"), str) and isinstance(o.get("target_ref"), str):
                revoked_by[o["source_ref"]] = o["target_ref"]
    techniques: dict[str, dict] = {}
    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        tid = external_id(o)
        if not tid:
            continue
        phases = sorted({str(p["phase_name"]) for p in o.get("kill_chain_phases") or []
                         if isinstance(p, dict) and p.get("kill_chain_name") == KILL_CHAIN_NAME and p.get("phase_name")})
        entry: dict = {"id": o["id"], "name": str(o.get("name") or tid), "phases": phases}
        if o.get("revoked"):
            entry["revoked"] = True
        if o.get("x_mitre_deprecated"):
            entry["deprecated"] = True
        replacement = by_id.get(revoked_by.get(o["id"], ""))
        if replacement is not None and external_id(replacement):
            entry["revoked_by"] = external_id(replacement)
        have = techniques.get(tid)
        # one id, one entry: a live object wins over a revoked/deprecated one
        if have is None or (not entry.get("revoked") and not entry.get("deprecated")
                            and (have.get("revoked") or have.get("deprecated"))):
            techniques[tid] = entry
    tactics: dict[str, dict] = {}
    for o in objs:
        if o.get("type") != "x-mitre-tactic":
            continue
        tid = external_id(o)
        if tid and o.get("x_mitre_shortname"):
            tactics[tid] = {"id": o["id"], "name": str(o.get("name") or tid), "phase": str(o["x_mitre_shortname"])}
    collection = next((o for o in objs if o.get("type") == "x-mitre-collection"), {})
    return {"format": INDEX_FORMAT, "source": source,
            "collection": collection.get("name"), "attack_version": collection.get("x_mitre_version"),
            "modified": collection.get("modified"),
            "tactics": dict(sorted(tactics.items())), "techniques": dict(sorted(techniques.items()))}


def dumps_index(index: dict) -> str:
    """One technique / tactic per line, so a regeneration diffs by technique."""
    def block(name: str) -> str:
        rows = [f'  {json.dumps(k)}: {json.dumps(v, ensure_ascii=False, separators=(", ", ": "))}'
                for k, v in index[name].items()]
        return f' "{name}": {{\n' + ",\n".join(rows) + "\n }"
    head = [f' {json.dumps(k)}: {json.dumps(index[k], ensure_ascii=False)}'
            for k in ("format", "source", "collection", "attack_version", "modified")]
    return "{\n" + ",\n".join(head + [block("tactics"), block("techniques")]) + "\n}\n"


def validate_index(doc) -> None:
    """The committed index (or one an operator points at) must be one this
    module can read: ``ValueError`` otherwise, naming what is wrong."""
    if not isinstance(doc, dict) or not isinstance(doc.get("techniques"), dict) or not doc["techniques"]:
        raise ValueError("attack index: must be a mapping with a non-empty 'techniques' mapping")
    if doc.get("format") != INDEX_FORMAT:
        raise ValueError(f"attack index: format {doc.get('format')!r} is not {INDEX_FORMAT}")
    for tid, e in doc["techniques"].items():
        if not isinstance(e, dict) or not isinstance(e.get("id"), str) or not e["id"].startswith("attack-pattern--") \
                or not isinstance(e.get("name"), str) or not isinstance(e.get("phases"), list):
            raise ValueError(f"attack index: technique {tid!r} needs id (attack-pattern--...), name, phases")
    for tid, e in (doc.get("tactics") or {}).items():
        if not isinstance(e, dict) or not isinstance(e.get("phase"), str) or not e["phase"]:
            raise ValueError(f"attack index: tactic {tid!r} needs a phase name")


# ----------------------------------------------------------------------- lookup
class AttackIndex:
    def __init__(self, doc: dict, path: str | None = None):
        validate_index(doc)
        self.path = path
        self.attack_version: str | None = doc.get("attack_version")
        self.techniques: dict[str, Technique] = {
            tid: Technique(tid, e["id"], e["name"], tuple(e.get("phases") or ()),
                           bool(e.get("revoked")), bool(e.get("deprecated")), e.get("revoked_by"))
            for tid, e in doc["techniques"].items()}
        self.tactics: dict[str, str] = {tid: str(e["phase"]) for tid, e in (doc.get("tactics") or {}).items()}
        self.ids: frozenset[str] = frozenset(t.id for t in self.techniques.values())

    def resolve(self, technique_id: str) -> Resolved | None:
        """The authoritative attack-pattern for ``technique_id``; a revoked
        technique follows ``revoked-by`` to its replacement; unknown -> None."""
        t = self.techniques.get(technique_id)
        seen: set[str] = set()
        while t is not None and t.revoked and t.revoked_by and t.external_id not in seen:
            seen.add(t.external_id)
            replacement = self.techniques.get(t.revoked_by)
            if replacement is None:
                break
            t = replacement
        return Resolved(t, technique_id) if t is not None else None

    def phases(self, technique_ids: Iterable[str], tactic_ids: Iterable[str] = ()) -> list[dict]:
        """``kill_chain_phases`` for techniques (their ATT&CK tactics) plus any
        explicit tactic ids — de-duplicated, sorted, in the spec's shape."""
        names: set[str] = set()
        for tid in technique_ids:
            r = self.resolve(tid)
            if r is not None:
                names.update(r.technique.phases)
        for ta in tactic_ids:
            phase = self.tactics.get(ta)
            if phase:
                names.add(phase)
        return [{"kill_chain_name": KILL_CHAIN_NAME, "phase_name": n} for n in sorted(names)]


@functools.lru_cache(maxsize=8)
def load_attack_index(path: str | None = None) -> AttackIndex:
    """The committed index, or ``path``: an index document or an ATT&CK STIX
    bundle (indexed on the fly). Cached per path — the index is read-only."""
    path = path or DEFAULT_INDEX_PATH
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and doc.get("type") == "bundle":
        doc = build_index(doc, source=os.path.abspath(path))
    return AttackIndex(doc, path)


# ------------------------------------------------------------------------ main
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m get_sybers_dxdfir.detect.attack_index",
                                 description="Regenerate the committed ATT&CK technique index from a MITRE STIX bundle.")
    ap.add_argument("bundle", help="enterprise-attack.json (MITRE attack-stix-data / mitre/cti)")
    ap.add_argument("-o", "--out", default=DEFAULT_INDEX_PATH, help=f"where to write (default: {DEFAULT_INDEX_PATH})")
    ap.add_argument("--source", default=DEFAULT_SOURCE, help="recorded as the index's provenance")
    args = ap.parse_args(argv)
    with open(args.bundle, encoding="utf-8") as fh:
        bundle = json.load(fh)
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        print(f"{args.bundle}: not a STIX bundle", file=sys.stderr)
        return 2
    index = build_index(bundle, args.source)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(dumps_index(index))
    print(f"{args.out}: {len(index['techniques'])} techniques, {len(index['tactics'])} tactics, "
          f"ATT&CK {index.get('attack_version')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
