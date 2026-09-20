"""Assemble, merge, validate and write the STIX 2.1 bundle; drive the push.

``hit_objects()`` turns detection hits into the object graph — per hit one
``sighting`` of the rule's ``indicator``. The rule body from the rules-as-code
directory IS the indicator's pattern (its language the ``pattern_type``); a
hit whose rule has no body, no ``created`` date, or no file at all is skipped
and counted — never given an invented pattern. ``indicates`` SROs point at
MITRE's own ATT&CK ``attack-pattern`` ids (BP §5.2: the authoritative
objects, referenced rather than copied); the observed host is an ``identity``
in ``where_sighted_refs``; the evidence becomes CONNECTED observations — a
connection's addresses under a ``network-traffic`` root, a file on its own,
each in its own ``observed-data`` (STIX 2.1 §4.14 / BP §5.9). Identical rows
(same run, rule, time, subject, evidence) collapse into one sighting with
``count`` incremented. Every time on an object comes from stable data (the
rule's dates, the observation time), never the export clock, so a re-export
is the same version of the same objects (§3.2 / §3.6).

``merge_objects()`` folds Byakugan's bundles in object-for-object. Byakugan projects
its CAR stores to STIX itself; DX does not re-derive anything, does not touch
ids, and resolves a duplicate id by keeping the newest ``modified`` — nothing
is dropped for being unfamiliar, so a superset of both producers reaches the
exchange.

``validate_bundle()`` is the well-formedness gate: structure = errors,
unresolved references = warnings — except references into MITRE's ATT&CK
repository, which are non-local by design (BP §3.3). It also checks what the
best practices ask of a producer: relationship names and endpoints against
the spec's tables (§5.1, BP §5.12), sighting endpoints (§5.2), no deprecated
``x_`` properties or ``x-`` types (§11, BP §2.3), no marked SCOs (BP §3.5),
dated markings, extension definitions present. ``run_export()`` is the whole
verb: read, assemble, validate, write, optionally push.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass

import yaml

from . import objects as o
from .attack_index import AttackIndex, load_attack_index
from .config import StixConfig
from .hits import Hit, read_hits
from .opencti import OpenCTIClient, Transport

_ID_RE = re.compile(
    r"^([a-z][a-z0-9-]*)--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_RELATIONSHIP_TYPE_RE = re.compile(r"^[a-z0-9-]+$")           # §5.1: lowercase ASCII, digits, hyphen
# SDO / SRO / SMO types whose created + modified are mandatory (§3.2).
_DATED_TYPES = frozenset({
    "attack-pattern", "campaign", "course-of-action", "extension-definition", "grouping", "identity",
    "incident", "indicator", "infrastructure", "intrusion-set", "location", "malware", "malware-analysis",
    "note", "observed-data", "opinion", "relationship", "report", "sighting", "threat-actor", "tool",
    "vulnerability",
})
_REQUIRED = {
    "relationship": ("relationship_type", "source_ref", "target_ref"),
    "sighting": ("sighting_of_ref",),
    "indicator": ("pattern", "pattern_type", "valid_from"),
    "observed-data": ("first_observed", "last_observed", "number_observed", "object_refs"),
    "marking-definition": ("created", "definition_type"),
    "extension-definition": ("created_by_ref", "name", "schema", "version", "extension_types"),
}
# STIX 2.1 §5.1: an SRO relates SDOs / SCOs — never these.
_NOT_ENDPOINTS = frozenset({"relationship", "sighting", "bundle", "marking-definition", "language-content",
                            "extension-definition"})
# The common relationship types (§5.1) any pair of objects may use.
COMMON_RELATIONSHIPS = frozenset({"derived-from", "duplicate-of", "related-to"})
ANY_SCO = "<sco>"
# STIX 2.1 §4 relationship tables: source type -> relationship_type -> allowed target types.
_TABLE = {
    "attack-pattern": {"delivers": {"malware"}, "targets": {"identity", "location", "vulnerability"},
                       "uses": {"malware", "tool"}},
    "campaign": {"attributed-to": {"intrusion-set", "threat-actor"}, "compromises": {"infrastructure"},
                 "originates-from": {"location"}, "targets": {"identity", "location", "vulnerability"},
                 "uses": {"attack-pattern", "infrastructure", "malware", "tool"}},
    "course-of-action": {"investigates": {"indicator"},
                         "mitigates": {"attack-pattern", "indicator", "malware", "tool", "vulnerability"},
                         "remediates": {"malware", "vulnerability"}},
    "identity": {"located-at": {"location"}},
    "indicator": {"indicates": {"attack-pattern", "campaign", "infrastructure", "intrusion-set", "malware",
                                "threat-actor", "tool"},
                  "based-on": {"observed-data"}},
    "infrastructure": {"communicates-with": {"infrastructure", "ipv4-addr", "ipv6-addr", "domain-name", "url"},
                       "consists-of": {"infrastructure", "observed-data", ANY_SCO},
                       "controls": {"infrastructure", "malware"}, "delivers": {"malware"},
                       "has": {"vulnerability"}, "hosts": {"tool", "malware"}, "located-at": {"location"},
                       "uses": {"infrastructure"}},
    "intrusion-set": {"attributed-to": {"threat-actor"}, "compromises": {"infrastructure"},
                      "hosts": {"infrastructure"}, "owns": {"infrastructure"}, "originates-from": {"location"},
                      "targets": {"identity", "location", "vulnerability"},
                      "uses": {"attack-pattern", "infrastructure", "malware", "tool"}},
    "malware": {"authored-by": {"threat-actor", "intrusion-set"}, "beacons-to": {"infrastructure"},
                "exfiltrates-to": {"infrastructure"},
                "communicates-with": {"ipv4-addr", "ipv6-addr", "domain-name", "url"}, "controls": {"malware"},
                "downloads": {"malware", "tool", "file"}, "drops": {"malware", "tool", "file"},
                "exploits": {"vulnerability"}, "originates-from": {"location"},
                "targets": {"identity", "infrastructure", "location", "vulnerability"},
                "uses": {"attack-pattern", "infrastructure", "malware", "tool"}, "variant-of": {"malware"}},
    "malware-analysis": {"characterizes": {"malware"}, "analysis-of": {"malware"},
                         "static-analysis-of": {"malware"}, "dynamic-analysis-of": {"malware"}},
    "threat-actor": {"attributed-to": {"identity"}, "compromises": {"infrastructure"}, "hosts": {"infrastructure"},
                     "owns": {"infrastructure"}, "impersonates": {"identity"}, "located-at": {"location"},
                     "targets": {"identity", "location", "vulnerability"},
                     "uses": {"attack-pattern", "infrastructure", "malware", "tool"}},
    "tool": {"delivers": {"malware"}, "drops": {"malware"}, "has": {"vulnerability"},
             "targets": {"identity", "infrastructure", "location", "vulnerability"}, "uses": {"infrastructure"}},
}
SPEC_RELATIONSHIPS: dict[str, dict[str, frozenset[str]]] = {
    src: {rt: frozenset(targets) for rt, targets in table.items()} for src, table in _TABLE.items()}

UNCASED = "uncased"
# The package's own rules-as-code (detect/rules): the default rules directory.
PACKAGE_RULES_DIR = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir, "detect", "rules"))
# Released STIX references the stable released branch (main), not dev (WIP), so
# exported artifacts don't point consumers at a moving target.
RULE_URL = "https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dxdfir/detect/rules/{id}.yml"
# STIX 2.1 pattern-type-ov (§10.19). The rules' own languages are trust-group
# values beyond it (BP §8.1) — documented in stix/README.md, versioned by
# ``pattern_version`` (the Elastic stack the rule is known to run on).
PATTERN_TYPE_OV = ("stix", "pcre", "sigma", "snort", "suricata", "yara")
TRUST_GROUP_PATTERN_TYPES = ("esql", "eql", "kuery", "lucene")


# ------------------------------------------------------------------- the rules
@dataclass(frozen=True)
class Rule:
    """What the export needs of a rules-as-code file (detect/rules/README.md)."""
    id: str
    name: str
    pattern: str
    pattern_type: str
    created: str                    # STIX timestamp: the rule's authoring date
    modified: str                   # its last material change (>= created)
    severity: str = ""
    status: str = ""
    attack: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    url: str | None = None


RuleSource = Callable[[str], "Rule | None"]


class RulesDir:
    """Rules from a rules-as-code directory: ``<detection id>.yml`` with a
    ``query``, its ``language`` and a ``created`` date supplies the indicator —
    the real rule is the pattern, its language the ``pattern_type``. A stub
    (``query: null``), an undated rule or an unknown id supplies nothing and
    :meth:`reason` says why; the hit is then skipped and counted, never given
    an invented pattern (BP §7.1: a STIX pattern names SCO properties; §2.3:
    no custom SCO types)."""

    def __init__(self, rules_dir: str = PACKAGE_RULES_DIR, rule_url: str | None = RULE_URL):
        self.rules_dir = rules_dir
        self.rule_url = rule_url
        self._cache: dict[str, tuple[Rule | None, str]] = {}

    def _load(self, detection_id: str) -> tuple[Rule | None, str]:
        for ext in (".yml", ".yaml"):
            path = os.path.join(self.rules_dir, detection_id + ext)
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8") as fh:
                try:
                    doc = yaml.safe_load(fh)
                except yaml.YAMLError as e:
                    raise ValueError(f"{path}: invalid YAML: {e}") from e
            if not isinstance(doc, dict):
                raise ValueError(f"{path}: a rule file must be one YAML mapping")
            if not doc.get("query") or not doc.get("language"):
                return None, "stub_rule"
            created = o.stix_timestamp(doc.get("created"))
            if not created:
                return None, "undated_rule"
            modified = o.stix_timestamp(doc.get("updated")) or created
            return Rule(
                id=detection_id, name=str(doc.get("name") or detection_id),
                pattern=str(doc["query"]).strip(), pattern_type=str(doc["language"]).lower(),
                created=created, modified=max(modified, created),
                severity=str(doc.get("severity") or "").lower(), status=str(doc.get("status") or ""),
                attack=tuple(o.technique_ids(doc.get("attack"))),
                tactics=tuple(str(t) for t in (doc.get("tactics") or []) if t),
                url=self.rule_url.format(id=detection_id) if self.rule_url else None), "ok"
        return None, "no_rule"

    def __call__(self, detection_id: str) -> Rule | None:
        if detection_id not in self._cache:
            self._cache[detection_id] = self._load(detection_id)
        return self._cache[detection_id][0]

    def reason(self, detection_id: str) -> str:
        """``ok`` / ``no_rule`` / ``stub_rule`` / ``undated_rule`` for ``detection_id``."""
        self(detection_id)
        return self._cache[detection_id][1]


def rules_source(rules_dir: str | None = None) -> RulesDir:
    """The rules of ``rules_dir`` (default: the package's own detect/rules)."""
    return RulesDir(rules_dir or PACKAGE_RULES_DIR)


# --------------------------------------------------------------- hits -> objects
def observations(hit: Hit, case: str, key: str, put: Callable[[dict], str], created_by: str) -> list[str] | None:
    """The hit's evidence as observed-data objects, ONE per connected SCO graph
    (STIX 2.1 §4.14 / BP §5.9): a connection — its ``network-traffic`` root
    with the two addresses it links through ``src_ref`` / ``dst_ref`` — or a
    lone address, and a file. ``None`` when the hit names none, or has no
    observation time (an observation without a time is not one)."""
    when = hit.timestamp or hit.detected_at
    if not when:
        return None
    refs: list[str] = []
    src, dst = o.ip_address(hit.source_ip), o.ip_address(hit.destination_ip)
    if src and dst:
        protocols = ["ipv6" if dst["type"] == "ipv6-addr" else "ipv4"] + [p for p in (hit.transport, hit.protocol) if p]
        traffic = o.network_traffic(put(src), put(dst), src_port=hit.source_port, dst_port=hit.destination_port,
                                    protocols=protocols)
        graph = [put(traffic), src["id"], dst["id"]]
        refs.append(put(o.observed_data(case, key, "network", graph, when, when, created_by=created_by)))
    elif src or dst:
        refs.append(put(o.observed_data(case, key, "address", [put(src or dst)], when, when, created_by=created_by)))
    f = o.file_observable(hit.file_name, hit.file_hashes)
    if f:
        refs.append(put(o.observed_data(case, key, "file", [put(f)], when, when, created_by=created_by)))
    return refs or None


def hit_objects(hits: Iterable[Hit], *, case_id: str | None = None, producer: str = o.DEFAULT_PRODUCER,
                tlp: str | None = "amber", rules: RuleSource | None = None, attack: AttackIndex | None = None,
                contact: str | None = o.DEFAULT_CONTACT, confidence: int | None = None,
                stack_version: str | None = None) -> tuple[dict[str, dict], dict]:
    """The object graph for ``hits``, keyed by id (insertion-ordered), and a
    report: sightings made, hits skipped by reason, techniques resolved /
    substituted / unresolved against the ATT&CK index."""
    hits = list(hits)
    rules = rules or rules_source()
    attack = attack or load_attack_index()
    case = case_id or next((h.run_id for h in hits if h.run_id), UNCASED)
    marking_ref = o.tlp_marking_ref(tlp) if tlp and str(tlp).lower() not in ("none", "no", "off", "") else None
    objs: dict[str, dict] = {}
    report: dict = {"hits": len(hits), "sightings": 0, "skipped": {},
                    "techniques": {"resolved": {}, "substituted": {}, "unresolved": []}}

    def put(obj: dict) -> str:
        o.mark(obj, marking_ref)
        objs.setdefault(obj["id"], obj)
        return obj["id"]

    def skip(reason: str) -> None:
        report["skipped"][reason] = report["skipped"].get(reason, 0) + 1

    created_by = put(o.producer_identity(producer, contact))
    put(o.extension_definition(created_by))
    for hit in hits:
        rule = rules(hit.detection_id)
        if rule is None:
            reason = getattr(rules, "reason", None)
            skip(reason(hit.detection_id) if callable(reason) else "no_rule")
            continue
        created = hit.detected_at or hit.timestamp
        if not created:
            skip("undated_hit")
            continue
        ind = put(o.indicator(
            rule.id, rule.name, created=rule.created, modified=rule.modified, created_by=created_by,
            pattern=rule.pattern, pattern_type=rule.pattern_type, pattern_version=stack_version,
            description=f"DX_DFIR detection rule '{rule.id}' ({rule.pattern_type})",
            severity=rule.severity, status=rule.status, techniques=rule.attack,
            kill_chain_phases=attack.phases(rule.attack, rule.tactics), rule_url=rule.url, confidence=confidence))
        # the rule's techniques are DECLARED by its author; one only the hit carries
        # (a signature lane's per-hit id) is DERIVED from the evidence
        for tid in dict.fromkeys([*rule.attack, *hit.attack_ids]):
            resolved = attack.resolve(tid)
            if resolved is None:
                if tid not in report["techniques"]["unresolved"]:
                    report["techniques"]["unresolved"].append(tid)
                continue
            report["techniques"]["resolved"][tid] = resolved.technique.id
            if resolved.substituted:
                report["techniques"]["substituted"][tid] = resolved.technique.external_id
            put(o.relationship(ind, resolved.technique.id, "indicates", created=rule.created,
                               modified=rule.modified, created_by=created_by,
                               relationship_class=o.RELATIONSHIP_CLASS_DECLARED if tid in rule.attack
                               else o.RELATIONSHIP_CLASS_DERIVED))
        where = [put(o.host_identity(hit.host, created_by))] if hit.host else None
        key = hit.key()
        sid = o.case_scoped_id("sighting", case, key)
        if sid in objs:
            objs[sid]["count"] = int(objs[sid].get("count", 1)) + 1
            continue
        put(o.sighting(
            case, key, ind, created=created, created_by=created_by,
            first_seen=hit.timestamp, last_seen=hit.timestamp, count=1,
            observed_data_refs=observations(hit, case, key, put, created_by), where_sighted_refs=where,
            description=f"{rule.name} — {hit.entity}" if hit.entity else rule.name, confidence=confidence,
            dx={"case_id": case, "run_id": hit.run_id, "detection_id": hit.detection_id, "severity": hit.severity,
                "source": hit.source, "car_guid": hit.car_guid}))
        report["sightings"] += 1
    return objs, report


def bundle_id(objects: Iterable[dict]) -> str:
    """Deterministic over the object ids: the same content is the same bundle."""
    return o.global_id("bundle", *sorted(obj["id"] for obj in objects))


def make_bundle(objects: dict[str, dict]) -> dict:
    return {"type": "bundle", "id": bundle_id(objects.values()), "objects": list(objects.values())}


def build_bundle(hits: Iterable[Hit], **kw) -> dict:
    """Detection hits -> one STIX 2.1 bundle (see :func:`hit_objects` for ``kw``)."""
    return make_bundle(hit_objects(hits, **kw)[0])


# ------------------------------------------------------------------ pass-through
def load_bundle(path: str) -> dict:
    """A STIX bundle from disk; ``ValueError`` when the file is not one."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or doc.get("type") != "bundle" or not isinstance(doc.get("objects"), list):
        raise ValueError(f"{path} is not a STIX bundle (expected type 'bundle' with 'objects')")
    return doc


def merge_objects(objects: dict[str, dict], incoming: Iterable[dict]) -> dict:
    """Fold ``incoming`` into ``objects`` by id. New ids are added; a duplicate
    keeps the newest ``modified`` (ties keep what is there). Nothing is
    dropped for its type — the exchange carries what both producers emit."""
    counts = {"added": 0, "replaced": 0, "kept": 0, "invalid": 0}
    for obj in incoming:
        if not isinstance(obj, dict) or not isinstance(obj.get("id"), str) or not obj.get("type"):
            counts["invalid"] += 1
            continue
        have = objects.get(obj["id"])
        if have is None:
            objects[obj["id"]] = obj
            counts["added"] += 1
        elif (o.stix_timestamp(obj.get("modified")) or "") > (o.stix_timestamp(have.get("modified")) or ""):
            objects[obj["id"]] = obj
            counts["replaced"] += 1
        else:
            counts["kept"] += 1
    return counts


def assemble(hits: Iterable[Hit], passthrough: Iterable[dict] = (), **kw) -> tuple[dict, dict]:
    """Hits + pass-through bundles -> ``(bundle, report)``."""
    objs, hit_report = hit_objects(hits, **kw)
    report = {"from_hits": len(objs), "hits": hit_report, "merged": []}
    for bundle in passthrough:
        counts = merge_objects(objs, bundle.get("objects") or [])
        counts["bundle_id"] = bundle.get("id")
        report["merged"].append(counts)
    return make_bundle(objs), report


# -------------------------------------------------------------------- validation
def _type_of(ref: str, types: dict[str, str]) -> str:
    return types.get(ref) or ref.split("--", 1)[0]


def _check_relationship(obj: dict, types: dict[str, str], errors: list[str], warnings: list[str]) -> None:
    oid, rt = obj["id"], obj.get("relationship_type")
    src, dst = obj.get("source_ref"), obj.get("target_ref")
    if not isinstance(rt, str) or not isinstance(src, str) or not isinstance(dst, str):
        return                                          # already reported as missing
    st, tt = _type_of(src, types), _type_of(dst, types)
    for label, t in (("source_ref", st), ("target_ref", tt)):
        if t in _NOT_ENDPOINTS:
            errors.append(f"{oid}: {label} is a {t} — an SRO relates SDOs / SCOs only (STIX 2.1 §5.1)")
    if rt in COMMON_RELATIONSHIPS:
        return
    table = SPEC_RELATIONSHIPS.get(st)
    if table is None:
        return                                          # an SCO / a type without a spec table: trust-group names
    targets = table.get(rt)
    if targets is None:
        warnings.append(f"{oid}: {rt!r} is not a relationship type the spec lists for {st} "
                        f"(STIX 2.1 §5.1 SHOULD; BP §5.12: trust groups agree on other names)")
    elif tt not in targets and not (ANY_SCO in targets and tt in o.SCO_TYPES):
        warnings.append(f"{oid}: {st} {rt} {tt} — the spec lists {sorted(t for t in targets if t != ANY_SCO)} "
                        f"as targets (STIX 2.1 §5.1)")


def _check_sighting(obj: dict, types: dict[str, str], errors: list[str]) -> None:
    oid, ref = obj["id"], obj.get("sighting_of_ref")
    if isinstance(ref, str) and (_type_of(ref, types) in o.SCO_TYPES or _type_of(ref, types) in _NOT_ENDPOINTS):
        errors.append(f"{oid}: sighting_of_ref must reference an SDO (STIX 2.1 §5.2)")
    for r in obj.get("observed_data_refs") or []:
        if isinstance(r, str) and _type_of(r, types) != "observed-data":
            errors.append(f"{oid}: observed_data_refs must reference observed-data only (STIX 2.1 §5.2)")
    for r in obj.get("where_sighted_refs") or []:
        if isinstance(r, str) and _type_of(r, types) not in ("identity", "location"):
            errors.append(f"{oid}: where_sighted_refs must reference identity or location only (STIX 2.1 §5.2)")


def validate_bundle(bundle, *, external_ids: Iterable[str] = ()) -> tuple[list[str], list[str]]:
    """``(errors, warnings)``. Errors: not a bundle, bad/duplicate ids, an id
    whose prefix is not its type, a produced object missing what the spec
    requires, an SRO / sighting pointing at what it must not. Warnings: a
    non-2.1 ``spec_version``, references that resolve neither inside the
    bundle nor in a common repository (``external_ids`` — MITRE's ATT&CK
    objects), deprecated custom properties / types, marked SCOs, relationship
    names or targets the spec does not list."""
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        return ["not a STIX bundle (type != 'bundle')"], warnings
    bid = bundle.get("id")
    if not isinstance(bid, str) or not bid.startswith("bundle--") or not _ID_RE.match(bid):
        errors.append(f"bad bundle id {bid!r}")
    objs = bundle.get("objects")
    if not isinstance(objs, list) or not objs:
        errors.append("bundle has no objects")
        return errors, warnings
    ids: set[str] = set()
    types: dict[str, str] = {}
    valid: list[dict] = []
    for i, obj in enumerate(objs):
        if not isinstance(obj, dict):
            errors.append(f"objects[{i}] is not an object")
            continue
        t, oid = obj.get("type"), obj.get("id")
        if not isinstance(t, str) or not t or not isinstance(oid, str) or not _ID_RE.match(oid):
            errors.append(f"objects[{i}] has no valid type/id")
            continue
        if not oid.startswith(f"{t}--"):
            errors.append(f"{oid}: id prefix does not match type {t!r}")
        if oid in ids:
            errors.append(f"{oid}: duplicate id")
        ids.add(oid)
        types[oid] = t
        valid.append(obj)
        if obj.get("spec_version") != o.SPEC_VERSION:
            warnings.append(f"{oid}: spec_version is {obj.get('spec_version')!r}, not '2.1'")
        if t.startswith("x-"):
            warnings.append(f"{oid}: custom object type {t!r} (STIX 2.1 §11.2, deprecated — "
                            f"BP §2.3: define new types with an extension-definition)")
        custom = sorted(k for k in obj if k.startswith("x_"))
        if custom:
            warnings.append(f"{oid}: custom propert{'y' if len(custom) == 1 else 'ies'} {custom} "
                            f"(STIX 2.1 §11.1, deprecated — BP §2.3: use an extension-definition)")
        if t in o.SCO_TYPES and obj.get("object_marking_refs"):
            warnings.append(f"{oid}: a marked SCO (BP §3.5: mark the observed-data, not the observable)")
        if t in _DATED_TYPES:
            for k in ("created", "modified"):
                if not obj.get(k):
                    errors.append(f"{oid}: missing {k}")
        for k in _REQUIRED.get(t, ()):
            if obj.get(k) in (None, "", []):
                errors.append(f"{oid}: missing {k}")
        rt = obj.get("relationship_type")
        if t == "relationship" and isinstance(rt, str) and rt and not _RELATIONSHIP_TYPE_RE.match(rt):
            errors.append(f"{oid}: relationship_type {rt!r} is not lowercase letters, digits and hyphens (STIX 2.1 §5.1)")
    # the spec's own TLP instances resolve everywhere (§7.2.1.4) — never shipped, always known
    known = ids | set(external_ids) | set(o.TLP_MARKING_IDS.values())
    for obj in valid:
        for k, v in obj.items():
            refs = [v] if k.endswith("_ref") and isinstance(v, str) else \
                   [r for r in v if isinstance(r, str)] if k.endswith("_refs") and isinstance(v, list) else []
            for ref in refs:
                if ref not in known:
                    warnings.append(f"{obj['id']}: {k} -> {ref} not in bundle")
        ext = obj.get("extensions")
        if isinstance(ext, dict):
            for eid in ext:
                if isinstance(eid, str) and eid.startswith("extension-definition--") and eid not in known:
                    warnings.append(f"{obj['id']}: extensions -> {eid} not in bundle "
                                    f"(its extension-definition must reach the consumer, BP §2.3)")
        if obj["type"] == "relationship":
            _check_relationship(obj, types, errors, warnings)
        elif obj["type"] == "sighting":
            _check_sighting(obj, types, errors)
    return errors, warnings


def relationship_class(obj: dict) -> str:
    """``declared`` / ``derived`` from an SRO's DX_DFIR extension — or from
    the labels a pass-through producer (Byakugan) set; ``unlabelled`` when
    nobody said."""
    cls = o.extension_of(obj).get("relationship_class")
    if cls in o.RELATIONSHIP_CLASSES:
        return cls
    labels = obj.get("labels") if isinstance(obj.get("labels"), list) else []
    for cls in o.RELATIONSHIP_CLASSES:
        if cls in labels:
            return cls
    return "unlabelled"


def summarise(bundle: dict) -> dict:
    objs = [x for x in bundle.get("objects", []) if isinstance(x, dict)]
    by_type = Counter(str(x.get("type")) for x in objs)
    classes = Counter(relationship_class(x) for x in objs if x.get("type") == "relationship")
    return {"objects": len(objs), "by_type": dict(sorted(by_type.items())),
            "sightings": by_type.get("sighting", 0), "indicators": by_type.get("indicator", 0),
            "relationship_classes": dict(sorted(classes.items()))}


def write_bundle(bundle: dict, path: str, pretty: bool = True) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2 if pretty else None, ensure_ascii=False, default=str)
        fh.write("\n")


# ---------------------------------------------------------------------- the verb
def run_export(cfg: StixConfig, hit_paths: Iterable[str] = (), bundle_paths: Iterable[str] = (),
               *, transport: Transport | None = None) -> tuple[dict, dict]:
    """Read hits + bundles, assemble, validate, write ``cfg.out`` (if set), push
    to OpenCTI (if ``cfg.push``). Returns ``(summary, bundle)``; ``summary["ok"]``
    is False when validation failed (nothing is written or pushed then) or the
    push was refused. ``ValueError`` when there is nothing to export (no
    inputs, or every hit skipped and no bundle passed through), the rules
    directory is missing, or an input is not what it claims to be."""
    summary: dict = {"tool": "stix-export", "config": cfg.redacted(), "inputs": [],
                     "bundle": None, "validation": {"errors": [], "warnings": []},
                     "push": None, "ok": True}
    hits: list[Hit] = []
    for p in hit_paths:
        found, report = read_hits(str(p))
        hits.extend(found)
        summary["inputs"].append(report)
    passthrough: list[dict] = []
    for p in bundle_paths:
        b = load_bundle(str(p))
        passthrough.append(b)
        summary["inputs"].append({"path": str(p), "kind": "bundle", "objects": len(b["objects"])})
    if not hits and not passthrough:
        raise ValueError("nothing to export: no detection hits and no bundles were read")

    rules = rules_source(cfg.rules_dir)
    if not os.path.isdir(rules.rules_dir):
        raise ValueError(f"rules directory not found: {rules.rules_dir} (rules_dir / --rules-dir)")
    attack = load_attack_index(cfg.attack_index)
    bundle, report = assemble(hits, passthrough, case_id=cfg.case_id, producer=cfg.producer, tlp=cfg.tlp,
                              rules=rules, attack=attack, contact=cfg.contact, confidence=cfg.confidence,
                              stack_version=cfg.stack_version)
    summary["hits"] = report["hits"]
    summary["merge"] = report["merged"]
    summary["attack_version"] = attack.attack_version
    if hits and not report["hits"]["sightings"] and not passthrough:
        raise ValueError("nothing to export: every hit was skipped "
                         f"({report['hits']['skipped']}) and no bundle was passed through")
    errors, warnings = validate_bundle(bundle, external_ids=attack.ids)
    summary["validation"] = {"errors": errors, "warnings": warnings}
    summary["summary"] = summarise(bundle)
    summary["bundle_id"] = bundle["id"]
    if errors:
        summary["ok"] = False
        return summary, bundle

    if cfg.out:
        write_bundle(bundle, cfg.out)
        summary["bundle"] = cfg.out
    if cfg.push:
        client = OpenCTIClient(cfg.opencti_url, cfg.opencti_token,
                               connector_id=cfg.opencti_connector_id,
                               transport=transport, timeout=cfg.timeout)
        result = client.push_bundle(bundle)
        summary["push"] = result.as_dict()
        summary["ok"] = result.ok
    return summary, bundle
