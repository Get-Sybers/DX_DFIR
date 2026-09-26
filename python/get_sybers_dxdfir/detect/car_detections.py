"""The car-detections lookup-index writer — Byakugan's behaviour hits, stamped.

``detect/rules/README.md`` says it plainly: "the rules are the specification,
not the pipelines" — the Elastic Detection Engine does not run any of this
repo's ES|QL/EQL rules yet, so ``car-detections`` (``detect/rules/car-detections/``)
has had a contract (``join-keys.yml``, ``car-detections.index-template.json``)
but no rows. This module gives it a first, working writer: it reads what
Byakugan's own ``--stix`` export already computed OFFLINE — the behaviour
layer (``analytics.py``'s runnable MITRE CAR analytics run back over the
finished CAR, STIX ``sighting`` objects in each source's
``stix_bundle.json``, see ``byakugan/stix.py`` "the behaviour layer") — and
projects each hit into one ``car-detections`` document, so
``FROM logs-car.*-* | LOOKUP JOIN car-detections ON event.id`` has something
real to join against today, independent of when the Detection Engine sweep
(``join-keys.yml``'s own ``writers`` block — reads ``.alerts-security.alerts-*``,
still future work, phase 2) lands.

INPUT. A byakugan output tree (default ``data_store/processed/byakugan``,
matching ``dxdfir build-car``'s own default): every ``<source>/stix_bundle.json``
under it, found the same way the engine's exchange (``byakugan.exchange``)
walks a tree for materialised CAR source directories. Nothing here imports
Byakugan or
re-derives what it already computed (D4) — this module only reads the bundle
Byakugan wrote.

MAPPING. A STIX ``sighting`` (``byakugan/stix.py``'s ``_sighting()``) already
carries the CAR guid as ``x_car_event_id`` and the analytic's ATT&CK coverage
as ``x_car_techniques``; its ``sighting_of_ref`` resolves the analytic's
``indicator`` (id, name); its ``observed_data_refs[0]``, when the row's owning
process resolved, carries ``x_car_process_entity_id`` (module/thread/file/
socket rows carry their OWNING process's guid there via ``owning_guid`` — the
same cascade ``join-keys.yml``'s own note describes). ATT&CK technique NAMES
and tactic id/name come from this repo's own committed, offline index
(:mod:`.attack_index`) — Byakugan's bundle never carries a technique's
human name (its ``attack-pattern.name`` is the bare id; see
``byakugan/stix.py``'s ``_attack_pattern_obj``), so this is genuine enrichment,
not a second copy of anything Byakugan already emits.

TWO STAMPED_FIELDS THIS BUNDLE CANNOT HONESTLY SUPPLY. MITRE CAR analytics
carry no severity/risk-scoring concept (unlike this repo's own rules-as-code
YAML, which declares one) — check ``byakugan/stix.py``'s ``_indicator_obj``:
it stamps id/name/object/action, nothing else, and it is right not to invent
one. ``detection.severity`` and ``event.risk_score`` are therefore never
written here (never a fabricated grade), per the ``honest nulls omitted``
instruction and the exchange's own rule (``byakugan.exchange.behaviour``:
"never given an invented attack-pattern or a fabricated entity"). A future
sweep writer, reading real Detection Engine alerts with real ``rule.severity``,
can fill them; this one cannot, and says so instead of guessing.

WHY NEVER ``@timestamp``. ``docs/riskgate.md``'s "Field shadowing" section
works through exactly this hazard: ``LOOKUP JOIN`` replaces any source field
the lookup index also maps, and ``@timestamp`` is one — a lookup row's
detection time would silently overwrite the CAR row's own evidence time on
every naive join ("the flagged evidence line reports 2026, not 2019: the
evidence time is silently overwritten, the very failure the gate exists to
catch"). Its own resolution names two branches: every joining query
stash/restores the field, or "the writer never sets ``@timestamp`` on lookup
rows (``detection.detected_at`` already holds the detection time) ... **the
second is the smaller contract amendment**". This writer takes that branch:
it never emits ``@timestamp`` (the template still maps it — dynamic:strict
only forbids a field the mapping does not know, never a mapped field a
document happens to omit — so this is not a template change, just a writer
that leaves one optional field alone). The riskgate fixture
(``.github/tests/elastic-riskgate/fixtures/car-detections.ndjson``) DOES set
``@timestamp``; that fixture's job is to make the naive-join probe observable
in the first place, not to prescribe what a real writer emits.

INDEX, NOT CREATE (UPSERT). ``join-keys.yml`` itself: "a sweep step ... reads
the Detection Engine's alerts ... and **upserts** one document per (detection,
guid)". ``docs/riskgate.md`` check 2.6: "More lines than lookup rows means
duplicate lookup documents (**the writer must upsert** by
``<detection.id>:<event.id>``)". The id is fully deterministic
(``<detection.id>:<event.id>``, ``document_id()``), so re-stamping the exact
same (analytic, event) pair — a re-run of ``stamp-detections`` over the same
tree, a source re-exported after a rebuild — is the ordinary case, not a
conflict to reject: this writer's ``--post`` uses the Elasticsearch ``_bulk``
``index`` action (replace-if-present), never ``create`` (which would 409 on
every re-run), exactly as the engine's ``byakugan.exchange.cti.indicators.bulk_lines``
already does for the same reason ("so a re-pull upserts").

ONE ROW PER (DETECTION, EVENT), EVEN WHEN BYAKUGAN SIGHTS IT TWICE.
``analytics.py``'s ``run_analytic()`` — "One hit per (clause, matching row)" —
can fire more than one clause of the SAME analytic on the SAME CAR row, which
would collide on this contract's own ``_id``. :func:`extract_rows` groups by
``(detection.id, event.id)`` before stamping, in the deterministic traversal
order (sorted sources, bundle order within a source): technique ids across a
group's hits union (harmless: a ``BehaviourHit``'s ``coverage`` is its
analytic's, identical across the analytic's own clauses — ``analytics.py``'s
``run_analytic`` passes ``coverage=an.coverage`` verbatim to every hit); the
FIRST-encountered hit in that order is the row's representative for
``detection.detected_at`` / ``detection.source_id`` / ``rule.name`` — simple,
and sufficient, since those already agree within one analytic's clauses.

DEFERRED (not this phase — the epic marks it explicitly optional): the
``logs-car.behaviour-*`` data stream (a *stream* of behaviour hits, distinct
from this *lookup* index). Also deferred: the Detection-Engine-alert sweep
``join-keys.yml`` itself describes as the phase-2 writer — this module is a
second, earlier-landing writer for the SAME index, not a replacement for it.

USAGE::

    dxdfir stamp-detections [TREE] [--out FILE] [--post] [--url URL] [--ca FILE]

    python -m get_sybers_dxdfir.detect.car_detections                    # writes TREE/car-detections.bulk.ndjson
    python -m get_sybers_dxdfir.detect.car_detections --post --insecure  # + PUT the template, POST the bulk body

Default output: ``<tree>/car-detections.bulk.ndjson`` plus one JSON summary
line on stdout. ``--post`` additionally resolves an Elasticsearch connection
(flags, then ``DXDFIR_ES_*``, then the ``elastic.env`` handoff's
``ELASTIC_PASSWORD`` / ``ELASTICSEARCH_USERNAME`` — the same file
``go/internal/tui/kibana.go``'s ``readElasticEnv`` and
``.github/tests/elastic-riskgate/riskgate.sh`` already read), diffs the
committed index template against what is live (GET first; PUT only when it
differs — a subset check, since a live cluster's GET echoes back fields
Elasticsearch defaults in that were never in what this repo commits) and bulk
POSTs the NDJSON with ``refresh=true`` so a ``LOOKUP JOIN`` run right after
sees the new rows. Pure standard library throughout (``urllib``, no
``requests``/``docker`` dependency for this path) — the client is
``.github/tests/elastic-riskgate/riskgate.py``'s ``Es``, minus its test-only
pieces.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from . import attack_index as attack_index_mod
from . import rules_loader
from .attack_index import AttackIndex, load_attack_index

DEFAULT_TREE = os.path.join("data_store", "processed", "byakugan")
BUNDLE_FILENAME = "stix_bundle.json"
DEFAULT_OUT_NAME = "car-detections.bulk.ndjson"
# This writer's own detection.status literal (free text on this contract, see
# the riskgate fixture's own "riskgate" sentinel) — distinguishes a row this
# writer stamped from one a future rules-as-code sweep would (whose
# detection.status would be the rule's own "ported" / "stub").
DETECTION_STATUS = "car-analytic"
# Every row's event.id is read straight off the bundle's own sighting /
# observed-data — never resolved through a rule's car_join.provenance fields.
JOIN_VIA = "direct"
FRAMEWORK = "MITRE ATT&CK"

# -- Elasticsearch connection (the --post path) -------------------------------
ENV_URL, ENV_USER, ENV_PASSWORD = "DXDFIR_ES_URL", "DXDFIR_ES_USER", "DXDFIR_ES_PASSWORD"
ENV_CA, ENV_INSECURE = "DXDFIR_ES_CA", "DXDFIR_ES_INSECURE"
DEFAULT_ES_URL = "https://localhost:9200"
DEFAULT_ES_USER = "elastic"
# The deploy's generated credential handoff ("localhost" is the default
# inventory's name for the workstation); the compose-era docker/elastic/.env
# is still read as a fallback for a not-yet-migrated stack.
ELASTIC_ENV_FILE = os.path.join("ansible", "inventory", "secrets", "localhost", "elastic.env")
LEGACY_ELASTIC_ENV_FILE = os.path.join("docker", "elastic", ".env")


class EsError(Exception):
    """``--post`` cannot proceed (unreachable stack, missing credentials, a
    rejected template or bulk request)."""


# --------------------------------------------------------------------- reading
def iter_bundles(tree: str) -> list[tuple[str, str]]:
    """Every ``stix_bundle.json`` under ``tree`` (any depth — the same walk
    the engine's ``byakugan.exchange.behaviour`` uses for materialised CAR
    source directories), as ``(source, path)`` sorted by path. ``source`` is the
    bundle's parent directory name — the same value Byakugan's own
    ``stix.export()`` defaults its ``case`` to
    (``os.path.basename(car_dir)``), so :func:`stamp_doc`'s ``detection.run_id``
    names the run this writer stamped from without inventing an identifier
    Byakugan did not already use."""
    found: list[tuple[str, str]] = []
    for cur, _dirs, files in os.walk(tree):
        if BUNDLE_FILENAME in files:
            source = os.path.basename(os.path.normpath(cur)) or cur
            found.append((source, os.path.join(cur, BUNDLE_FILENAME)))
    return sorted(found, key=lambda t: t[1])


def load_bundle(path: str) -> dict | None:
    """The parsed bundle, or ``None`` when the file is not readable JSON
    carrying an ``objects`` list — a malformed bundle is skipped (and counted
    by :func:`extract_rows`), never fatal to the rest of the tree."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("objects"), list):
        return None
    return doc


def flatten(doc: dict, prefix: str = "") -> dict:
    """Nested ``{"host": {"name": ..}}`` -> dotted ``{"host.name": ..}`` (lists
    kept) — what the stamped-fields audit walks. The exchange's own copy lives
    in the Byakugan engine (``byakugan.exchange``)."""
    out: dict = {}
    for k, v in doc.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict) and v:
            out.update(flatten(v, key + "."))
        else:
            out[key] = v
    return out


def _index_by_id(bundle: dict) -> dict[str, dict]:
    return {o["id"]: o for o in bundle["objects"] if isinstance(o, dict) and isinstance(o.get("id"), str)}


# ------------------------------------------------------------------- the join
@dataclass(frozen=True)
class Hit:
    """One STIX ``sighting``, resolved to what the join needs — a row's worth
    of :func:`stamp_doc` inputs before the (detection, event) grouping pass."""
    detection_id: str
    rule_name: str
    event_id: str
    process_entity_id: str | None
    detected_at: str | None
    source_index: str
    source_id: str
    technique_ids: tuple[str, ...]


def _extract_hit(sighting: dict, objs: dict[str, dict]) -> tuple[Hit | None, str | None]:
    """One ``sighting`` object -> a :class:`Hit`, or ``(None, reason)`` when
    the bundle does not carry what the join needs. Never guessed: a sighting
    with no ``x_car_event_id`` (a guid-less CAR row, A9 in ``byakugan/stix.py``)
    or whose ``sighting_of_ref`` does not resolve to an indicator in this same
    bundle is skipped, not defaulted."""
    event_id = sighting.get("x_car_event_id")
    if not isinstance(event_id, str) or not event_id:
        return None, "no_event_id"
    # a ref must be a string before it can key the object index — a malformed
    # bundle putting a dict/list there would otherwise raise (unhashable) and
    # abort the whole stamp run instead of skipping the one sighting
    ind_ref = sighting.get("sighting_of_ref")
    ind = objs.get(ind_ref) if isinstance(ind_ref, str) else None
    if not isinstance(ind, dict) or ind.get("type") != "indicator":
        return None, "no_indicator"
    detection_id = ind.get("x_car_analytic")
    if not isinstance(detection_id, str) or not detection_id:
        return None, "no_analytic_id"
    rule_name = ind.get("name")
    if not isinstance(rule_name, str) or not rule_name:
        return None, "no_rule_name"
    process_entity_id = None
    refs = sighting.get("observed_data_refs")
    if isinstance(refs, list) and refs and isinstance(refs[0], str):
        od = objs.get(refs[0])
        if isinstance(od, dict):
            pid = od.get("x_car_process_entity_id")
            if isinstance(pid, str) and pid:
                process_entity_id = pid
    car_object = sighting.get("x_car_object")
    source_index = f"logs-car.{car_object}-*" if isinstance(car_object, str) and car_object else "logs-car.*-*"
    detected_at = sighting.get("first_seen") or sighting.get("created")
    techniques = tuple(t for t in (sighting.get("x_car_techniques") or []) if isinstance(t, str) and t)
    return Hit(detection_id, rule_name, event_id, process_entity_id, detected_at,
              source_index, str(sighting.get("id") or ""), techniques), None


def extract_rows(tree: str) -> tuple[list[dict], dict]:
    """Every ``stix_bundle.json`` under ``tree``, sighting objects in bundle
    order, grouped by ``(detection_id, event_id)`` (see the module docstring:
    ``analytics.py`` can hit one row with more than one clause of the same
    analytic). Returns ``(rows, report)``; ``rows`` keep first-seen order —
    sorted sources, bundle order within one — so two runs over the same tree
    produce byte-identical output. Each row is ``{"hit": Hit, "run_id": str,
    "technique_ids": tuple[str, ...]}``."""
    report: dict = {"sources": 0, "sources_skipped": {}, "sightings": 0, "skipped": {}, "rows": 0}
    groups: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for source, path in iter_bundles(tree):
        bundle = load_bundle(path)
        if bundle is None:
            report["sources_skipped"][path] = "unreadable_or_malformed"
            continue
        report["sources"] += 1
        objs = _index_by_id(bundle)
        for obj in bundle["objects"]:
            if not isinstance(obj, dict) or obj.get("type") != "sighting":
                continue
            report["sightings"] += 1
            hit, reason = _extract_hit(obj, objs)
            if hit is None:
                report["skipped"][reason] = report["skipped"].get(reason, 0) + 1
                continue
            key = (hit.detection_id, hit.event_id)
            group = groups.get(key)
            if group is None:
                groups[key] = {"hit": hit, "run_id": source, "technique_ids": set(hit.technique_ids)}
                order.append(key)
            else:
                group["technique_ids"].update(hit.technique_ids)   # first hit stays representative
    rows = [{"hit": groups[k]["hit"], "run_id": groups[k]["run_id"],
            "technique_ids": tuple(sorted(groups[k]["technique_ids"]))} for k in order]
    report["rows"] = len(rows)
    return rows, report


# ---------------------------------------------------------------- ATT&CK enrichment
def _tactics_by_phase(index_path: str | None = None) -> dict[str, tuple[str, str]]:
    """``{kill-chain phase shortname: (tactic id, tactic name)}`` — the
    reverse of the SAME ``tactics`` block :mod:`.attack_index` already
    commits and reads (its ``AttackIndex.tactics`` keeps only the id -> phase
    direction, which a technique's ``.phases`` already gives us; this is the
    other direction of the one committed file, not a second table)."""
    path = index_path or attack_index_mod.DEFAULT_INDEX_PATH
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    out: dict[str, tuple[str, str]] = {}
    for tid, entry in (doc.get("tactics") or {}).items():
        phase, name = (entry or {}).get("phase"), (entry or {}).get("name")
        if phase and name:
            out.setdefault(str(phase), (str(tid), str(name)))
    return out


def _scalar_or_list(values: Iterable[str]):
    """A single value bare, several as a sorted list, none as ``None`` — the
    shape the engine's ``byakugan.exchange.cti.indicators`` already uses for a
    multi-valued ECS field (Elasticsearch accepts the same field mapped
    scalar or array; ES|QL rule files in this repo's own ``rules/*.yml``
    ``MV_APPEND`` the same way when more than one value applies)."""
    seen = sorted({v for v in values if v})
    if not seen:
        return None
    return seen[0] if len(seen) == 1 else seen


# --------------------------------------------------------------------- stamping
def stamp_doc(hit: Hit, run_id: str, technique_ids: Iterable[str], attack: AttackIndex,
             phase_tactics: dict[str, tuple[str, str]]) -> dict:
    """One car-detections document for ``hit`` — EXACTLY the two join keys
    ``join-keys.yml`` declares plus its 16 ``stamped_fields``, honest nulls
    omitted (never ``detection.severity`` / ``event.risk_score`` — see the
    module docstring; never ``@timestamp`` — same). A technique id this
    repo's committed ATT&CK index does not know still stamps
    ``threat.technique.id`` (Byakugan asserted it) but contributes no name and
    no tactic — reported by the caller, never invented here."""
    doc: dict = {"event": {"id": hit.event_id}}
    if hit.process_entity_id:
        doc["process"] = {"entity_id": hit.process_entity_id}
    doc["detection"] = {
        "id": hit.detection_id, "status": DETECTION_STATUS, "run_id": run_id,
        "source_index": hit.source_index, "source_id": hit.source_id, "join_via": JOIN_VIA,
    }
    if hit.detected_at:
        doc["detection"]["detected_at"] = hit.detected_at
    doc["rule"] = {"id": hit.detection_id, "name": hit.rule_name}

    tactic_ids: set[str] = set()
    tactic_names: set[str] = set()
    technique_names: set[str] = set()
    for tid in technique_ids:
        resolved = attack.resolve(tid)
        if resolved is None:
            continue
        technique_names.add(resolved.technique.name)
        for phase in resolved.technique.phases:
            hit_tactic = phase_tactics.get(phase)
            if hit_tactic:
                tactic_ids.add(hit_tactic[0])
                tactic_names.add(hit_tactic[1])
    threat: dict = {"framework": FRAMEWORK}
    technique_id_v = _scalar_or_list(technique_ids)
    if technique_id_v is not None:
        technique: dict = {"id": technique_id_v}
        name_v = _scalar_or_list(technique_names)
        if name_v is not None:
            technique["name"] = name_v
        threat["technique"] = technique
    tactic_id_v, tactic_name_v = _scalar_or_list(tactic_ids), _scalar_or_list(tactic_names)
    if tactic_id_v is not None or tactic_name_v is not None:
        tactic = {}
        if tactic_id_v is not None:
            tactic["id"] = tactic_id_v
        if tactic_name_v is not None:
            tactic["name"] = tactic_name_v
        threat["tactic"] = tactic
    doc["threat"] = threat
    return doc


def document_id(detection_id: str, event_id: str) -> str:
    """``_id`` per ``join-keys.yml``: ``<detection.id>:<event.id>``."""
    return f"{detection_id}:{event_id}"


def _mapped_fields(properties: dict | None, prefix: str = "") -> set[str]:
    """Every leaf field path an index template's ``mappings.properties`` maps
    — the same small walk ``rules_loader._mapped_fields`` (and the engine's
    ``byakugan.exchange.cti.indicators.template_fields``) already does for its
    own templates; this module owns its own copy rather than reach into another
    module's private helper."""
    out: set[str] = set()
    for name, spec in (properties or {}).items():
        path = prefix + name
        if isinstance(spec, dict) and "properties" in spec:
            out |= _mapped_fields(spec["properties"], path + ".")
        else:
            out.add(path)
    return out


def bulk_lines(pairs: Iterable[tuple[str, dict]], index: str) -> Iterator[str]:
    """Elasticsearch ``_bulk`` body lines for ``(document_id, doc)`` pairs —
    an ``index`` action (upsert; see the module docstring), then the
    document — ready for ``POST /_bulk``."""
    for doc_id, doc in pairs:
        yield json.dumps({"index": {"_index": index, "_id": doc_id}}, separators=(",", ":"))
        yield json.dumps(doc, ensure_ascii=False, separators=(",", ":"), default=str)


# ---------------------------------------------------------------------- the verb
def run_stamp(tree: str, *, template: dict, join_keys: dict, out: str | None = None,
             index: str | None = None, attack_index_path: str | None = None
             ) -> tuple[dict, list[dict], list[str]]:
    """Every ``stix_bundle.json`` under ``tree`` -> car-detections bulk NDJSON
    ``lines`` (+ the parsed ``docs`` and a ``summary``), written to ``out``
    (default ``<tree>/car-detections.bulk.ndjson``). ``template`` / ``join_keys``
    are the already-loaded, already-validated car-detections contract
    (:func:`rules_loader.load_car_detections` / ``validate_car_detections`` —
    the caller's job, once, not re-read here). Raises ``ValueError`` naming
    the field(s) if a stamped document ever carries something the template
    does not map — template drift, not something a row should silently ship."""
    index = index or join_keys["lookup_index"]
    mapped = _mapped_fields(((template.get("template") or {}).get("mappings") or {}).get("properties"))
    attack = load_attack_index(attack_index_path)
    phase_tactics = _tactics_by_phase(attack_index_path)
    rows, report = extract_rows(tree)
    docs: list[dict] = []
    ids: list[str] = []
    for row in rows:
        hit = row["hit"]
        doc = stamp_doc(hit, row["run_id"], row["technique_ids"], attack, phase_tactics)
        extra = sorted(k for k in flatten(doc) if k not in mapped)
        if extra:
            raise ValueError(f"{hit.detection_id}:{hit.event_id}: stamped field(s) the car-detections "
                             f"template does not map: {extra} — car_detections.py and the index "
                             "template have drifted apart")
        docs.append(doc)
        ids.append(document_id(hit.detection_id, hit.event_id))
    out = out or os.path.join(tree, DEFAULT_OUT_NAME)
    lines = list(bulk_lines(zip(ids, docs), index))
    parent = os.path.dirname(os.path.abspath(out))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")
    summary = {"tool": "car-detections-stamp", "tree": tree, "index": index, "out": out,
              "report": report, "docs": len(docs), "ok": True}
    return summary, docs, lines


# ------------------------------------------------------------- the ES client (--post)
class Es:
    """Just enough of an Elasticsearch client: basic auth, own CA, no proxy —
    ``.github/tests/elastic-riskgate/riskgate.py``'s ``Es``, minus its
    test-only bits (``call()`` keeps the same ``(status, doc)`` contract)."""

    def __init__(self, url: str, user: str, password: str, ca: str | None, insecure: bool) -> None:
        self.url = url.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        # The stack is on loopback: an inherited https_proxy must not swallow the call.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))

    def call(self, method: str, path: str, body=None, ctype: str = "application/json"):
        data = None
        if body is not None:
            data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Authorization", self.auth)
        if data is not None:
            req.add_header("Content-Type", ctype)
        try:
            with self.opener.open(req, timeout=120) as resp:
                status, text = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as e:
            raise EsError(f"{method} {path}: cannot reach {self.url}: {getattr(e, 'reason', e)}") from e
        try:
            doc = json.loads(text) if text.strip() else {}
        except ValueError:
            doc = {"raw": text}
        return status, doc


def _reason(doc) -> str:
    if isinstance(doc, dict):
        err = doc.get("error")
        if isinstance(err, dict):
            return str(err.get("reason") or err)
        if err:
            return str(err)
        if "raw" in doc:
            return str(doc["raw"])[:300]
    return str(doc)[:300]


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _read_elastic_env(path: str = ELASTIC_ENV_FILE) -> dict[str, str]:
    """``ELASTICSEARCH_USERNAME`` / ``ELASTIC_PASSWORD`` (or
    ``ELASTICSEARCH_PASSWORD``) from the deploy's generated ``elastic.env``
    handoff — the same file, read the same way, as
    ``go/internal/tui/kibana.go``'s ``readElasticEnv`` and
    ``.github/tests/elastic-riskgate/riskgate.sh`` — falling back to the
    compose-era ``docker/elastic/.env``. A missing file or key is never an
    error here: the environment or a flag may supply it instead."""
    out: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        if path != LEGACY_ELASTIC_ENV_FILE:
            return _read_elastic_env(LEGACY_ELASTIC_ENV_FILE)
        return out
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip().strip("'\"")
        if key == "ELASTICSEARCH_USERNAME" and value:
            out["user"] = value
        elif key in ("ELASTIC_PASSWORD", "ELASTICSEARCH_PASSWORD") and value:
            out["password"] = value
    return out


def resolve_es(*, url: str | None = None, user: str | None = None, password: str | None = None,
               ca: str | None = None, insecure: bool = False, env: dict | None = None,
               env_file: str = ELASTIC_ENV_FILE) -> Es:
    """Flags, then ``DXDFIR_ES_*``, then the ``elastic.env`` handoff — "resolved
    the way the repo already does it" (the module docstring). Fails loudly
    (``EsError``) rather than silently posting nowhere or unverified, mirroring
    ``riskgate.py``'s own ``connect_from_env``."""
    env = os.environ if env is None else env
    dotenv = _read_elastic_env(env_file)
    url = url or env.get(ENV_URL) or DEFAULT_ES_URL
    user = user or env.get(ENV_USER) or dotenv.get("user") or DEFAULT_ES_USER
    password = password or env.get(ENV_PASSWORD) or dotenv.get("password")
    if not password:
        raise EsError(f"no Elasticsearch password: pass --password, set {ENV_PASSWORD}, or run "
                      f"`dxdfir deploy stack` first so {env_file} carries ELASTIC_PASSWORD")
    ca = ca or env.get(ENV_CA)
    insecure = insecure or _truthy(env.get(ENV_INSECURE))
    if url.startswith("https://") and not ca and not insecure:
        raise EsError(
            f"https without a CA: pass --ca (the deploy writes it to "
            "ansible/inventory/secrets/<host>/certs/ca/ca.crt), or --insecure "
            "(loopback only, last resort)")
    return Es(url, user, password, ca, insecure)


def _contains(local, remote) -> bool:
    """True when every key/value ``local`` carries is present and equal in
    ``remote`` (recursively) — a SUBSET check, not ``==``. A live cluster's
    GET echoes back fields Elasticsearch defaults in (``composed_of``,
    ``allow_auto_create``, ``data_stream`` ...) that were never in what this
    repo commits; a strict ``==`` would re-PUT an unchanged template on every
    run, which is not what "diff-first: GET and skip when equal" asks for.

    Lists deliberately compare by position AND length, never as subsets: the
    list-valued template fields are order-sensitive (``composed_of`` — later
    components win the mapping merge — and ``index_patterns``), so a remote
    reordering or superset is a real difference. If a cluster ever normalises
    a list on echo, the cost is a spurious re-PUT of an idempotent template —
    the fail-safe direction — never a skipped PUT that leaves the live
    template drifted."""
    if isinstance(local, dict):
        return isinstance(remote, dict) and all(k in remote and _contains(v, remote[k]) for k, v in local.items())
    if isinstance(local, list):
        return isinstance(remote, list) and len(local) == len(remote) and all(
            _contains(a, b) for a, b in zip(local, remote))
    return local == remote


def put_template_if_needed(es: Es, name: str, template: dict) -> dict:
    """GET ``_index_template/<name>``; PUT ``template`` only when it is not
    already a subset of what is live. Returns ``{"action": "skipped"|"put", ...}``."""
    status, doc = es.call("GET", f"/_index_template/{name}")
    if status == 200:
        current = next((t.get("index_template") for t in doc.get("index_templates", [])
                        if t.get("name") == name), None)
        if current is not None and _contains(template, current):
            return {"action": "skipped", "reason": "already up to date"}
    elif status != 404:
        raise EsError(f"GET _index_template/{name}: HTTP {status}: {_reason(doc)}")
    status, doc = es.call("PUT", f"/_index_template/{name}", template)
    if status != 200 or not doc.get("acknowledged"):
        raise EsError(f"PUT _index_template/{name}: HTTP {status}: {_reason(doc)}")
    return {"action": "put", "status": status}


def post_bulk(es: Es, lines: list[str]) -> dict:
    """POST the ``_bulk`` NDJSON body (``refresh=true`` — a lookup row should
    be joinable right after this call returns). Returns accepted / error
    counts, never raises on a per-item error (those are named in ``errors``)."""
    if not lines:
        return {"accepted": 0, "errors": [], "total": 0}
    body = "\n".join(lines) + "\n"
    status, doc = es.call("POST", "/_bulk?refresh=true", body, ctype="application/x-ndjson")
    if status != 200:
        raise EsError(f"POST _bulk: HTTP {status}: {_reason(doc)}")
    accepted, errors = 0, []
    for item in doc.get("items", []):
        ((_action, res),) = item.items()
        if res.get("error"):
            errors.append(f"{res.get('_id')}: {_reason({'error': res['error']})}")
        else:
            accepted += 1
    return {"accepted": accepted, "errors": errors, "total": len(doc.get("items", []))}


# --------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m get_sybers_dxdfir.detect.car_detections",
        description="Stamp Byakugan's behaviour hits (STIX sightings) into the car-detections lookup index.")
    ap.add_argument("tree", nargs="?", default=DEFAULT_TREE,
                    help=f"the byakugan output tree (default: {DEFAULT_TREE})")
    ap.add_argument("--out", default=None,
                    help=f"bulk NDJSON path (default: <tree>/{DEFAULT_OUT_NAME})")
    ap.add_argument("--index", default=None,
                    help="the concrete lookup index the bulk docs target (default: join-keys.yml's "
                         "lookup_index, 'car-detections')")
    ap.add_argument("--rules-dir", default=rules_loader.RULES_DIR,
                    help="where the car-detections/ contract lives (default: the package's own rules)")
    ap.add_argument("--attack-index", default=None,
                    help="an ATT&CK index/bundle other than the committed one")
    ap.add_argument("--post", action="store_true",
                    help="also PUT the index template (skipped when already equal) and POST the bulk body")
    ap.add_argument("--template-name", default=None,
                    help="the index template's registered name (default: join-keys.yml's lookup_index)")
    ap.add_argument("--url", default=None, help=f"Elasticsearch URL (default: {DEFAULT_ES_URL}, or {ENV_URL})")
    ap.add_argument("--user", default=None, help=f"basic auth user (default: elastic, or {ENV_USER})")
    ap.add_argument("--password", default=None,
                    help=f"basic auth password (default: the elastic.env handoff, or {ENV_PASSWORD})")
    ap.add_argument("--ca", default=None, help=f"CA bundle PEM (default: {ENV_CA})")
    ap.add_argument("--insecure", action="store_true",
                    help=f"skip TLS verification (loopback only, last resort; or {ENV_INSECURE}=1)")
    args = ap.parse_args(argv)
    car_dir = os.path.join(args.rules_dir, "car-detections")
    try:
        template, join_keys = rules_loader.load_car_detections(
            os.path.join(car_dir, "car-detections.index-template.json"),
            os.path.join(car_dir, "join-keys.yml"))
        rules_loader.validate_car_detections(template, join_keys)
        summary, _docs, lines = run_stamp(
            args.tree, template=template, join_keys=join_keys, out=args.out, index=args.index,
            attack_index_path=args.attack_index)
        if args.post:
            es = resolve_es(url=args.url, user=args.user, password=args.password,
                            ca=args.ca, insecure=args.insecure)
            template_name = args.template_name or join_keys["lookup_index"]
            summary["template"] = put_template_if_needed(es, template_name, template)
            summary["bulk"] = post_bulk(es, lines)
            summary["ok"] = not summary["bulk"]["errors"]
    except (EsError, ValueError, OSError) as e:
        print(json.dumps({"tool": "car-detections-stamp", "error": str(e)}), file=sys.stderr)
        return 1
    print(json.dumps(summary, default=str))
    return 0 if summary.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
