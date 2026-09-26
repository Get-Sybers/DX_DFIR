"""Elastic detection rules-as-code — the Byakugan sibling of :mod:`.registry`.

:mod:`.registry` is the HuntList for the Kusto backend: one Python dict per
detection and a ``validate()`` that fails fast on a malformed entry. This module
is the same idea for Elastic's own Detection Engine, with the detections as
DATA: one YAML file per rule under ``detect/rules/``, each carrying an ES|QL or
EQL query plus the contract for the TAGGED EVIDENCE LINE it produces. It loads
the files, validates them with the registry's rigor, and exposes
``list_rules()`` / ``validate()``.

ADDITIVE. The Kusto registry, runner and emulator stay exactly as they are
until Kusto retires at the end of phase 2 (decision D1). Nothing here imports
them, so the rule set stays loadable after that retirement; the ids are shared
(every rule file reuses its registry id, and ``tests/test_rules.py`` pins the
two id sets equal, so a detection can neither be dropped silently nor exist
twice under different names).

Rule file shape (``rules/README.md`` documents the model in full)::

    id: win-defender-tamper           # == registry id == file stem
    name: Windows Defender disabled or reconfigured
    status: ported | stub             # stub: query is a TODO, the KQL intent is kept
    severity: low | medium | high | critical
    risk_score: 47                    # optional, defaults from severity
    attack: [T1562.001]               # ATT&CK technique ids (may be empty)
    tactics: [TA0005]                 # optional ATT&CK tactic ids
    created: "2026-09-02"             # ISO date the rule was authored (the STIX export needs it)
    updated: "2026-09-02"             # optional; the last material change, defaults to created
    language: esql | eql
    index: [logs-dxdfir.evtx-*]         # the data streams the query reads
    query: |                          # ported only; null/absent for a stub
    evidence:                         # the tagged-evidence-line contract
      shape: line | aggregate
      stamped_by: query | engine
      fields: [threat.technique.id, ...]
    car_join: {key: event.id, via: direct | provenance, provenance: [...]}
    fields: [{ecs: event.code, native: EventId}, ...]     # optional
    source: {registry: <id>, kind: kusto | jsonl, kql: ... | match: ...}
    todo: {query: ..., blockers: [...]}                    # stub only

The query check is STRUCTURAL, not a parser. ES|QL must start with a FROM over
exactly the declared data streams, chain only known commands, request
``METADATA _id, _index, _version`` when it does not aggregate (that is what
makes the Detection Engine emit one alert per matched source document), and
stamp every field the evidence contract promises. EQL must be a
``<category> where`` / ``sequence`` / ``sample`` query. Both must balance their
brackets outside string literals and carry no KQL left-overs.
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import re
import sys

import yaml

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
CAR_DETECTIONS_DIR = os.path.join(RULES_DIR, "car-detections")
CAR_DETECTIONS_TEMPLATE = os.path.join(CAR_DETECTIONS_DIR, "car-detections.index-template.json")
CAR_DETECTIONS_JOIN_KEYS = os.path.join(CAR_DETECTIONS_DIR, "join-keys.yml")
# The CTI indicator-match rule contract (rules/cti/): one Detection Engine
# threat_match rule as data. The cti-* index template its threat_index reads
# lives in the Byakugan engine now (byakugan.exchange.cti — the cti-pull
# sub-tool fills it), so the rule validates standalone here; hand
# validate_indicator_match a template (a copy a deployment kept) and the
# cross-checks run too. The template<->pattern-mapping agreement itself is
# tested engine-side.
CTI_DIR = os.path.join(RULES_DIR, "cti")
CTI_RULE = os.path.join(CTI_DIR, "cti-indicator-match.yml")
THREAT_MATCH = "threat_match"
# Elastic's names for the Kibana query languages a threat_match rule speaks
# (not the Kusto "KQL" the rules' source column keeps).
KIBANA_LANGUAGES = ("kuery", "lucene")
THREAT_MAPPING_TYPES = ("mapping",)
THREAT_MATCH_REQUIRED = ("id", "name", "type", "status", "severity", "attack", "language", "index",
                         "query", "threat_index", "threat_language", "threat_indicator_path",
                         "threat_mapping", "evidence", "car_join")
# What the sightings push (the engine's cti-sightings sub-tool,
# byakugan.exchange.cti.sightings) reads off an indicator-match alert: the
# platform's indicator id and the value that matched.
ROUND_TRIP_FIELDS = ("threat.enrichments.indicator.id", "threat.enrichments.matched.atomic")

# Elastic's severity set (the registry's "info" maps to "low") and the Detection
# Engine's canonical risk score for each — used when a rule declares none.
SEVERITIES = ("low", "medium", "high", "critical")
RISK_SCORES = {"low": 21, "medium": 47, "high": 73, "critical": 99}
LANGUAGES = ("esql", "eql")
STATUSES = ("ported", "stub")
SHAPES = ("line", "aggregate")
STAMPERS = ("query", "engine")
SOURCE_KINDS = ("kusto", "jsonl")
JOIN_VIAS = ("direct", "provenance")
# The keys the car-detections lookup index can be joined on (guid travels as
# event.id on every CAR object, and as process.entity_id on process). Kept in
# lockstep with rules/car-detections/join-keys.yml (pinned by the tests).
CAR_JOIN_KEYS = ("event.id", "process.entity_id")
REQUIRED = ("id", "name", "status", "severity", "attack", "language", "index",
            "evidence", "car_join", "source")

_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TACTIC_RE = re.compile(r"^TA\d{4}$")
# A data stream pattern: logs-<dataset>-* (dataset may carry a wildcard segment,
# e.g. logs-car.*-* for every CAR object).
_INDEX_RE = re.compile(r"^logs-[a-z0-9_]+(?:\.[a-z0-9_*]+)*-\*$")
# An ECS-style field path (@timestamp, event.code, winlog.event_data.ImagePath).
_FIELD_RE = re.compile(r"^[@a-z][a-z0-9_]*(?:\.[A-Za-z0-9_]+)*$")
_MATCH_RE = re.compile(r"^match_[a-z0-9_]+$")

_ESQL_PIPE_CMDS = (
    "WHERE", "EVAL", "KEEP", "DROP", "STATS", "INLINESTATS", "SORT", "LIMIT",
    "RENAME", "LOOKUP JOIN", "MV_EXPAND", "GROK", "DISSECT", "ENRICH",
    "CHANGE_POINT", "SAMPLE", "FORK", "COMPLETION", "RERANK", "FUSE",
)
_ESQL_METADATA = ("_id", "_index", "_version")
_ESQL_FROM_RE = re.compile(r"^\s*FROM\s+(.+?)(?:\s+METADATA\s+(.+))?\s*$", re.I | re.S)
_EQL_HEAD_RE = re.compile(r"^\s*(?:(?:sequence|sample)\b|[a-z_][\w.]*\s+where\b)", re.I)
# KQL that has no business in an Elastic query — a port that still contains one
# of these was not finished. Word-bounded (ES|QL's DATE_DIFF( is not iff().
_KQL_LEFTOVERS = tuple(re.compile(p, re.I) for p in (
    r"\bdatabase\(", r"\|\s*project\b", r"\|\s*extend\b", r"\|\s*summarize\b",
    r"\bpack\(", r"=~", r"\bstrcat\(", r"\btostring\(", r"\btolong\(", r"\biff\(",
    r"\bmatches\s+regex\b", r"\btake_any\(", r"\bmake_set\(", r"\bisnotempty\("))
_BRACKETS = {")": "(", "]": "[", "}": "{"}


# ---------------------------------------------------------------- pure query helpers
def _strip_strings(text: str) -> str:
    """The query with every string literal (``"..."`` and ``\"\"\"...\"\"\"``)
    blanked to ``""``, so bracket balancing and command detection are not
    fooled by quoted content (regexes, paths). Raises ValueError on an
    unterminated literal. Pure."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith('"""', i):
            j = text.find('"""', i + 3)
            if j < 0:
                raise ValueError("unterminated triple-quoted string")
            out.append('""')
            i = j + 3
            continue
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise ValueError("unterminated string literal")
            out.append('""')
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _unbalanced(stripped: str) -> str | None:
    """The first bracket problem in an already string-stripped query, or None."""
    stack: list[str] = []
    for c in stripped:
        if c in "([{":
            stack.append(c)
        elif c in _BRACKETS:
            if not stack or stack[-1] != _BRACKETS[c]:
                return f"unexpected {c!r}"
            stack.pop()
    return f"unclosed {stack[-1]!r}" if stack else None


def _esql_commands(stripped: str) -> list[str]:
    """The pipeline of an ES|QL query (string-stripped) as trimmed commands."""
    return [c.strip() for c in stripped.split("|")]


def _command_head(cmd: str) -> str:
    words = cmd.split(None, 2)
    if not words:
        return ""
    head = words[0].upper()
    if head == "LOOKUP" and len(words) > 1:
        head = "LOOKUP " + words[1].upper()
    return head


def _produces(stripped: str, field: str) -> bool:
    """True when the (string-stripped) ES|QL assigns ``field`` (EVAL / STATS
    ``field = ...``) or groups by it (``STATS ... BY field``)."""
    if re.search(r"(?<![\w.])" + re.escape(field) + r"\s*=(?!=)", stripped):
        return True
    for cmd in _esql_commands(stripped):
        if _command_head(cmd) in ("STATS", "INLINESTATS") and " BY " in cmd.upper():
            keys = cmd[cmd.upper().rindex(" BY ") + 4:]
            if field in {k.strip() for k in keys.split(",")}:
                return True
    return False


def check_query(rule: dict) -> list[str]:
    """Structural sanity problems with a ported rule's query (``[]`` = fine).
    Not a parser: it checks the shape the Detection Engine needs, not that
    every function call is valid."""
    query = rule.get("query")
    if not isinstance(query, str) or not query.strip():
        return ["query must be non-empty"]
    problems: list[str] = []
    for leftover in _KQL_LEFTOVERS:
        m = leftover.search(query)
        if m:
            problems.append(f"KQL left-over {m.group(0)!r} in an Elastic query")
    try:
        stripped = _strip_strings(query)
    except ValueError as e:
        return problems + [str(e)]
    bad = _unbalanced(stripped)
    if bad:
        problems.append(bad)
    language = rule.get("language")
    if language == "esql":
        problems += _check_esql(rule, stripped)
    elif language == "eql":
        problems += _check_eql(rule, stripped)
    return problems


def _check_esql(rule: dict, stripped: str) -> list[str]:
    problems: list[str] = []
    cmds = _esql_commands(stripped)
    m = _ESQL_FROM_RE.match(cmds[0])
    if not m:
        return ["ES|QL must start with FROM <data streams> [METADATA ...]"]
    sources = {s.strip() for s in m.group(1).split(",") if s.strip()}
    declared = set(rule.get("index") or [])
    if sources != declared:
        problems.append(f"FROM reads {sorted(sources)} but index declares {sorted(declared)}")
    meta = {s.strip() for s in (m.group(2) or "").split(",") if s.strip()}
    heads = [_command_head(c) for c in cmds[1:]]
    for head in heads:
        if head not in _ESQL_PIPE_CMDS:
            problems.append(f"unknown ES|QL command {head!r}")
    # Only STATS collapses rows into groups (an aggregate alert). INLINESTATS
    # augments each row without collapsing it, so an INLINESTATS query stays
    # non-aggregating here: it still emits one alert per matched document, so it
    # must request METADATA and its evidence is a line, not an aggregate.
    aggregating = "STATS" in heads
    if not aggregating and not set(_ESQL_METADATA) <= meta:
        problems.append("non-aggregating ES|QL must request METADATA "
                        + ", ".join(_ESQL_METADATA) + " (one alert per matched document)")
    shape = (rule.get("evidence") or {}).get("shape")
    if aggregating and shape == "line":
        problems.append("a STATS query produces aggregate evidence, not a line")
    if not aggregating and shape == "aggregate":
        problems.append("an aggregate evidence shape needs a STATS command")
    if (rule.get("evidence") or {}).get("stamped_by") == "query":
        for field in (rule.get("evidence") or {}).get("fields") or []:
            if isinstance(field, str) and not _produces(stripped, field):
                problems.append(f"evidence field {field!r} is promised but never stamped by the query")
    return problems


def _check_eql(rule: dict, stripped: str) -> list[str]:
    problems: list[str] = []
    if not _EQL_HEAD_RE.match(stripped):
        problems.append("EQL must be a '<category> where ...', 'sequence' or 'sample' query")
    if (rule.get("evidence") or {}).get("stamped_by") != "engine":
        problems.append("EQL cannot stamp fields itself; evidence.stamped_by must be 'engine'")
    return problems


# ---------------------------------------------------------------------- loading
def load(rules_dir: str = RULES_DIR) -> list[dict]:
    """Every ``*.yml`` / ``*.yaml`` directly under ``rules_dir`` as a rule dict
    (``_path`` attached; ``risk_score`` defaulted from a valid severity), in
    path order. Subdirectories (car-detections/) are not rules. Raises
    ValueError on a file that is not one YAML mapping."""
    paths = sorted(glob.glob(os.path.join(rules_dir, "*.yml"))
                   + glob.glob(os.path.join(rules_dir, "*.yaml")))
    rules: list[dict] = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            try:
                doc = yaml.safe_load(fh)
            except yaml.YAMLError as e:
                raise ValueError(f"{path}: not valid YAML: {e}") from e
        if not isinstance(doc, dict):
            raise ValueError(f"{path}: a rule file must be exactly one YAML mapping")
        doc["_path"] = path
        if "risk_score" not in doc and doc.get("severity") in RISK_SCORES:
            doc["risk_score"] = RISK_SCORES[doc["severity"]]
        rules.append(doc)
    return rules


def _str_list(v) -> bool:
    return isinstance(v, list) and all(isinstance(s, str) and s.strip() for s in v)


def validate(rules: list[dict] | None = None) -> None:
    """Fail fast on a malformed rule set — a bad rule must stop the load before
    anything is pushed to the Detection Engine, not half-install a rule set.
    Mirrors :func:`registry.validate`: first problem raises ValueError, prefixed
    with the rule id."""
    rules = load() if rules is None else rules
    seen: set[str] = set()
    for r in rules:
        rid = r.get("id", "")
        prefix = f"rule {rid!r}: "
        if not isinstance(rid, str) or not _ID_RE.match(rid):
            raise ValueError(prefix + "id must be non-empty kebab-case")
        if rid in seen:
            raise ValueError(prefix + "duplicate id")
        seen.add(rid)
        path = r.get("_path")
        if path and os.path.splitext(os.path.basename(path))[0] != rid:
            raise ValueError(prefix + f"file must be named <id>.yml, not {os.path.basename(path)}")
        missing = [k for k in REQUIRED if k not in r]
        if missing:
            raise ValueError(prefix + f"missing required field(s) {missing}")
        name = r.get("name")
        if not isinstance(name, str) or not name.strip() or '"' in name or "\\" in name:
            raise ValueError(prefix + "name must be non-empty, without quotes/backslashes")
        if r.get("status") not in STATUSES:
            raise ValueError(prefix + f"status must be one of {STATUSES}")
        if r.get("severity") not in SEVERITIES:
            raise ValueError(prefix + f"severity must be one of {SEVERITIES}")
        score = r.get("risk_score", RISK_SCORES[r["severity"]])
        if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
            raise ValueError(prefix + "risk_score must be an integer 0..100")
        attack = r.get("attack")
        if not isinstance(attack, list) or not all(
                isinstance(t, str) and _TECHNIQUE_RE.match(t) for t in attack):
            raise ValueError(prefix + "attack must be a list of ATT&CK technique ids (T1234 / T1234.001)")
        tactics = r.get("tactics", [])
        if not isinstance(tactics, list) or not all(
                isinstance(t, str) and _TACTIC_RE.match(t) for t in tactics):
            raise ValueError(prefix + "tactics must be a list of ATT&CK tactic ids (TA0001)")
        _validate_dates(prefix, r)
        if r.get("language") not in LANGUAGES:
            raise ValueError(prefix + f"language must be one of {LANGUAGES}")
        index = r.get("index")
        if not _str_list(index) or not index or not all(_INDEX_RE.match(i) for i in index):
            raise ValueError(prefix + "index must be a non-empty list of logs-<dataset>-* data stream patterns")
        _validate_evidence(prefix, r)
        _validate_car_join(prefix, r.get("car_join"))
        _validate_fields(prefix, r.get("fields"))
        _validate_source(prefix, r.get("source"))
        if r["status"] == "ported":
            if "todo" in r:
                raise ValueError(prefix + "a ported rule carries no todo block")
            problems = check_query(r)
            if problems:
                raise ValueError(prefix + "query: " + "; ".join(problems))
        else:
            if r.get("query") is not None:
                raise ValueError(prefix + "a stub must leave query null (put the intent in todo.query)")
            todo = r.get("todo")
            if not isinstance(todo, dict) or not isinstance(todo.get("query"), str) \
                    or not todo["query"].strip():
                raise ValueError(prefix + "a stub needs todo.query (the intended ES|QL/EQL)")
            if not _str_list(todo.get("blockers")) or not todo["blockers"]:
                raise ValueError(prefix + "a stub needs a non-empty todo.blockers list (why it is a stub)")


def rule_date(value) -> datetime.datetime | None:
    """A rule's ``created`` / ``updated`` value as an aware UTC datetime — an
    ISO 8601 date or datetime string (``"2026-09-02"``, ``"2026-09-02T07:01:04Z"``)
    or what YAML already parsed one into — or ``None`` when it is neither."""
    if isinstance(value, bool):
        return None
    if isinstance(value, datetime.datetime):
        dt = value
    elif isinstance(value, datetime.date):
        dt = datetime.datetime(value.year, value.month, value.day)
    elif isinstance(value, str) and value.strip():
        s = value.strip()
        try:
            dt = datetime.datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
        except ValueError:
            return None
    else:
        return None
    utc = datetime.timezone.utc
    return dt.replace(tzinfo=utc) if dt.tzinfo is None else dt.astimezone(utc)


def _validate_dates(prefix: str, r: dict) -> None:
    """``created`` / ``updated`` are optional here (the STIX export requires
    ``created``: it is the indicator's ``created`` / ``valid_from``, and
    ``updated`` its ``modified`` — STIX 2.1 §3.2 says ``created`` never
    changes and §3.6 that ``modified`` versions the object, so neither may be
    an export-time clock). When present they must be ISO 8601 and ordered."""
    created, updated = r.get("created"), r.get("updated")
    if created is not None and rule_date(created) is None:
        raise ValueError(prefix + 'created must be an ISO 8601 date or datetime ("2026-09-02")')
    if updated is not None:
        if rule_date(updated) is None:
            raise ValueError(prefix + 'updated must be an ISO 8601 date or datetime ("2026-09-02")')
        if created is None:
            raise ValueError(prefix + "updated needs created")
        if rule_date(updated) < rule_date(created):
            raise ValueError(prefix + "updated must not be earlier than created")


def _validate_evidence(prefix: str, r: dict, engine_prefixes: tuple[str, ...] = ("kibana.alert.",)) -> None:
    ev = r.get("evidence")
    if not isinstance(ev, dict):
        raise ValueError(prefix + "evidence must be a mapping (shape, stamped_by, fields)")
    if ev.get("shape") not in SHAPES:
        raise ValueError(prefix + f"evidence.shape must be one of {SHAPES}")
    if ev.get("stamped_by") not in STAMPERS:
        raise ValueError(prefix + f"evidence.stamped_by must be one of {STAMPERS}")
    fields = ev.get("fields")
    if not _str_list(fields) or not fields or not all(_FIELD_RE.match(f) for f in fields):
        raise ValueError(prefix + "evidence.fields must be a non-empty list of field paths")
    if ev["stamped_by"] == "engine" and not all(f.startswith(engine_prefixes) for f in fields):
        raise ValueError(prefix + "engine-stamped evidence fields are the Detection Engine's "
                         + " / ".join(p + "*" for p in engine_prefixes) + " fields")
    if ev["stamped_by"] == "query":
        has_technique = "threat.technique.id" in fields
        if r.get("attack") and not has_technique:
            raise ValueError(prefix + "a rule with ATT&CK techniques must stamp threat.technique.id on the evidence line")
        if not r.get("attack") and has_technique:
            raise ValueError(prefix + "no ATT&CK techniques declared, so threat.technique.id cannot be stamped")


def _validate_car_join(prefix: str, cj) -> None:
    if not isinstance(cj, dict):
        raise ValueError(prefix + "car_join must be a mapping (key, via[, provenance])")
    if cj.get("key") not in CAR_JOIN_KEYS:
        raise ValueError(prefix + f"car_join.key must be one of {CAR_JOIN_KEYS}")
    if cj.get("via") not in JOIN_VIAS:
        raise ValueError(prefix + f"car_join.via must be one of {JOIN_VIAS}")
    if cj["via"] == "provenance":
        prov = cj.get("provenance")
        if not _str_list(prov) or not prov or not all(_FIELD_RE.match(f) for f in prov):
            raise ValueError(prefix + "car_join.via=provenance needs a non-empty provenance field list")


def _validate_fields(prefix: str, fields) -> None:
    if fields is None:
        return
    if not isinstance(fields, list) or not all(
            isinstance(f, dict) and isinstance(f.get("ecs"), str) and _FIELD_RE.match(f["ecs"])
            and isinstance(f.get("native"), str) and f["native"].strip() for f in fields):
        raise ValueError(prefix + "fields must be a list of {ecs: <field path>, native: <lane field>}")


def _validate_source(prefix: str, src) -> None:
    if not isinstance(src, dict):
        raise ValueError(prefix + "source must be a mapping (registry, kind, kql | match)")
    if not isinstance(src.get("registry"), str) or not _ID_RE.match(src["registry"]):
        raise ValueError(prefix + "source.registry must be the kebab-case registry id")
    if src.get("kind") not in SOURCE_KINDS:
        raise ValueError(prefix + f"source.kind must be one of {SOURCE_KINDS}")
    if src["kind"] == "kusto":
        if not isinstance(src.get("kql"), str) or not src["kql"].strip():
            raise ValueError(prefix + "a kusto-sourced rule must keep the source KQL in source.kql")
    elif not isinstance(src.get("match"), str) or not _MATCH_RE.match(src["match"]):
        raise ValueError(prefix + "a jsonl-sourced rule must name the registry matcher in source.match")


def list_rules(rules_dir: str = RULES_DIR) -> list[dict]:
    """The validated rule set, sorted by id. The entry point for anything that
    consumes the rules (an exporter, a runner, the CLI)."""
    rules = load(rules_dir)
    validate(rules)
    return sorted(rules, key=lambda r: r["id"])


def ported(rules: list[dict]) -> list[dict]:
    return [r for r in rules if r.get("status") == "ported"]


def stubs(rules: list[dict]) -> list[dict]:
    return [r for r in rules if r.get("status") == "stub"]


# ------------------------------------------------------- the car-detections contract
def load_car_detections(template_path: str = CAR_DETECTIONS_TEMPLATE,
                        join_keys_path: str = CAR_DETECTIONS_JOIN_KEYS) -> tuple[dict, dict]:
    """The car-detections lookup index contract as data: (index template, join
    keys). Both files are pure data the deploy step PUTs / the rules join on."""
    with open(template_path, encoding="utf-8") as fh:
        template = json.load(fh)
    with open(join_keys_path, encoding="utf-8") as fh:
        join_keys = yaml.safe_load(fh)
    return template, join_keys


def _mapped_fields(properties: dict, prefix: str = "") -> set[str]:
    out: set[str] = set()
    for name, spec in (properties or {}).items():
        path = prefix + name
        if isinstance(spec, dict) and "properties" in spec:
            out |= _mapped_fields(spec["properties"], path + ".")
        else:
            out.add(path)
    return out


def validate_car_detections(template: dict, join_keys: dict) -> None:
    """The lookup index must be a LOOKUP-mode index whose mapping carries every
    join key the rules may join on, and the join-key data must agree with the
    loader's CAR_JOIN_KEYS."""
    patterns = template.get("index_patterns")
    if not _str_list(patterns) or not patterns:
        raise ValueError("car-detections: template needs index_patterns")
    settings = (template.get("template") or {}).get("settings") or {}
    if settings.get("index.mode") != "lookup":
        raise ValueError("car-detections: template must set index.mode: lookup (LOOKUP JOIN needs it)")
    mapped = _mapped_fields(((template.get("template") or {}).get("mappings") or {}).get("properties"))
    name = join_keys.get("lookup_index")
    # Glob -> regex: escape every metacharacter first (so a '.' in a pattern is
    # literal, not "any char"), then turn the escaped '*' back into '.*'.
    if not isinstance(name, str) or not any(
            re.fullmatch(re.escape(p).replace(r"\*", ".*"), name) for p in patterns):
        raise ValueError("car-detections: join-keys lookup_index must match the template's index_patterns")
    joins = join_keys.get("join")
    if not isinstance(joins, list) or not joins:
        raise ValueError("car-detections: join-keys needs a non-empty join list")
    lookup_fields: list[str] = []
    for j in joins:
        if not isinstance(j, dict):
            raise ValueError("car-detections: each join entry must be a mapping")
        for k in ("car_field", "ecs_field", "lookup_field"):
            if not isinstance(j.get(k), str) or not j[k].strip():
                raise ValueError(f"car-detections: join entry needs {k}")
        if j["ecs_field"] != j["lookup_field"]:
            raise ValueError(f"car-detections: LOOKUP JOIN ON needs the same field name on both sides "
                             f"({j['ecs_field']} != {j['lookup_field']})")
        if j["lookup_field"] not in mapped:
            raise ValueError(f"car-detections: join field {j['lookup_field']} is not mapped in the template")
        lookup_fields.append(j["lookup_field"])
    if set(lookup_fields) != set(CAR_JOIN_KEYS):
        raise ValueError(f"car-detections: join keys {sorted(lookup_fields)} must equal CAR_JOIN_KEYS {sorted(CAR_JOIN_KEYS)}")
    stamped = join_keys.get("stamped_fields")
    if not _str_list(stamped) or not stamped or not set(stamped) <= mapped:
        raise ValueError("car-detections: stamped_fields must list mapped fields of the lookup index")
    example = join_keys.get("example_query")
    if not isinstance(example, str) or not re.search(
            r"LOOKUP JOIN\s+" + re.escape(name) + r"\s+ON\s+(" + "|".join(map(re.escape, CAR_JOIN_KEYS)) + r")\b", example):
        raise ValueError("car-detections: example_query must LOOKUP JOIN the lookup index ON a join key")


# ------------------------------------------------- the CTI indicator-match contract
def load_cti_contract(rule_path: str = CTI_RULE, template_path: str = CTI_TEMPLATE) -> tuple[dict, dict]:
    """The indicator-match rule (rules/cti/) and the cti-* index template it
    reads, both as data: ``(rule, template)``. The rule gets ``_path`` and a
    defaulted ``risk_score`` exactly as :func:`load` gives the rule set."""
    with open(rule_path, encoding="utf-8") as fh:
        try:
            rule = yaml.safe_load(fh)
        except yaml.YAMLError as e:
            raise ValueError(f"{rule_path}: not valid YAML: {e}") from e
    if not isinstance(rule, dict):
        raise ValueError(f"{rule_path}: a rule file must be exactly one YAML mapping")
    rule["_path"] = rule_path
    if "risk_score" not in rule and rule.get("severity") in RISK_SCORES:
        rule["risk_score"] = RISK_SCORES[rule["severity"]]
    with open(template_path, encoding="utf-8") as fh:
        template = json.load(fh)
    return rule, template


def _covered(pattern: str, index_patterns: list[str]) -> bool:
    """True when ``pattern`` is one of the template's index patterns, or a
    name / narrower glob one of them matches (glob -> regex as above)."""
    return any(pattern == p or re.fullmatch(re.escape(p).replace(r"\*", ".*"), pattern)
               for p in index_patterns)


def _mapping_node(template: dict, path: str) -> dict | None:
    """The template's mapping definition at dotted ``path``, or None."""
    node: dict = {"properties": ((template.get("template") or {}).get("mappings") or {}).get("properties") or {}}
    for seg in path.split("."):
        nxt = (node.get("properties") or {}).get(seg)
        if not isinstance(nxt, dict):
            return None
        node = nxt
    return node


def validate_indicator_match(rule: dict, template: dict | None = None) -> None:
    """Fail fast on a malformed indicator-match rule (``rules/cti/``) — the
    Detection Engine's ``threat_match`` shape: a Kibana-language query over
    the evidence streams, the threat index, the indicator path and the
    field-to-field mapping — with :func:`validate`'s rigor (first problem
    raises ValueError prefixed with the rule id). Given the cti-* index
    ``template``, every indicator-side field the mapping reads must be mapped
    there under the indicator path, and every ``threat_index`` pattern must
    be one the template covers."""
    if not isinstance(rule, dict):
        raise ValueError("indicator-match rule: a rule must be a mapping")
    rid = rule.get("id", "")
    prefix = f"rule {rid!r}: "
    if not isinstance(rid, str) or not _ID_RE.match(rid):
        raise ValueError(prefix + "id must be non-empty kebab-case")
    path = rule.get("_path")
    if path and os.path.splitext(os.path.basename(path))[0] != rid:
        raise ValueError(prefix + f"file must be named <id>.yml, not {os.path.basename(path)}")
    if rule.get("type") != THREAT_MATCH:
        raise ValueError(prefix + f"type must be {THREAT_MATCH!r} (an indicator-match rule)")
    missing = [k for k in THREAT_MATCH_REQUIRED if k not in rule]
    if missing:
        raise ValueError(prefix + f"missing required field(s) {missing}")
    name = rule.get("name")
    if not isinstance(name, str) or not name.strip() or '"' in name or "\\" in name:
        raise ValueError(prefix + "name must be non-empty, without quotes/backslashes")
    if rule.get("status") != "ported" or "todo" in rule:
        raise ValueError(prefix + "an indicator-match rule has no stub form (the indicators are the query): "
                         "status must be 'ported', without a todo block")
    if rule.get("severity") not in SEVERITIES:
        raise ValueError(prefix + f"severity must be one of {SEVERITIES}")
    score = rule.get("risk_score", RISK_SCORES[rule["severity"]])
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
        raise ValueError(prefix + "risk_score must be an integer 0..100")
    attack = rule.get("attack")
    if not isinstance(attack, list) or not all(
            isinstance(t, str) and _TECHNIQUE_RE.match(t) for t in attack):
        raise ValueError(prefix + "attack must be a list of ATT&CK technique ids (T1234 / T1234.001)")
    tactics = rule.get("tactics", [])
    if not isinstance(tactics, list) or not all(
            isinstance(t, str) and _TACTIC_RE.match(t) for t in tactics):
        raise ValueError(prefix + "tactics must be a list of ATT&CK tactic ids (TA0001)")
    for key in ("language", "threat_language"):
        if rule.get(key) not in KIBANA_LANGUAGES:
            raise ValueError(prefix + f"{key} must be one of {KIBANA_LANGUAGES} (Elastic's names for the Kibana query languages)")
    index = rule.get("index")
    if not _str_list(index) or not index or not all(_INDEX_RE.match(i) for i in index):
        raise ValueError(prefix + "index must be a non-empty list of logs-<dataset>-* data stream patterns")
    for key in ("query", "threat_query"):
        q = rule.get(key)
        if key == "threat_query" and q is None:
            continue                                    # optional: no filter on the indicators
        if not isinstance(q, str) or not q.strip():
            raise ValueError(prefix + f"{key} must be a non-empty Kibana-language query")
        if re.match(r"^\s*FROM\s", q, re.I):
            raise ValueError(prefix + f"{key} is ES|QL; an indicator-match rule speaks {KIBANA_LANGUAGES}")
        for leftover in _KQL_LEFTOVERS:
            m = leftover.search(q)
            if m:
                raise ValueError(prefix + f"{key}: KQL left-over {m.group(0)!r} in an Elastic query")
        try:
            bad = _unbalanced(_strip_strings(q))
        except ValueError as e:
            bad = str(e)
        if bad:
            raise ValueError(prefix + f"{key}: {bad}")
    threat_index = rule.get("threat_index")
    if not _str_list(threat_index) or not threat_index:
        raise ValueError(prefix + "threat_index must be a non-empty list of index patterns (cti-*)")
    if template is not None:
        patterns = template.get("index_patterns")
        if not _str_list(patterns) or not patterns:
            raise ValueError(prefix + "the cti-* template has no index_patterns")
        for ti in threat_index:
            if not _covered(ti, patterns):
                raise ValueError(prefix + f"threat_index {ti!r} is not covered by the cti-* template's index_patterns {patterns}")
    tip = rule.get("threat_indicator_path")
    if not isinstance(tip, str) or not _FIELD_RE.match(tip):
        raise ValueError(prefix + "threat_indicator_path must be a field path (threat.indicator)")
    mapped: set[str] | None = None
    if template is not None:
        node = _mapping_node(template, tip)
        if not node or not isinstance(node.get("properties"), dict):
            raise ValueError(prefix + f"threat_indicator_path {tip} is not mapped as an object in the cti-* template")
        mapped = _mapped_fields(((template.get("template") or {}).get("mappings") or {}).get("properties"))
    groups = rule.get("threat_mapping")
    if not isinstance(groups, list) or not groups:
        raise ValueError(prefix + "threat_mapping must be a non-empty list of {entries: [...]} groups")
    seen_pairs: set[tuple[str, str]] = set()
    for g in groups:
        entries = g.get("entries") if isinstance(g, dict) else None
        if not isinstance(entries, list) or not entries:
            raise ValueError(prefix + "each threat_mapping group needs a non-empty entries list")
        for e in entries:
            if not isinstance(e, dict) or e.get("type") not in THREAT_MAPPING_TYPES:
                raise ValueError(prefix + "threat_mapping entries are {field, type: mapping, value}")
            field, value = e.get("field"), e.get("value")
            if not isinstance(field, str) or not _FIELD_RE.match(field):
                raise ValueError(prefix + f"threat_mapping field {field!r} must be an evidence field path")
            if not isinstance(value, str) or not _FIELD_RE.match(value) or not value.startswith(tip + "."):
                raise ValueError(prefix + f"threat_mapping value {value!r} must be a field under {tip}.")
            if mapped is not None and value not in mapped:
                raise ValueError(prefix + f"threat_mapping value {value} is not mapped in the cti-* template")
            if (field, value) in seen_pairs:
                raise ValueError(prefix + f"threat_mapping maps {field} -> {value} twice")
            seen_pairs.add((field, value))
    for key in ("items_per_search", "concurrent_searches"):
        v = rule.get(key)
        if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 1):
            raise ValueError(prefix + f"{key} must be a positive integer")
    _validate_evidence(prefix, rule, engine_prefixes=("kibana.alert.", "threat.enrichments."))
    ev = rule["evidence"]
    if ev.get("stamped_by") != "engine" or ev.get("shape") != "line":
        raise ValueError(prefix + "an indicator match is one engine-enriched alert per matched evidence "
                         "document: evidence.shape line, stamped_by engine")
    if not set(ROUND_TRIP_FIELDS) <= set(ev["fields"]):
        raise ValueError(prefix + "evidence.fields must carry the round-trip pair the sightings push reads: "
                         + ", ".join(ROUND_TRIP_FIELDS))
    _validate_car_join(prefix, rule.get("car_join"))
    _validate_fields(prefix, rule.get("fields"))


# ---------------------------------------------------------------------- summary
def summary(rules: list[dict]) -> dict:
    by_language: dict[str, int] = {}
    for r in rules:
        by_language[r["language"]] = by_language.get(r["language"], 0) + 1
    return {
        "tool": "rules", "rules": len(rules), "ported": len(ported(rules)),
        "stub": len(stubs(rules)), "by_language": by_language,
        "detections": {r["id"]: {"status": r["status"], "language": r["language"],
                                 "severity": r["severity"], "index": r["index"],
                                 "attack": r["attack"]} for r in rules},
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m get_sybers_dxdfir.detect.rules_loader",
        description="Load and validate the Elastic detection rules-as-code set; print a JSON summary.")
    ap.add_argument("--rules-dir", default=RULES_DIR)
    args = ap.parse_args(argv)
    # Validate the car-detections contract from the SAME rules dir, so a custom
    # --rules-dir is checked against its own car-detections/, not the built-in one.
    car_dir = os.path.join(args.rules_dir, "car-detections")
    cti_rule = os.path.join(args.rules_dir, "cti", "cti-indicator-match.yml")
    try:
        rules = list_rules(args.rules_dir)
        validate_car_detections(*load_car_detections(
            os.path.join(car_dir, "car-detections.index-template.json"),
            os.path.join(car_dir, "join-keys.yml")))
        # The CTI indicator-match contract is one per deployment, not per
        # detection: a rules dir that carries it is checked against the
        # built-in cti-* template; one that does not is not made to.
        if os.path.isfile(cti_rule):
            validate_indicator_match(*load_cti_contract(cti_rule, CTI_TEMPLATE))
    except (ValueError, OSError) as e:
        print(json.dumps({"tool": "rules", "error": str(e)}), file=sys.stderr)
        return 1
    print(json.dumps(summary(rules), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
