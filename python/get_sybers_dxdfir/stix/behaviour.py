"""Behaviour sightings — the detection lanes joined to the CAR entities they touch.

The north star is not *"run MITRE's CAR analytics"* — it is to let **threat
detections light up behaviour over the cascaded, cross-source-resolved data**. A
Suricata alert is one IP 5-tuple; a Hayabusa alert is one evtx record; a YARA hit
is one process. On their own they say *what* fired, not *which entity across the
rest of the evidence* it belongs to. This module performs that join — against the
finished CAR stores (``car.db``) the engine wrote — and emits each join as a STIX
2.1 **Sighting of the ATT&CK attack-pattern** the detection names, anchored to an
``observed-data`` **keyed on the matched CAR row's spindle ``guid``** (the same
behaviour-timeline entity every source of evidence converges onto).

Where :mod:`.export` sights the rule *indicator* over observed-data minted from
the detection's OWN fields, this sights the **attack-pattern** (BP §5.2:
MITRE's authoritative object id, referenced not copied — the consumer's ATT&CK
import holds it) over observed-data built from the **CAR entity** — so a bare C2
IP reads as its resolved domain and the connection, and an evtx record reads as
the process and its executable. The observed-data's identity IS the spindle guid
(``case_scoped_id`` keyed on it), so every detector that touches the same entity
references the SAME observation — the behaviour timeline as the primary axis.

Only what the evidence carries becomes STIX: a detection that names no resolvable
technique, or that joins to no CAR entity, is counted and skipped — never given an
invented attack-pattern or a fabricated entity. Reuses the exchange's object
builders (:mod:`.objects`), the authoritative ATT&CK index (:mod:`.attack_index`)
and :mod:`.export`'s bundle assembly / validation, so a behaviour bundle merges
object-for-object with the detection-export and PIIAT bundles.

Join keys (offline, against ``car.db`` directly — the Elastic-native provenance
join of ``detect/rules/*.car_join`` is a later phase):

    suricata  alert src/dest IP        -> CAR ``flow`` (src_ip / dest_ip)
    hayabusa  Sysmon ProcessGuid       -> CAR ``process`` (guid), else (host, pid)
    yara      memory match PID (+host) -> CAR ``process`` (pid)
              file/disk match hash     -> CAR ``file`` (sha256 / md5 / sha1)
"""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field

from . import objects as o
from .attack_index import AttackIndex, load_attack_index
from .export import make_bundle, summarise, validate_bundle

# CAR object tables the join reads (the engine's per-object store, one table
# per CAR object — see byakugan store.py, formerly PIIAT-MitreCar). Only these
# carry a joinable subject.
_FLOW_COLS = ("guid", "timestamp", "hostname", "fqdn", "src_ip", "dest_ip", "src_port",
              "dest_port", "transport_protocol", "application_protocol", "dest_fqdn", "src_fqdn")
_PROCESS_COLS = ("guid", "timestamp", "hostname", "fqdn", "pid", "command_line", "exe",
                 "image_path", "user", "sid", "md5_hash", "sha1_hash", "sha256_hash")
_FILE_COLS = ("guid", "timestamp", "hostname", "fqdn", "file_name", "file_path",
              "md5_hash", "sha1_hash", "sha256_hash")


# --------------------------------------------------------------------- CAR entities
@dataclass(frozen=True)
class CarRow:
    """One matched CAR entity: its spindle ``guid``, its object table, the host it
    belongs to, the observation instant and the columns the SCO builders need."""
    object_type: str                     # flow / process / file
    guid: str
    host: str | None
    timestamp: str | None                # STIX-normalised (UTC, ms) or None
    cols: dict

    @property
    def label(self) -> str:
        """A short human name for the entity (for a sighting's description)."""
        c = self.cols
        if self.object_type == "flow":
            dst = c.get("dest_fqdn") or c.get("dest_ip")
            return f"{c.get('src_ip') or '?'} -> {dst or '?'}"
        if self.object_type == "process":
            return os.path.basename(str(c.get("exe") or c.get("image_path") or "")) or f"pid {c.get('pid')}"
        return os.path.basename(str(c.get("file_path") or c.get("file_name") or "")) or self.guid


def _norm_ip(value) -> str | None:
    obj = o.ip_address(value)
    return obj["value"] if obj else None


class CarIndex:
    """Every joinable CAR entity across one or more ``car.db`` stores, indexed by
    the keys the detection lanes carry. Built once, queried per detection."""

    def __init__(self) -> None:
        self.flows_by_ip: dict[str, list[CarRow]] = {}
        self.flows_by_pair: dict[frozenset[str], list[CarRow]] = {}
        self.process_by_guid: dict[str, CarRow] = {}
        self.process_by_host_pid: dict[tuple[str, int], CarRow] = {}
        self.process_by_pid: dict[int, list[CarRow]] = {}
        self.file_by_hash: dict[str, CarRow] = {}
        self.stores: list[str] = []

    # -- ingest --------------------------------------------------------------
    def add_store(self, car_db: str) -> None:
        self.stores.append(car_db)
        db = sqlite3.connect(f"file:{car_db}?mode=ro", uri=True)
        try:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "flow" in tables:
                for row in self._rows(db, "flow", _FLOW_COLS):
                    self._add_flow(row)
            if "process" in tables:
                for row in self._rows(db, "process", _PROCESS_COLS):
                    self._add_process(row)
            if "file" in tables:
                for row in self._rows(db, "file", _FILE_COLS):
                    self._add_file(row)
        finally:
            db.close()

    @staticmethod
    def _rows(db, table, cols) -> Iterable[dict]:
        have = {r[1] for r in db.execute(f'PRAGMA table_info("{table}")')}
        picked = [c for c in cols if c in have]
        if "guid" not in picked:
            return
        for r in db.execute(f'SELECT {",".join(picked)} FROM "{table}"'):
            yield dict(zip(picked, r))

    def _row(self, object_type: str, c: dict) -> CarRow | None:
        guid = c.get("guid")
        if not guid:
            return None
        host = c.get("hostname") or c.get("fqdn")
        return CarRow(object_type, str(guid), str(host) if host else None,
                      o.stix_timestamp(c.get("timestamp")), c)

    def _add_flow(self, c: dict) -> None:
        row = self._row("flow", c)
        if row is None:
            return
        src, dst = _norm_ip(c.get("src_ip")), _norm_ip(c.get("dest_ip"))
        for ip in (src, dst):
            if ip:
                self.flows_by_ip.setdefault(ip, []).append(row)
        if src and dst:
            self.flows_by_pair.setdefault(frozenset((src, dst)), []).append(row)

    def _add_process(self, c: dict) -> None:
        row = self._row("process", c)
        if row is None:
            return
        # ProcessGuid is the strongest key; keep the FIRST (a process's create wins
        # over its later spoke events, which repeat the guid).
        self.process_by_guid.setdefault(row.guid.lower(), row)
        pid = _int(c.get("pid"))
        if pid is not None:
            self.process_by_pid.setdefault(pid, []).append(row)
            if row.host:
                self.process_by_host_pid.setdefault((row.host.lower(), pid), row)

    def _add_file(self, c: dict) -> None:
        row = self._row("file", c)
        if row is None:
            return
        for h in (c.get("sha256_hash"), c.get("sha1_hash"), c.get("md5_hash")):
            if h:
                self.file_by_hash.setdefault(str(h).lower(), row)

    # -- query ---------------------------------------------------------------
    def match(self, det: "Detection") -> list[CarRow]:
        """The CAR entities ``det`` touches (de-duplicated by guid, first-seen)."""
        found: list[CarRow] = []
        seen: set[str] = set()

        def take(row: CarRow | None) -> None:
            if row is not None and row.guid not in seen:
                seen.add(row.guid)
                found.append(row)

        if det.source == "suricata":
            # the specific connection (both endpoints) is the precise join; only when
            # the alert names a single endpoint do we widen to every flow it touched.
            pair = frozenset(det.ips)
            if len(pair) >= 2 and pair in self.flows_by_pair:
                for row in self.flows_by_pair[pair]:
                    take(row)
            else:
                for ip in det.ips:
                    for row in self.flows_by_ip.get(ip, ()):
                        take(row)
        elif det.source == "hayabusa":
            if det.process_guid:
                take(self.process_by_guid.get(det.process_guid.lower()))
            if not found and det.host and det.pid is not None:
                take(self.process_by_host_pid.get((det.host.lower(), det.pid)))
        elif det.source == "yara":
            for h in det.hashes:
                take(self.file_by_hash.get(h.lower()))
            if not found and det.pid is not None:
                if det.host and (det.host.lower(), det.pid) in self.process_by_host_pid:
                    take(self.process_by_host_pid.get((det.host.lower(), det.pid)))
                else:
                    for row in self.process_by_pid.get(det.pid, ()):
                        take(row)
        return found


def _int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------- detections
@dataclass
class Detection:
    """One normalised detection firing from a lane's raw output."""
    source: str                          # suricata / hayabusa / yara
    detection_id: str                    # the rules-as-code id (sig-*)
    name: str                            # the human title (signature / rule / title)
    techniques: list[str] = field(default_factory=list)
    timestamp: str | None = None
    host: str | None = None
    ips: list[str] = field(default_factory=list)
    process_guid: str | None = None
    pid: int | None = None
    process: str | None = None
    hashes: list[str] = field(default_factory=list)
    matched: dict = field(default_factory=dict)


def suricata_detections(path: str) -> list[Detection]:
    """Suricata EVE ``alert`` events -> detections. ATT&CK ids come from ET Open's
    ``alert.metadata.mitre_technique_id`` (BP: the reference projection)."""
    out: list[Detection] = []
    for rec in _jsonl(path):
        if rec.get("event_type") != "alert":
            continue
        alert = rec.get("alert") or {}
        meta = alert.get("metadata") or {}
        techs = o.technique_ids(meta.get("mitre_technique_id")) or o.technique_ids(meta)
        ips = [ip for ip in (_norm_ip(rec.get("src_ip")), _norm_ip(rec.get("dest_ip"))) if ip]
        out.append(Detection(
            source="suricata", detection_id="sig-suricata-alert",
            name=str(alert.get("signature") or "Suricata IDS alert"),
            techniques=techs, timestamp=o.stix_timestamp(rec.get("timestamp")),
            ips=ips, matched={"ips": ips, "signature_id": alert.get("signature_id")}))
    return out


# Hayabusa's JSON profile names the ProcessGuid / PID inside Details; the ATT&CK
# ids ride in MitreTags (the ¦-separated profile) or, failing that, OtherTags.
def hayabusa_detections(path: str) -> list[Detection]:
    """Hayabusa Sigma-over-EVTX timeline -> detections (Sysmon process events carry
    the ProcessGuid the CAR process is keyed on)."""
    out: list[Detection] = []
    for rec in _jsonl(path):
        details = rec.get("Details") if isinstance(rec.get("Details"), dict) else {}
        extra = rec.get("ExtraFieldInfo") if isinstance(rec.get("ExtraFieldInfo"), dict) else {}
        techs = o.technique_ids(rec.get("MitreTags")) or o.technique_ids(rec.get("OtherTags"))
        out.append(Detection(
            source="hayabusa", detection_id="sig-hayabusa-high",
            name=str(rec.get("RuleTitle") or "Hayabusa detection"),
            techniques=techs, timestamp=o.stix_timestamp(rec.get("Timestamp")),
            host=_str(rec.get("Computer")),
            process_guid=_str(details.get("PGUID") or details.get("ProcessGuid") or extra.get("ProcessGuid")),
            pid=_int(details.get("PID")), process=_str(details.get("Proc")),
            hashes=_hashes_from_hayabusa(details.get("Hashes")),
            matched={"record_id": rec.get("RecordID"), "channel": rec.get("Channel"),
                     "event_id": rec.get("EventID"), "level": rec.get("Level")}))
    return out


def yara_detections(path: str) -> list[Detection]:
    """YARA matches (``memory.jsonl`` / ``disk.jsonl`` / ``matches.jsonl``) ->
    detections. The parsed match carries a rule + PID/process (memory) or a
    target path (file/disk); ATT&CK ids are not in the parsed output."""
    out: list[Detection] = []
    for rec in _jsonl(path):
        if rec.get("tool") != "yara" or not rec.get("rule"):
            continue
        out.append(Detection(
            source="yara", detection_id="sig-yara-match", name=str(rec.get("rule")),
            techniques=o.technique_ids(rec.get("rule")), host=_str(rec.get("host")),
            pid=_int(rec.get("pid")), process=_str(rec.get("process")),
            matched={"rule": rec.get("rule"), "yara_source": rec.get("source"),
                     "target": rec.get("target"), "pid": rec.get("pid")}))
    return out


_DETECTION_FILES = {
    "suricata": (suricata_detections, ("suricata",), (".eve.jsonl",)),
    "hayabusa": (hayabusa_detections, ("hayabusa",), ("timeline.jsonl",)),
    "yara": (yara_detections, ("yara",), ("memory.jsonl", "disk.jsonl", "matches.jsonl")),
}


def load_detections(detections_dir: str) -> list[Detection]:
    """Every lane's output under ``<detections_dir>/<lane>/`` -> detections. A lane
    with no output contributes nothing (never an error)."""
    dets: list[Detection] = []
    for lane, (parser, subdirs, suffixes) in _DETECTION_FILES.items():
        for sub in subdirs:
            base = os.path.join(detections_dir, sub)
            if not os.path.isdir(base):
                continue
            for name in sorted(os.listdir(base)):
                if any(name.endswith(sfx) for sfx in suffixes):
                    dets.extend(parser(os.path.join(base, name)))
    return dets


# --------------------------------------------------------------- objects
def _entity_observation(row: CarRow, case: str, put, created_by: str) -> str | None:
    """The matched CAR entity as ONE connected ``observed-data`` graph, keyed on
    its spindle ``guid`` (so every detector that touches the entity references the
    same observation). ``None`` when the row carries nothing observable."""
    when = row.timestamp
    if not when:
        return None
    c = row.cols
    if row.object_type == "flow":
        src, dst = o.ip_address(c.get("src_ip")), o.ip_address(c.get("dest_ip"))
        if not (src or dst):
            return None
        graph: list[str] = []
        if src and dst:
            base = "ipv6" if dst["type"] == "ipv6-addr" else "ipv4"
            protos = [base] + [p for p in (c.get("transport_protocol"), c.get("application_protocol")) if p]
            traffic = o.network_traffic(put(src), put(dst), src_port=_int(c.get("src_port")),
                                        dst_port=_int(c.get("dest_port")), protocols=protos)
            graph += [put(traffic), src["id"], dst["id"]]
        else:
            graph.append(put(src or dst))
        # the spindle-resolved name on the flow — the "expand the alert beyond its
        # source": the C2 IP read as its domain (DNS + SNI, cross-source).
        dom = o.domain_name(c.get("dest_fqdn"))
        if dom and dst:
            dom["resolves_to_refs"] = [dst["id"]]
            graph.append(put(dom))
        return put(o.observed_data(case, row.guid, "network", graph, when, when, created_by=created_by))
    if row.object_type in ("process", "file"):
        name = os.path.basename(str(c.get("exe") or c.get("image_path") or c.get("file_path")
                                    or c.get("file_name") or "")) or None
        hashes = {k: c.get(v) for k, v in (("MD5", "md5_hash"), ("SHA-1", "sha1_hash"),
                                           ("SHA-256", "sha256_hash")) if c.get(v)}
        f = o.file_observable(name, hashes)
        if f is None:
            return None
        return put(o.observed_data(case, row.guid, row.object_type, [put(f)], when, when, created_by=created_by))
    return None


def behaviour_objects(detections: Iterable[Detection], car: CarIndex, *, case_id: str,
                      producer: str = o.DEFAULT_PRODUCER, tlp: str | None = "amber",
                      attack: AttackIndex | None = None,
                      contact: str | None = o.DEFAULT_CONTACT) -> tuple[dict[str, dict], dict]:
    """The object graph for ``detections`` joined to ``car``, keyed by id, plus a
    report. One ``sighting`` of the ATT&CK attack-pattern per (detection, entity,
    technique), over the entity's spindle-keyed ``observed-data``."""
    attack = attack or load_attack_index()
    marking_ref = o.tlp_marking_ref(tlp) if tlp and str(tlp).lower() not in ("none", "no", "off", "") else None
    objs: dict[str, dict] = {}
    report = {"detections": 0, "sightings": 0, "entities": 0, "skipped": {},
              "techniques": {"resolved": {}, "substituted": {}, "unresolved": []}}

    def put(obj: dict) -> str:
        o.mark(obj, marking_ref)
        objs.setdefault(obj["id"], obj)
        return obj["id"]

    def skip(reason: str) -> None:
        report["skipped"][reason] = report["skipped"].get(reason, 0) + 1

    created_by = put(o.producer_identity(producer, contact))
    put(o.extension_definition(created_by))
    matched_guids: set[str] = set()
    for det in detections:
        report["detections"] += 1
        # The cross-source join is judged FIRST: which CAR entity (if any) this
        # detection touches is the point — "expand the alert beyond its source" —
        # independent of whether the detection also names an ATT&CK technique.
        rows = car.match(det)
        if not rows:
            skip("no_car_entity")
            continue
        for row in rows:                        # every entity a detection flags counts
            matched_guids.add(row.guid)
        resolved = [(t, attack.resolve(t)) for t in dict.fromkeys(det.techniques)]
        for tid, r in resolved:
            if r is None and tid not in report["techniques"]["unresolved"]:
                report["techniques"]["unresolved"].append(tid)
        resolved = [(t, r) for t, r in resolved if r is not None]
        if not resolved:
            # the join is real (e.g. a suricata alert on the resolved C2 flow), but
            # the detection names no ATT&CK technique, so there is nothing to sight.
            skip("joined_no_technique")
            continue
        when = det.timestamp
        for row in rows:
            od = _entity_observation(row, case_id, put, created_by)
            if od is None:
                skip("entity_not_observable")
                continue
            where = [put(o.host_identity(row.host, created_by))] if row.host else None
            created = when or row.timestamp
            for tid, res in resolved:
                report["techniques"]["resolved"][tid] = res.technique.id
                if res.substituted:
                    report["techniques"]["substituted"][tid] = res.technique.external_id
                key = f"{det.detection_id}|{row.guid}|{tid}"
                put(o.sighting(
                    case_id, key, res.technique.id, created=created, created_by=created_by,
                    first_seen=when or row.timestamp, last_seen=when or row.timestamp,
                    observed_data_refs=[od], where_sighted_refs=where,
                    description=f"{det.name} — {row.label} ({res.technique.name})",
                    dx={"case_id": case_id, "detection_id": det.detection_id, "source": det.source,
                        "car_guid": row.guid, "car_object": row.object_type, "technique": tid,
                        "signature": det.name, "matched": det.matched or None}))
                report["sightings"] += 1
    report["entities"] = len(matched_guids)
    return objs, report


def build_behaviour_bundle(detections: Iterable[Detection], car: CarIndex, **kw) -> tuple[dict, dict]:
    """``detections`` joined to ``car`` -> ``(bundle, report)``."""
    objs, report = behaviour_objects(detections, car, **kw)
    return make_bundle(objs), report


def run_behaviour(*, car_paths: Iterable[str], detections_dir: str, case_id: str,
                  out: str | None = None, producer: str = o.DEFAULT_PRODUCER,
                  tlp: str | None = "amber", attack_index: str | None = None) -> tuple[dict, dict]:
    """Read the CAR stores + the lane outputs, join, assemble, validate, write
    (if ``out``). Returns ``(summary, bundle)``; ``summary['ok']`` is False when
    validation failed (nothing is written then)."""
    car = CarIndex()
    for p in _car_dbs(car_paths):
        car.add_store(p)
    detections = load_detections(detections_dir)
    attack = load_attack_index(attack_index)
    bundle, report = build_behaviour_bundle(detections, car, case_id=case_id, producer=producer,
                                            tlp=tlp, attack=attack)
    errors, warnings = validate_bundle(bundle, external_ids=attack.ids)
    summary = {"tool": "stix-behaviour-sightings", "case_id": case_id,
               "car_stores": car.stores, "detections_dir": detections_dir,
               "report": report, "attack_version": attack.attack_version,
               "summary": summarise(bundle), "bundle_id": bundle.get("id"),
               "validation": {"errors": errors, "warnings": warnings},
               "bundle": None, "ok": not errors}
    if not errors and out:
        from .export import write_bundle
        write_bundle(bundle, out)
        summary["bundle"] = out
    return summary, bundle


# ------------------------------------------------------------------- small helpers
def _car_dbs(paths: Iterable[str]) -> list[str]:
    """Resolve each path to the ``car.db`` files under it (a file is taken as-is; a
    directory is walked for every ``car.db``)."""
    found: list[str] = []
    for p in paths:
        if os.path.isfile(p):
            found.append(p)
        elif os.path.isdir(p):
            for cur, _dirs, files in os.walk(p):
                if "car.db" in files:
                    found.append(os.path.join(cur, "car.db"))
    return sorted(dict.fromkeys(found))


def _jsonl(path: str) -> Iterable[dict]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                yield rec


def _str(value) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _hashes_from_hayabusa(value) -> list[str]:
    """Sysmon's ``Hashes`` field ("SHA256=...,MD5=...") or a dict -> raw digests."""
    out: list[str] = []
    if isinstance(value, dict):
        out = [str(v) for v in value.values() if v]
    elif isinstance(value, str):
        for part in value.replace(";", ",").split(","):
            _algo, _, digest = part.partition("=")
            if digest:
                out.append(digest.strip())
    return [h for h in out if h]
