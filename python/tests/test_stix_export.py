"""Unit tests for the STIX 2.1 export + OpenCTI exchange scaffold (no network).

The shape under test is the STIX Best Practices one: indicators are the real
rules (dated by the rule file, so a re-export is the same version), sightings
reference MITRE's own ATT&CK ids through `indicates`, observations are
connected SCO graphs, DX_DFIR's own properties travel in one extension
definition, TLP is referenced never shipped, SCOs are never marked.
"""
import datetime
import json
import pathlib
import re
import uuid

import pytest
import yaml

from get_sybers_dxdfir.detect import rules_loader as rl
from get_sybers_dxdfir.stix import cli as stix_cli
from get_sybers_dxdfir.stix import attack_index, config, export, hits, objects, opencti

SCO_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
REPO = pathlib.Path(__file__).resolve().parents[2]
TS_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")     # §2.10 / BP §4.5: UTC, exactly three digits
AMBER = objects.TLP_MARKING_IDS["amber"]

# One misc.Detections row exactly as `dxdfir detect --jsonl-out` writes it.
ENVELOPE = {
    "RunId": "20260902T090000Z-abcd1234", "DetectionId": "win-eventlog-cleared",
    "Title": "Windows event log cleared", "Severity": "high", "AttackIds": "T1070.001",
    "Source": "host.EvtxEcmdJson", "Timestamp": "2026-08-31T12:11:53.899000Z",
    "Entity": "PC1", "Details": {"EventId": 1102, "Channel": "Security", "Computer": "PC1"},
    "DetectedAt": "2026-09-02T09:00:01.000000Z",
}
# A signature-lane row: Details came back from Kusto as a JSON string, the
# entity is the "src -> dst:port" shape, AttackIds carries the ET Open form.
SURICATA = {
    "RunId": "20260902T090000Z-abcd1234", "DetectionId": "sig-suricata-alert",
    "Title": "Suricata IDS alert", "Severity": "medium", "AttackIds": "T1204,t1059_003",
    "Source": "signatures/suricata", "Timestamp": "2026-08-31 12:11:53.899 +00:00",
    "Entity": "10.0.0.5 -> 203.0.113.9:443",
    "Details": '{"Signature": "ET MALWARE beacon", "SignatureId": 2000001, "proto": "TCP"}',
    "DetectedAt": "2026-09-02T09:00:02.000000Z",
}
# A Byakugan tagged evidence line (query-stamped) with car-detections provenance.
STAMPED = {
    "@timestamp": "2026-08-31T12:00:00Z", "host": {"name": "PC2"},
    "event": {"id": "car-guid-123", "code": "7045"},
    "rule": {"id": "win-service-suspicious-path", "name": "Service installed from a suspicious path"},
    "threat": {"technique": {"id": ["T1543.003"], "name": ["Windows Service"]}},
    "detection": {"severity": "high", "run_id": "run-es-1", "detected_at": "2026-09-02T09:30:00Z",
                  "source_index": "logs-dxdfir.evtx-case17"},
    "file": {"name": "evil.exe", "hash": {"sha256": "a" * 64, "md5": "b" * 32}},
    "kibana": {"alert": {"uuid": "ignored-bookkeeping"}},
}


def _write_rule(d, rid, *, query, language="esql", attack=(), tactics=(), created="2026-09-02",
                updated=None, name=None, severity="high", status="ported"):
    doc = {"id": rid, "name": name or rid, "status": status, "severity": severity, "attack": list(attack),
           "tactics": list(tactics), "language": language, "query": query}
    if created:
        doc["created"] = created
    if updated:
        doc["updated"] = updated
    (d / f"{rid}.yml").write_text(yaml.safe_dump(doc))


@pytest.fixture(scope="module")
def rules(tmp_path_factory):
    """A rules-as-code directory: the rules the fixtures' hits name (the
    Suricata one ported here, unlike in the package), a stub and an undated one."""
    d = tmp_path_factory.mktemp("rules")
    _write_rule(d, "win-eventlog-cleared", query='any where event.code == "1102"', language="eql",
                attack=["T1070.001"], tactics=["TA0005"], name="Windows event log cleared")
    _write_rule(d, "sig-suricata-alert", query='FROM logs-dxdfir.suricata-* | WHERE suricata.eve.event_type == "alert"',
                severity="medium", name="Suricata IDS alert")
    _write_rule(d, "win-service-suspicious-path", query='FROM logs-dxdfir.evtx-* | WHERE event.code == "7045"',
                attack=["T1543.003"], created="2026-09-01", updated="2026-09-02",
                name="Service installed from a suspicious path")
    _write_rule(d, "vol-malfind-injection", query=None, status="stub")
    _write_rule(d, "undated-rule", query="FROM logs-dxdfir.x-* | LIMIT 1", created=None)
    return export.rules_source(str(d))


@pytest.fixture(scope="module")
def attack():
    return attack_index.load_attack_index()


def _by_type(bundle, t):
    return [x for x in bundle["objects"] if x["type"] == t]


def _one(bundle, t):
    found = _by_type(bundle, t)
    assert len(found) == 1, f"expected one {t}, got {len(found)}"
    return found[0]


def _hit(doc):
    h = hits.hit_from_document(doc)
    assert h is not None
    return h


def _bundle(rules, *docs, **kw):
    return export.build_bundle([_hit(d) if isinstance(d, dict) else d for d in docs], rules=rules, **kw)


def _ext(obj):
    return objects.extension_of(obj)


# ---- primitives ------------------------------------------------------------
def test_technique_ids_normalises_and_dedupes():
    assert objects.technique_ids("T1204,t1059_003 ¦ T1204") == ["T1204", "T1059.003"]
    assert objects.technique_ids(["attack.t1112", "TA0005", None]) == ["T1112"]
    assert objects.technique_ids(None) == [] and objects.technique_ids("") == []


def test_stix_timestamp_is_utc_millisecond_precision():
    ts = objects.stix_timestamp
    assert ts("2026-08-31T12:11:53.899000Z") == "2026-08-31T12:11:53.899Z"
    assert ts("2018-03-27 12:11:53.899 +00:00") == "2018-03-27T12:11:53.899Z"   # hayabusa
    assert ts("2011-06-18T18:17:15.107810+0000") == "2011-06-18T18:17:15.107Z"  # suricata
    assert ts("2020-01-02T03:04:05+02:00") == "2020-01-02T01:04:05.000Z"        # offset folded
    assert ts("2020-01-02T03:04:05") == "2020-01-02T03:04:05.000Z"              # naive = UTC
    assert ts(1735689600000) == "2025-01-01T00:00:00.000Z"                      # epoch ms
    assert ts(1735689600) == "2025-01-01T00:00:00.000Z"                         # epoch s
    assert ts(datetime.date(2026, 9, 2)) == "2026-09-02T00:00:00.000Z"          # a rule file's created
    assert ts(datetime.datetime(2026, 9, 2, 7, 1, 4, 500000)) == "2026-09-02T07:01:04.500Z"
    assert ts(None) is None and ts("") is None and ts("not a time") is None and ts(True) is None


def test_sco_ids_follow_the_spec():
    # §2.9: uuid5 under the STIX SCO namespace over the canonical JSON of the
    # id-contributing properties — computed here independently of the package.
    ip = objects.ip_address("1.1.1.1")
    assert ip["type"] == "ipv4-addr" and ip["spec_version"] == "2.1"
    assert ip["id"] == "ipv4-addr--" + str(uuid.uuid5(SCO_NS, '{"value":"1.1.1.1"}'))
    assert objects.ip_address("2001:db8::1")["type"] == "ipv6-addr"
    assert objects.ip_address("PC1") is None                     # not an address: nothing invented
    # file: ONE hash contributes (MD5 preferred over SHA-256), plus the name
    f = objects.file_observable("evil.exe", {"SHA-256": "a" * 64, "MD5": "b" * 32})
    expect = '{"hashes":{"MD5":"' + "b" * 32 + '"},"name":"evil.exe"}'
    assert f["id"] == "file--" + str(uuid.uuid5(SCO_NS, expect))
    assert f["hashes"] == {"MD5": "b" * 32, "SHA-256": "a" * 64}   # all hashes still carried
    assert objects.file_observable(None, {}) is None
    # network-traffic (§6.12): src_ref / dst_ref / ports / protocols contribute; protocols is required
    dst = objects.ip_address("203.0.113.9")
    nt = objects.network_traffic(ip["id"], dst["id"], dst_port=443, protocols=["ipv4", "TCP"])
    expect = '{"dst_port":443,"dst_ref":"%s","protocols":["ipv4","tcp"],"src_ref":"%s"}' % (dst["id"], ip["id"])
    assert nt["id"] == "network-traffic--" + str(uuid.uuid5(SCO_NS, expect))
    assert (nt["src_ref"], nt["dst_ref"], nt["dst_port"], nt["protocols"]) == (ip["id"], dst["id"], 443, ["ipv4", "tcp"])
    assert "src_port" not in nt and nt["spec_version"] == "2.1"
    assert objects.network_traffic(None, None, protocols=["ipv4"]) is None
    assert objects.network_traffic(ip["id"], dst["id"], protocols=[]) is None


def test_relationship_requires_a_class():
    with pytest.raises(ValueError):
        objects.relationship("indicator--x", "attack-pattern--y", "indicates", created="2026-09-02T00:00:00.000Z",
                             modified=None, created_by="identity--p", relationship_class="guessed")


def test_markings_are_referenced_never_shipped_and_never_on_scos():
    assert objects.tlp_marking_ref("AMBER") == AMBER
    with pytest.raises(ValueError):
        objects.tlp_marking_ref("black")
    ip = objects.mark(objects.ip_address("1.1.1.1"), AMBER)
    assert "object_marking_refs" not in ip                                   # BP §3.5
    assert "object_marking_refs" not in objects.mark(objects.tlp_marking("amber"), AMBER)
    sighting = objects.mark({"type": "sighting", "id": "sighting--x"}, AMBER)
    assert sighting["object_marking_refs"] == [AMBER]


# ---- hits -> objects -------------------------------------------------------
def test_envelope_hit_becomes_sighting_indicator_and_technique(rules, attack):
    bundle = _bundle(rules, ENVELOPE, case_id="CASE-1", stack_version="9.4.3")
    sighting, indicator = _one(bundle, "sighting"), _one(bundle, "indicator")
    identities = _by_type(bundle, "identity")
    assert sighting["spec_version"] == "2.1" and sighting["id"].startswith("sighting--")
    assert sighting["sighting_of_ref"] == indicator["id"]
    assert sighting["first_seen"] == sighting["last_seen"] == "2026-08-31T12:11:53.899Z"
    assert sighting["created"] == sighting["modified"] == "2026-09-02T09:00:01.000Z"   # DetectedAt: stable
    assert sighting["count"] == 1 and sighting["description"] == "Windows event log cleared — PC1"
    # DX_DFIR's own properties: the ONE extension, nothing else (no x_ anywhere)
    assert _ext(sighting) == {"case_id": "CASE-1", "run_id": ENVELOPE["RunId"], "detection_id": "win-eventlog-cleared",
                              "severity": "high", "source": "host.EvtxEcmdJson"}
    assert sighting["extensions"][objects.EXTENSION_ID]["extension_type"] == "property-extension"
    assert not any(k.startswith("x_") for x in bundle["objects"] for k in x)
    # the indicator IS the rule: its query, its language, its dates (§3.2 / §3.6)
    assert indicator["name"] == "Windows event log cleared"
    assert indicator["pattern"] == 'any where event.code == "1102"' and indicator["pattern_type"] == "eql"
    assert indicator["pattern_version"] == "9.4.3"
    assert indicator["created"] == indicator["modified"] == indicator["valid_from"] == "2026-09-02T00:00:00.000Z"
    assert indicator["indicator_types"] == ["malicious-activity"]
    assert indicator["external_references"] == [
        {"source_name": "dxdfir", "external_id": "win-eventlog-cleared",
         "url": export.RULE_URL.format(id="win-eventlog-cleared")},
        {"source_name": "mitre-attack", "external_id": "T1070.001",
         "url": "https://attack.mitre.org/techniques/T1070/001/"}]
    assert _ext(indicator) == {"detection_id": "win-eventlog-cleared", "severity": "high", "status": "ported"}
    phases = indicator["kill_chain_phases"]
    assert phases and all(p["kill_chain_name"] == "mitre-attack" for p in phases)
    assert attack.tactics["TA0005"] in {p["phase_name"] for p in phases}
    # indicates -> MITRE's authoritative attack-pattern id (BP §5.2); no local copy in the bundle
    rel = _one(bundle, "relationship")
    target = attack.resolve("T1070.001").technique.id
    assert target.startswith("attack-pattern--") and target in attack.ids
    assert (rel["relationship_type"], rel["source_ref"], rel["target_ref"]) == ("indicates", indicator["id"], target)
    assert _ext(rel) == {"relationship_class": "declared"} and "labels" not in rel
    assert rel["created"] == rel["modified"] == "2026-09-02T00:00:00.000Z"
    assert not _by_type(bundle, "attack-pattern")
    # Details.Computer -> the host identity that saw it; the producer created everything, with contact (BP §3.4)
    producer = next(i for i in identities if i["name"] == "DX_DFIR")
    host = next(i for i in identities if i["name"] == "PC1")
    assert producer["contact_information"] == objects.DEFAULT_CONTACT
    assert producer["created"] == objects.IDENTITY_CREATED and producer["modified"] == objects.IDENTITY_MODIFIED
    assert host["identity_class"] == "system" and sighting["where_sighted_refs"] == [host["id"]]
    assert all(x.get("created_by_ref") == producer["id"] for x in bundle["objects"] if x["id"] != producer["id"])
    # the extension definition rides along (§7.3, BP §9): id, schema URL, version, docs reference
    ext = _one(bundle, "extension-definition")
    assert ext["id"] == objects.EXTENSION_ID and ext["extension_types"] == ["property-extension"]
    assert ext["schema"] == objects.EXTENSION_SCHEMA_URL and ext["version"] == objects.EXTENSION_VERSION
    assert ext["external_references"][0]["url"] == objects.EXTENSION_DOC_URL and ext["created_by_ref"] == producer["id"]
    # TLP amber by default: REFERENCED by every SDO / SRO, the marking object itself never shipped (BP §3.5)
    assert not _by_type(bundle, "marking-definition")
    assert all(x["object_marking_refs"] == [AMBER] for x in bundle["objects"]
               if x["type"] not in ("extension-definition",))
    assert export.validate_bundle(bundle, external_ids=attack.ids) == ([], [])


def test_ids_and_created_are_stable_across_exports(rules):
    a = _bundle(rules, ENVELOPE, case_id="CASE-A")
    b = _bundle(rules, ENVELOPE, case_id="CASE-B")
    again = _bundle(rules, ENVELOPE, case_id="CASE-A")
    for t in ("indicator", "relationship", "extension-definition"):
        assert _one(a, t)["id"] == _one(b, t)["id"]           # content-keyed: global
        assert _one(a, t)["created"] == _one(b, t)["created"]  # and dated by content: never the export clock
    assert {i["id"] for i in _by_type(a, "identity")} == {i["id"] for i in _by_type(b, "identity")}
    assert _one(a, "sighting")["id"] != _one(b, "sighting")["id"]   # observation: case-scoped
    assert a == again and a["id"] != b["id"]                          # idempotent per case, byte for byte


def test_rule_dates_version_the_indicator(tmp_path):
    # STIX 2.1 §3.2: created never changes; §3.6: only a material change bumps modified
    d = tmp_path / "rules"
    d.mkdir()
    _write_rule(d, "win-eventlog-cleared", query="FROM logs-dxdfir.evtx-* | LIMIT 1", created="2026-08-01",
                updated="2026-08-15T10:00:00Z")
    first = _one(_bundle(export.rules_source(str(d)), ENVELOPE), "indicator")
    assert (first["created"], first["valid_from"], first["modified"]) == \
        ("2026-08-01T00:00:00.000Z", "2026-08-01T00:00:00.000Z", "2026-08-15T10:00:00.000Z")
    _write_rule(d, "win-eventlog-cleared", query="FROM logs-dxdfir.evtx-* | LIMIT 2", created="2026-08-01",
                updated="2026-09-01")
    second = _one(_bundle(export.rules_source(str(d)), ENVELOPE), "indicator")
    assert second["id"] == first["id"] and second["created"] == first["created"]
    assert second["modified"] == "2026-09-01T00:00:00.000Z" and second["pattern"].endswith("LIMIT 2")
    # updated before created is clamped, an undated rule is not exported
    _write_rule(d, "win-eventlog-cleared", query="FROM x", created="2026-08-01", updated="2026-07-01")
    assert _one(_bundle(export.rules_source(str(d)), ENVELOPE), "indicator")["modified"] == "2026-08-01T00:00:00.000Z"


def test_arrow_entity_yields_a_connected_network_observation(rules, attack):
    h = _hit(SURICATA)
    assert (h.source_ip, h.destination_ip, h.destination_port) == ("10.0.0.5", "203.0.113.9", 443)
    assert h.transport == "tcp" and h.protocol is None
    assert h.details["Signature"] == "ET MALWARE beacon"                  # string parsed
    assert h.attack_ids == ["T1204", "T1059.003"]
    assert h.timestamp == "2026-08-31T12:11:53.899Z"
    bundle = _bundle(rules, h)
    ips = {x["value"]: x for x in _by_type(bundle, "ipv4-addr")}
    assert set(ips) == {"10.0.0.5", "203.0.113.9"}
    # §4.14 / BP §5.9: the addresses hang off a network-traffic root — a connected graph, not a bag
    nt = _one(bundle, "network-traffic")
    assert (nt["src_ref"], nt["dst_ref"], nt["dst_port"], nt["protocols"]) == \
        (ips["10.0.0.5"]["id"], ips["203.0.113.9"]["id"], 443, ["ipv4", "tcp"])
    od = _one(bundle, "observed-data")
    assert od["object_refs"] == [nt["id"], ips["10.0.0.5"]["id"], ips["203.0.113.9"]["id"]]
    assert od["first_observed"] == od["last_observed"] == od["created"] == h.timestamp and od["number_observed"] == 1
    assert _one(bundle, "sighting")["observed_data_refs"] == [od["id"]]
    # the observation is marked, the observables are not (BP §3.5)
    assert od["object_marking_refs"] == [AMBER]
    assert all("object_marking_refs" not in x for x in bundle["objects"] if objects.is_sco(x))
    # techniques the HIT carries but the rule does not declare are DERIVED relationships to MITRE's ids
    rels = _by_type(bundle, "relationship")
    assert {r["target_ref"] for r in rels} == {attack.resolve(t).technique.id for t in ("T1204", "T1059.003")}
    assert all(_ext(r) == {"relationship_class": "derived"} for r in rels)
    assert _one(bundle, "indicator")["external_references"] == [
        {"source_name": "dxdfir", "external_id": "sig-suricata-alert", "url": export.RULE_URL.format(id="sig-suricata-alert")}]
    # no case given: the run id scopes the observations
    assert _ext(_one(bundle, "sighting"))["case_id"] == SURICATA["RunId"]
    assert export.validate_bundle(bundle, external_ids=attack.ids) == ([], [])


def test_connection_and_file_are_separate_observations(rules):
    doc = {**STAMPED, "source": {"ip": "10.1.1.1", "port": 51000}, "destination": {"ip": "2001:db8::9", "port": 53},
           "network": {"transport": "udp", "protocol": "dns"}}
    h = _hit(doc)
    assert (h.source_port, h.destination_port, h.transport, h.protocol) == (51000, 53, "udp", "dns")
    bundle = _bundle(rules, h, case_id="CASE-17")
    nt = _one(bundle, "network-traffic")
    assert nt["protocols"] == ["ipv6", "udp", "dns"] and nt["src_port"] == 51000 and nt["dst_port"] == 53
    assert nt["src_ref"] == _one(bundle, "ipv4-addr")["id"] and nt["dst_ref"] == _one(bundle, "ipv6-addr")["id"]
    ods = {tuple(sorted(x["object_refs"])): x for x in _by_type(bundle, "observed-data")}
    assert len(ods) == 2
    f = _one(bundle, "file")
    assert f["name"] == "evil.exe" and (f["id"],) in ods                      # the file on its own
    network = next(x for refs, x in ods.items() if nt["id"] in refs)
    assert set(network["object_refs"]) == {nt["id"], nt["src_ref"], nt["dst_ref"]}
    s = _one(bundle, "sighting")
    assert set(s["observed_data_refs"]) == {x["id"] for x in ods.values()}
    assert _ext(s)["car_guid"] == "car-guid-123" and _ext(s)["source"] == "logs-dxdfir.evtx-case17"
    assert "details" not in _ext(s) and "entity" not in _ext(s)                 # raw evidence is not exported


def test_entities_that_are_not_addresses_produce_no_observables(rules):
    assert hits.arrow_endpoints("? -> 2.2.2.2:80") == (None, None, None)
    assert hits.arrow_endpoints("PC1: PSEXEC.EXE") == (None, None, None)
    bundle = _bundle(rules, {**ENVELOPE, "Entity": "svchost.exe (pid 4)", "Details": {}})
    assert not _by_type(bundle, "observed-data") and not _by_type(bundle, "ipv4-addr")
    assert "where_sighted_refs" not in _one(bundle, "sighting")
    # a lone address is its own (trivially connected) observation — no network-traffic root without a peer
    lone = _bundle(rules, {**{k: v for k, v in STAMPED.items() if k != "file"}, "source": {"ip": "10.9.9.9"}})
    od = _one(lone, "observed-data")
    assert od["object_refs"] == [_one(lone, "ipv4-addr")["id"]] and not _by_type(lone, "network-traffic")


def test_identical_rows_collapse_into_one_sighting_with_count(rules):
    bundle = _bundle(rules, ENVELOPE, ENVELOPE, SURICATA)
    sightings = _by_type(bundle, "sighting")
    assert sorted(s["count"] for s in sightings) == [1, 2]
    assert len(_by_type(bundle, "indicator")) == 2


def test_hits_without_an_exportable_rule_are_skipped_and_counted(rules):
    stub = {**ENVELOPE, "DetectionId": "vol-malfind-injection"}
    unknown = {**ENVELOPE, "DetectionId": "nope-rule"}
    undated = {**ENVELOPE, "DetectionId": "undated-rule"}
    objs, report = export.hit_objects([_hit(stub), _hit(unknown), _hit(undated), _hit(ENVELOPE)], rules=rules)
    assert report["sightings"] == 1 and report["hits"] == 4
    assert report["skipped"] == {"stub_rule": 1, "no_rule": 1, "undated_rule": 1}
    assert rules.reason("vol-malfind-injection") == "stub_rule" and rules.reason("win-eventlog-cleared") == "ok"
    assert [x["type"] for x in objs.values()].count("indicator") == 1
    # a reference pattern is never invented for them
    assert not any("x-dxdfir" in json.dumps(x) for x in objs.values())
    # a hit with no time at all cannot be an observation either
    _, report = export.hit_objects([_hit({**ENVELOPE, "Timestamp": None, "DetectedAt": None})], rules=rules)
    assert report["skipped"] == {"undated_hit": 1}


def test_revoked_and_unknown_techniques(rules, attack):
    objs, report = export.hit_objects([_hit({**ENVELOPE, "AttackIds": "T1070.001, T9999"})], rules=rules)
    resolved = attack.resolve("T1070.001")
    assert resolved.substituted                                     # revoked in ATT&CK 19: follows revoked-by
    assert report["techniques"]["substituted"] == {"T1070.001": resolved.technique.external_id}
    assert report["techniques"]["resolved"] == {"T1070.001": resolved.technique.id}
    assert report["techniques"]["unresolved"] == ["T9999"]
    rels = [x for x in objs.values() if x["type"] == "relationship"]
    assert [r["target_ref"] for r in rels] == [resolved.technique.id]     # nothing invented for T9999


def test_elastic_stamped_line_is_read(rules):
    h = _hit(STAMPED)
    assert h.detection_id == "win-service-suspicious-path"
    assert h.attack_ids == ["T1543.003"] and h.technique_names == {"T1543.003": "Windows Service"}
    assert (h.host, h.entity, h.severity, h.run_id) == ("PC2", "PC2", "high", "run-es-1")
    assert h.car_guid == "car-guid-123" and h.source == "logs-dxdfir.evtx-case17"
    assert h.file_name == "evil.exe" and h.file_hashes == {"MD5": "b" * 32, "SHA-256": "a" * 64}
    assert h.timestamp == "2026-08-31T12:00:00.000Z" and h.detected_at == "2026-09-02T09:30:00.000Z"
    assert "kibana.alert.uuid" not in h.details and h.details["event.code"] == "7045"
    bundle = _bundle(rules, h, case_id="CASE-17")
    assert _one(bundle, "file")["name"] == "evil.exe"
    assert _ext(_one(bundle, "sighting"))["car_guid"] == "car-guid-123"
    ind = _one(bundle, "indicator")
    assert ind["created"] == "2026-09-01T00:00:00.000Z" and ind["modified"] == "2026-09-02T00:00:00.000Z"
    assert _one(bundle, "relationship")["extensions"][objects.EXTENSION_ID]["relationship_class"] == "declared"


def test_kibana_alert_threat_block_is_read():
    alert = {"kibana": {"alert": {
        "rule": {"rule_id": "win-defender-tamper", "name": "Defender tamper",
                 "threat": [{"framework": "MITRE ATT&CK",
                             "technique": [{"id": "T1562", "name": "Impair Defenses",
                                            "subtechnique": [{"id": "T1562.001", "name": "Disable Tools"}]}]}]},
        "severity": "medium", "original_time": "2026-08-31T12:00:00Z"}},
        "host.name": "PC3", "source.ip": "10.1.1.1", "destination.ip": "10.2.2.2", "destination.port": "445",
        "source.port": "70000"}
    h = _hit(alert)
    assert h.detection_id == "win-defender-tamper" and h.title == "Defender tamper"
    assert h.attack_ids == ["T1562", "T1562.001"]
    assert h.technique_names["T1562.001"] == "Disable Tools"
    assert h.host == "PC3" and h.destination_port == 445 and h.severity == "medium"
    assert h.source_port is None                                         # not a port: nothing invented
    # a document that names no detection is not a hit — never guessed
    assert hits.hit_from_document({"event": {"id": "x"}, "host": {"name": "PC9"}}) is None
    assert hits.hit_from_document({"DetectionId": ""}) is None


def test_read_hits_accepts_jsonl_array_and_search_response(tmp_path):
    jsonl = tmp_path / "hits.jsonl"
    jsonl.write_text(json.dumps(ENVELOPE) + "\n\nnot json\n" + json.dumps(SURICATA) + "\n")
    found, report = hits.read_hits(str(jsonl))
    assert [h.detection_id for h in found] == ["win-eventlog-cleared", "sig-suricata-alert"]
    assert report["documents"] == 3 and report["hits"] == 2 and report["skipped"] == 1
    array = tmp_path / "hits.json"
    array.write_text(json.dumps([ENVELOPE, {"event": {"id": "context-row"}}]))
    found, report = hits.read_hits(str(array))
    assert len(found) == 1 and report["skipped"] == 1
    search = tmp_path / "search.json"
    search.write_text(json.dumps({"took": 1, "hits": {"total": {"value": 1}, "hits": [
        {"_index": "logs-dxdfir.evtx-case17", "_id": "abc", "_source": STAMPED}]}}))
    found, _ = hits.read_hits(str(search))
    assert len(found) == 1 and found[0].source == "logs-dxdfir.evtx-case17"
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"type": "bundle", "id": "bundle--x", "objects": []}))
    with pytest.raises(ValueError):
        hits.read_hits(str(bundle))


def test_every_shipped_ported_rule_exports_and_stubs_are_skipped():
    # the package's own rules are the default rules directory; each ported one is an indicator
    assert export.PACKAGE_RULES_DIR == rl.RULES_DIR
    shipped = rl.list_rules()
    docs = [{**ENVELOPE, "DetectionId": r["id"], "AttackIds": ",".join(r["attack"])} for r in shipped]
    objs, report = export.hit_objects([_hit(d) for d in docs], case_id="CASE-ALL")
    by_rule = {_ext(x)["detection_id"]: x for x in objs.values() if x["type"] == "indicator"}
    for r in shipped:
        if r["status"] == "ported":
            ind = by_rule[r["id"]]
            assert ind["pattern"] == r["query"].strip() and ind["pattern_type"] == r["language"]
            assert ind["created"] == objects.stix_timestamp(r["created"])
            assert ind["modified"] == objects.stix_timestamp(r.get("updated", r["created"]))
            assert _ext(ind)["status"] == "ported" and _ext(ind)["severity"] == r["severity"]
        else:
            assert r["id"] not in by_rule
    assert report["skipped"] == {"stub_rule": len(rl.stubs(shipped))}
    assert report["sightings"] == len(rl.ported(shipped))
    assert report["techniques"]["unresolved"] == []


def test_stack_version_default_matches_the_deployed_stack():
    # pattern_version = the Elastic stack the rules run on (STIX 2.1 §4.7); one pin, ansible's
    defaults = yaml.safe_load((REPO / "ansible/collections/get_sybers.dxdfir/roles/dxdfir_deploy_sofelk/defaults/main.yml")
                              .read_text())
    assert defaults["dxdfir_deploy_sofelk_elastic_version"] == config.DEFAULT_STACK_VERSION
    assert set(export.TRUST_GROUP_PATTERN_TYPES) >= {"esql", "eql", "kuery"}
    assert not set(export.TRUST_GROUP_PATTERN_TYPES) & set(export.PATTERN_TYPE_OV)
    readme = (REPO / "python/get_sybers_dxdfir/stix/README.md").read_text()
    assert "pattern_version" in readme and "pattern-type-ov" in readme      # BP §8.1: documented trust-group values


def test_extension_schema_covers_everything_emitted(rules):
    schema = json.loads((REPO / "python/get_sybers_dxdfir/stix/extension/dxdfir-extension.schema.json").read_text())
    assert schema["$id"] == objects.EXTENSION_SCHEMA_URL and objects.EXTENSION_ID in schema["description"]
    assert schema["additionalProperties"] is False and schema["properties"]["extension_type"] == {"const": "property-extension"}
    bundle = _bundle(rules, ENVELOPE, SURICATA, STAMPED)
    seen = set()
    for x in bundle["objects"]:
        for k, v in _ext(x).items():
            assert k in schema["properties"], (x["type"], k)
            seen.add(k)
            if isinstance(v, dict):
                assert set(v) <= set(schema["properties"][k]["properties"]), (k, v)
    assert {"detection_id", "severity", "status", "case_id", "run_id", "car_guid", "source", "relationship_class"} <= seen


# ---- the bundle ------------------------------------------------------------
def test_bundle_is_well_formed(rules, attack):
    bundle = _bundle(rules, ENVELOPE, SURICATA, STAMPED)
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    uuid.UUID(bundle["id"].split("--", 1)[1])
    ids = [x["id"] for x in bundle["objects"]]
    assert len(ids) == len(set(ids))
    assert all(x["spec_version"] == "2.1" for x in bundle["objects"])
    for x in bundle["objects"]:
        for k in ("created", "modified", "first_seen", "last_seen", "valid_from", "first_observed", "last_observed"):
            if k in x:
                assert TS_RE.match(x[k]), (x["id"], k, x[k])
        assert not any(k.startswith("x_") for k in x) and not x["type"].startswith("x-")
    errors, warnings = export.validate_bundle(bundle, external_ids=attack.ids)
    assert errors == [] and warnings == []            # every *_ref(s) resolves: here or in MITRE's repository
    json.loads(json.dumps(bundle))                    # serialisable as-is
    assert export.bundle_id(bundle["objects"]) == bundle["id"]
    summary = export.summarise(bundle)
    assert summary["sightings"] == 3 and summary["indicators"] == 3
    assert summary["relationship_classes"] == {"declared": 2, "derived": 2}
    assert summary["by_type"]["extension-definition"] == 1 and "marking-definition" not in summary["by_type"]


def test_validate_bundle_flags_defects(rules, attack):
    ok = _bundle(rules, SURICATA)
    assert export.validate_bundle({"type": "report"})[0]
    dup = json.loads(json.dumps(ok))
    dup["objects"].append(dict(dup["objects"][-1]))
    assert any("duplicate id" in e for e in export.validate_bundle(dup)[0])
    bad = json.loads(json.dumps(ok))
    bad["objects"][0]["id"] = "indicator--" + bad["objects"][0]["id"].split("--", 1)[1]
    assert any("does not match type" in e for e in export.validate_bundle(bad)[0])
    # a dangling reference warns; one into MITRE's repository (external_ids) does not; the spec's TLP ids never
    dangling = json.loads(json.dumps(ok))
    next(x for x in dangling["objects"] if x["type"] == "sighting")["sighting_of_ref"] = \
        "indicator--00000000-0000-4000-8000-000000000000"
    errors, warnings = export.validate_bundle(dangling, external_ids=attack.ids)
    assert errors == [] and any("not in bundle" in w for w in warnings)
    errors, warnings = export.validate_bundle(ok)
    assert errors == [] and all("target_ref -> attack-pattern--" in w for w in warnings) and warnings
    missing = json.loads(json.dumps(ok))
    del next(x for x in missing["objects"] if x["type"] == "indicator")["pattern"]
    assert any("missing pattern" in e for e in export.validate_bundle(missing)[0])

    def with_extra(*objs):
        b = json.loads(json.dumps(ok))
        b["objects"].extend(objs)
        return export.validate_bundle(b, external_ids=attack.ids)
    dated = {"spec_version": "2.1", "created": "2026-09-02T00:00:00.000Z", "modified": "2026-09-02T00:00:00.000Z"}
    ind = _one(ok, "indicator")["id"]
    host = "identity--" + str(uuid.uuid4())
    # deprecated customisation, marked SCOs (BP §2.3, §3.5): warnings
    _, w = with_extra({**dated, "type": "x-dx-thing", "id": "x-dx-thing--" + str(uuid.uuid4())})
    assert any("custom object type" in x for x in w)
    _, w = with_extra({**objects.ip_address("9.9.9.9"), "x_dx_note": 1, "object_marking_refs": [AMBER]})
    assert any("custom property" in x for x in w) and any("marked SCO" in x for x in w)
    # relationship names / targets against the spec's tables (§5.1, BP §5.12): warnings; bad endpoints: errors
    rel = lambda rt, src, dst: {**dated, "type": "relationship", "id": "relationship--" + str(uuid.uuid4()),  # noqa: E731
                                "relationship_type": rt, "source_ref": src, "target_ref": dst}
    _, w = with_extra(rel("indicates", ind, host))
    assert any("indicator indicates identity" in x for x in w)
    _, w = with_extra(rel("detects", ind, "malware--" + str(uuid.uuid4())))
    assert any("not a relationship type the spec lists for indicator" in x for x in w)
    e, w = with_extra(rel("related-to", ind, "malware--" + str(uuid.uuid4())))
    assert e == [] and not any("spec lists" in x for x in w)
    e, _ = with_extra(rel("indicates", _one(ok, "sighting")["id"], ind))
    assert any("SRO relates SDOs / SCOs only" in x for x in e)
    e, _ = with_extra(rel("Bad Name", ind, host))
    assert any("relationship_type" in x for x in e)
    # sighting endpoints (§5.2): errors
    s = json.loads(json.dumps(_one(ok, "sighting")))
    s["id"], s["sighting_of_ref"] = "sighting--" + str(uuid.uuid4()), _one(ok, "network-traffic")["id"]
    assert any("sighting_of_ref must reference an SDO" in x for x in with_extra(s)[0])
    s = json.loads(json.dumps(_one(ok, "sighting")))
    s["id"], s["where_sighted_refs"] = "sighting--" + str(uuid.uuid4()), [_one(ok, "network-traffic")["id"]]
    assert any("where_sighted_refs" in x for x in with_extra(s)[0])
    s = json.loads(json.dumps(_one(ok, "sighting")))
    s["id"], s["observed_data_refs"] = "sighting--" + str(uuid.uuid4()), [ind]
    assert any("observed_data_refs" in x for x in with_extra(s)[0])
    # a marking-definition needs created (§7.2.1); an extension used but not defined is warned
    e, _ = with_extra({"type": "marking-definition", "spec_version": "2.1", "id": "marking-definition--" + str(uuid.uuid4()),
                       "definition_type": "statement", "definition": {"statement": "x"}})
    assert any("missing created" in x for x in e)
    undefined = json.loads(json.dumps(ok))
    undefined["objects"] = [x for x in undefined["objects"] if x["type"] != "extension-definition"]
    _, w = export.validate_bundle(undefined, external_ids=attack.ids)
    assert any("extension-definition must reach the consumer" in x for x in w)


def test_piiat_bundle_passes_through_untouched(rules, tmp_path):
    own, _ = export.hit_objects([_hit(SURICATA)], rules=rules)
    shared_ip = objects.ip_address("10.0.0.5")                  # same spec id both sides derive
    newer = dict(own[objects.global_id("indicator", "sig-suricata-alert")], modified="2027-01-01T00:00:00.000Z",
                 name="Suricata IDS alert (revised)")
    now = "2026-09-02T10:00:00.000Z"
    piiat = {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": [
        shared_ip,
        {"type": "observed-data", "spec_version": "2.1", "id": "observed-data--" + str(uuid.uuid4()),
         "created": now, "modified": now, "first_observed": now, "last_observed": now,
         "number_observed": 1, "object_refs": [shared_ip["id"]]},
        {"type": "relationship", "spec_version": "2.1", "id": "relationship--" + str(uuid.uuid4()),
         "created": now, "modified": now, "relationship_type": "created-by",
         "source_ref": "process--" + str(uuid.uuid4()), "target_ref": "process--" + str(uuid.uuid4()),
         "labels": ["declared"]},
        {"type": "relationship", "spec_version": "2.1", "id": "relationship--" + str(uuid.uuid4()),
         "created": now, "modified": now, "relationship_type": "related-to",
         "source_ref": "file--" + str(uuid.uuid4()), "target_ref": "process--" + str(uuid.uuid4()),
         "labels": ["derived"], "x_piiat_inferred": True},
        newer,
        "not an object",
    ]}
    path = tmp_path / "piiat.json"
    path.write_text(json.dumps(piiat))
    bundle, report = export.assemble([_hit(SURICATA)], [export.load_bundle(str(path))], rules=rules)
    counts = report["merged"][0]
    assert (counts["added"], counts["kept"], counts["replaced"], counts["invalid"]) == (3, 1, 1, 1)
    assert report["hits"]["sightings"] == 1
    assert sum(1 for x in bundle["objects"] if x["id"] == shared_ip["id"]) == 1
    assert next(x for x in bundle["objects"] if x["id"] == newer["id"])["name"] == "Suricata IDS alert (revised)"
    # PIIAT's objects are neither re-marked nor re-keyed; their labels still say their class
    passed = next(x for x in bundle["objects"] if x.get("x_piiat_inferred"))
    assert "object_marking_refs" not in passed and passed["labels"] == ["derived"]
    assert export.summarise(bundle)["relationship_classes"] == {"declared": 1, "derived": 3}
    errors, warnings = export.validate_bundle(bundle)
    assert errors == [] and warnings                       # PIIAT refs held elsewhere, its x_ property: warned, not refused
    not_a_bundle = tmp_path / "hits.json"
    not_a_bundle.write_text("[]")
    with pytest.raises(ValueError):
        export.load_bundle(str(not_a_bundle))


# ---- OpenCTI exchange (stubbed transport) -----------------------------------
class RecordingTransport:
    def __init__(self, status=200, text='{"data": {"stixBundlePush": true}}'):
        self.calls, self.status, self.text = [], status, text

    def post(self, url, headers, body, timeout):
        self.calls.append((url, dict(headers), body, timeout))
        return self.status, self.text


def test_opencti_client_posts_the_bundle_through_the_transport(rules):
    bundle = _bundle(rules, ENVELOPE)
    rec = RecordingTransport()
    client = opencti.OpenCTIClient("https://opencti.example.test/", "tok-123",
                                   connector_id="conn-1", transport=rec, timeout=7)
    result = client.push_bundle(bundle)
    assert result.ok and result.objects == len(bundle["objects"]) and result.status == 200
    url, headers, body, timeout = rec.calls[0]
    assert url == "https://opencti.example.test/graphql" and timeout == 7.0
    assert headers["Authorization"] == "Bearer tok-123" and headers["Content-Type"] == "application/json"
    payload = json.loads(body)
    assert "stixBundlePush" in payload["query"]
    assert payload["variables"]["connectorId"] == "conn-1"
    assert json.loads(payload["variables"]["bundle"]) == bundle
    assert "tok-123" not in payload["variables"]["bundle"]
    assert "tok-123" not in repr(client) and "tok-123" not in json.dumps(result.as_dict())


def test_opencti_client_reports_refusals_without_raising(rules):
    bundle = _bundle(rules, ENVELOPE)

    def push(status, text):
        client = opencti.OpenCTIClient("https://x.test", "t", transport=RecordingTransport(status, text))
        return client.push_bundle(bundle)
    assert not push(401, "").ok and "token" in push(401, "").message
    refused = push(200, '{"errors": [{"message": "Connector not registered"}]}')
    assert not refused.ok and "Connector not registered" in refused.message
    assert not push(500, "<html>boom</html>").ok
    down = push(0, "connection refused")
    assert not down.ok and "unreachable" in down.message
    # the deterministic default connector id is a plain uuid the platform can register once
    uuid.UUID(opencti.OpenCTIClient("https://x.test", "t", transport=RecordingTransport()).connector_id)


def test_opencti_client_refuses_to_start_without_endpoint_or_token():
    with pytest.raises(ValueError):
        opencti.OpenCTIClient(None, "t", transport=RecordingTransport())
    with pytest.raises(ValueError):
        opencti.OpenCTIClient("https://x.test", "", transport=RecordingTransport())


def test_opencti_client_refuses_non_https_endpoint():
    # the bearer token must never go over cleartext: http:// or a schemeless URL is refused
    for bad in ("http://opencti.test", "opencti.test/graphql"):
        with pytest.raises(ValueError):
            opencti.OpenCTIClient(bad, "t", transport=RecordingTransport())


# ---- config + the verb -----------------------------------------------------
def test_config_layers_file_env_and_overrides(tmp_path):
    f = tmp_path / "stix.json"
    f.write_text(json.dumps({"case": "FILE-CASE", "tlp": "GREEN", "push": "yes", "confidence": "80",
                             "contact": "soc@example.test", "stack_version": "9.5.0",
                             "opencti": {"url": "https://file.test", "token": "file-token"}}))
    env = {"DXDFIR_OPENCTI_URL": "https://env.test", "DXDFIR_OPENCTI_TOKEN": "env-token",
           "DXDFIR_STIX_ATTACK_INDEX": "/tmp/attack.json"}
    cfg = config.load_config(str(f), env=env, case_id="FLAG-CASE", out=None)
    assert (cfg.case_id, cfg.tlp, cfg.push, cfg.confidence) == ("FLAG-CASE", "green", True, 80)
    assert (cfg.contact, cfg.stack_version, cfg.attack_index) == ("soc@example.test", "9.5.0", "/tmp/attack.json")
    assert (cfg.opencti_url, cfg.opencti_token) == ("https://env.test", "env-token")
    assert cfg.redacted()["opencti_token"] == "***" and "env-token" not in json.dumps(cfg.redacted())
    y = tmp_path / "stix.yml"
    y.write_text("out: bundle.json\nopencti:\n  connector_id: c-1\n")
    cfg = config.load_config(str(y), env={})
    assert (cfg.out, cfg.opencti_connector_id, cfg.push, cfg.tlp) == ("bundle.json", "c-1", False, "amber")
    assert (cfg.rules_dir, cfg.attack_index, cfg.confidence) == (None, None, None)
    assert cfg.stack_version == config.DEFAULT_STACK_VERSION and cfg.contact == objects.DEFAULT_CONTACT
    assert config.load_config(env={}).opencti_token is None
    assert config.load_config(env={"DXDFIR_STIX_CONFIDENCE": "0"}).confidence == 0
    assert config.load_config(env={"DXDFIR_STIX_CONTACT": " "}).contact is None
    for bad in ("high", "101", "-1", True):
        with pytest.raises(ValueError, match="confidence"):
            config.load_config(env={}, confidence=bad)


def test_run_export_writes_and_pushes(rules, tmp_path):
    jsonl = tmp_path / "hits.jsonl"
    jsonl.write_text(json.dumps(ENVELOPE) + "\n" + json.dumps(SURICATA) + "\n")
    out = tmp_path / "exchange" / "bundle.json"
    rec = RecordingTransport()
    cfg = config.StixConfig(case_id="CASE-9", out=str(out), push=True, rules_dir=rules.rules_dir,
                            opencti_url="https://x.test", opencti_token="t", confidence=75)
    summary, bundle = export.run_export(cfg, [str(jsonl)], transport=rec)
    assert summary["ok"] and summary["push"]["ok"] and len(rec.calls) == 1
    assert json.loads(out.read_text()) == bundle
    assert summary["summary"]["sightings"] == 2 and summary["validation"] == {"errors": [], "warnings": []}
    assert summary["hits"]["sightings"] == 2 and summary["hits"]["skipped"] == {}
    assert summary["attack_version"] and summary["config"]["opencti_token"] == "***"
    assert all(x["confidence"] == 75 for x in bundle["objects"] if x["type"] in ("indicator", "sighting"))
    # no push configured: the transport is never touched; no inputs: refused; every hit skipped: refused
    class Explode:
        def post(self, *a):
            raise AssertionError("must not be called")
    summary, _ = export.run_export(config.StixConfig(out=str(out), rules_dir=rules.rules_dir), [str(jsonl)],
                                   transport=Explode())
    assert summary["ok"] and summary["push"] is None
    with pytest.raises(ValueError):
        export.run_export(config.StixConfig(), [], transport=Explode())
    stubs = tmp_path / "stubs.jsonl"
    stubs.write_text(json.dumps({**ENVELOPE, "DetectionId": "vol-malfind-injection"}) + "\n")
    with pytest.raises(ValueError, match="every hit was skipped"):
        export.run_export(config.StixConfig(rules_dir=rules.rules_dir), [str(stubs)], transport=Explode())
    with pytest.raises(ValueError, match="rules directory"):
        export.run_export(config.StixConfig(rules_dir=str(tmp_path / "nope")), [str(jsonl)], transport=Explode())


def _stix(argv, capsys):
    """Drive the argparse CLI exactly as the Go passthrough does — an argv list to
    ``main`` — and return (exit_code, stdout, stderr)."""
    try:
        stix_cli.main(argv)
        code = 0
    except SystemExit as e:
        code = e.code if e.code is not None else 0
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_stix_export(tmp_path, monkeypatch, capsys):
    jsonl = tmp_path / "hits.jsonl"
    jsonl.write_text(json.dumps(ENVELOPE) + "\n")
    out = tmp_path / "bundle.json"
    code, stdout, stderr = _stix(["export", "--hits", str(jsonl), "--out", str(out),
                                  "--case", "CASE-7", "--tlp", "green"], capsys)
    assert code == 0, stdout + stderr
    bundle = json.loads(out.read_text())
    assert export.validate_bundle(bundle, external_ids=attack_index.load_attack_index().ids) == ([], [])
    assert not _by_type(bundle, "marking-definition")
    assert _one(bundle, "sighting")["object_marking_refs"] == [objects.TLP_MARKING_IDS["green"]]
    assert _one(bundle, "indicator")["pattern_version"] == config.DEFAULT_STACK_VERSION   # the package's rules
    summary = json.loads(stdout)
    assert summary["summary"]["sightings"] == 1 and summary["bundle"] == str(out)
    # --push takes endpoint/token from the environment and goes through the transport
    rec = RecordingTransport()
    monkeypatch.setattr(opencti, "UrllibTransport", lambda: rec)
    monkeypatch.setenv("DXDFIR_OPENCTI_URL", "https://env.test")
    monkeypatch.setenv("DXDFIR_OPENCTI_TOKEN", "env-token")
    code, stdout, stderr = _stix(["export", "--hits", str(jsonl), "--out", str(out), "--push"], capsys)
    assert code == 0, stdout + stderr
    assert rec.calls[0][0] == "https://env.test/graphql"
    assert rec.calls[0][1]["Authorization"] == "Bearer env-token"
    # a refused push is exit 1; --push without a token is exit 2; no inputs is exit 2
    monkeypatch.setattr(opencti, "UrllibTransport", lambda: RecordingTransport(403, ""))
    assert _stix(["export", "--hits", str(jsonl), "--push"], capsys)[0] == 1
    monkeypatch.delenv("DXDFIR_OPENCTI_TOKEN")
    assert _stix(["export", "--hits", str(jsonl), "--push"], capsys)[0] == 2
    assert _stix(["export"], capsys)[0] == 2


# ---- the ATT&CK index: MITRE's authoritative attack-pattern ids (BP §5.2, §2.2)
def test_committed_attack_index_resolves_techniques_to_mitre_ids():
    ix = attack_index.load_attack_index()
    assert ix.attack_version and len(ix.techniques) > 600 and len(ix.tactics) >= 14
    for t in ix.techniques.values():
        assert t.id.startswith("attack-pattern--")
        uuid.UUID(t.id.split("--", 1)[1])
    live = ix.resolve("T1204")
    assert live is not None and not live.substituted and live.technique.name == "User Execution"
    assert live.technique.id in ix.ids and live.technique.phases == ("execution",)
    assert ix.resolve("T9999") is None and ix.resolve("") is None
    # a revoked technique follows MITRE's revoked-by pointer to a live replacement, and says so
    revoked = next(t for t in ix.techniques.values() if t.revoked and t.revoked_by)
    r = ix.resolve(revoked.external_id)
    assert r is not None and r.substituted and r.requested == revoked.external_id
    assert not r.technique.revoked and r.technique.external_id != revoked.external_id
    # kill-chain phases: the techniques' tactics plus explicit tactic ids — spec shape, de-duplicated, sorted
    assert ix.phases(["T1204", "T1204"], ["TA0002", "TA0001"]) == [
        {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
    assert ix.phases(["T9999"]) == []


def _attack_bundle():
    def ap(uid, tid, name, phases, **extra):
        return {"type": "attack-pattern", "id": f"attack-pattern--{uid}", "name": name,
                "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                         "url": "https://attack.mitre.org/techniques/" + tid}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases], **extra}
    old = ap("11111111-1111-4111-8111-111111111111", "T1000", "Old", ["execution"], revoked=True)
    new = ap("22222222-2222-4222-8222-222222222222", "T2000", "New", ["persistence", "execution"])
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--x", "name": "Enterprise ATT&CK",
         "x_mitre_version": "19.2", "modified": "2026-08-05T21:33:58.496Z"},
        old, new,
        ap("33333333-3333-4333-8333-333333333333", "T3000", "Gone", [], x_mitre_deprecated=True),
        {"type": "relationship", "id": "relationship--x", "relationship_type": "revoked-by",
         "source_ref": old["id"], "target_ref": new["id"]},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--x", "name": "Execution", "x_mitre_shortname": "execution",
         "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}]},
        {"type": "malware", "id": "malware--x", "name": "not indexed"},
    ]}


def test_build_index_is_deterministic_and_round_trips(tmp_path):
    bundle = _attack_bundle()
    doc = attack_index.build_index(bundle, source="test")
    assert (doc["format"], doc["source"], doc["attack_version"]) == (1, "test", "19.2")
    assert doc["techniques"]["T1000"] == {"id": "attack-pattern--11111111-1111-4111-8111-111111111111", "name": "Old",
                                          "phases": ["execution"], "revoked": True, "revoked_by": "T2000"}
    assert doc["techniques"]["T2000"]["phases"] == ["execution", "persistence"]      # sorted
    assert doc["techniques"]["T3000"]["deprecated"] is True and "malware" not in json.dumps(doc)
    assert doc["tactics"] == {"TA0002": {"id": "x-mitre-tactic--x", "name": "Execution", "phase": "execution"}}
    text = attack_index.dumps_index(doc)
    assert json.loads(text) == doc
    assert text == attack_index.dumps_index(attack_index.build_index(bundle, source="test"))
    # the module's CLI writes that same document; a raw bundle path indexes on the fly
    out, src = tmp_path / "index.json", tmp_path / "enterprise-attack.json"
    src.write_text(json.dumps(bundle))
    assert attack_index.main([str(src), "-o", str(out), "--source", "test"]) == 0
    assert out.read_text() == text
    ix = attack_index.load_attack_index(str(src))
    assert ix.resolve("T1000").technique.external_id == "T2000" and ix.resolve("T1000").substituted
    assert attack_index.load_attack_index(str(out)).ids == ix.ids == {doc["techniques"][t]["id"] for t in doc["techniques"]}
    # not a bundle: exit 2; a malformed index is refused up front
    src2 = tmp_path / "report.json"
    src2.write_text(json.dumps({"type": "report"}))
    assert attack_index.main([str(src2), "-o", str(out)]) == 2
    for bad in ({}, {"format": 1, "techniques": {}}, {"format": 2, "techniques": doc["techniques"]},
                {"format": 1, "techniques": {"T1": {"id": "malware--x", "name": "n", "phases": []}}},
                {"format": 1, "techniques": doc["techniques"], "tactics": {"TA1": {"name": "no phase"}}}):
        with pytest.raises(ValueError):
            attack_index.validate_index(bad)
