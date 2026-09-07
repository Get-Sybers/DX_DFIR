"""Unit tests for the behaviour-sightings bridge (detections -> CAR entities ->
STIX Sightings of ATT&CK attack-patterns over spindle-identified observed-data).

No network, no docker: a synthetic ``car.db`` (the engine's per-object schema) and
hand-written lane output exercise the join and the emitted object graph. The
shape under test: the sighting sights the ATT&CK attack-pattern (MITRE's own id,
referenced not shipped), its observed-data is keyed on the matched CAR row's
spindle ``guid`` (so two detectors on one entity share the observation), the
observed host is a where-sighted identity, and the bundle validates clean with
ATT&CK ids as the permitted non-local references.
"""
import json
import sqlite3
import uuid

import pytest

from get_sybers_dxdfir.stix import attack_index, behaviour, export, objects

# Real techniques that resolve in the committed ATT&CK index.
T_SCAN = "T1046"        # Network Service Discovery — the masscan-style suricata alert
T_EXEC = "T1059"        # Command and Scripting Interpreter — the DOSfuscated cmd hayabusa alert

FLOW_GUID = "flow-guid-0001"
PROC_GUID = "{11111111-2222-3333-4444-555555555555}"
C2_IP = "100.101.0.42"
C2_FQDN = "scoring-c2.berylia.org"
HOST = "DESKTOP-M913391"
WHEN = "2024-01-19T05:34:22.833000Z"


def _make_car_db(path):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE flow (guid TEXT, timestamp TEXT, hostname TEXT, fqdn TEXT, src_ip TEXT, "
               "dest_ip TEXT, src_port INT, dest_port INT, transport_protocol TEXT, "
               "application_protocol TEXT, dest_fqdn TEXT, src_fqdn TEXT)")
    db.execute("INSERT INTO flow VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               (FLOW_GUID, "2024-01-19 05:34:22.000 +00:00", HOST, None, "10.0.0.5", C2_IP,
                44100, 22, "tcp", "ssh", C2_FQDN, None))
    db.execute("CREATE TABLE process (guid TEXT, timestamp TEXT, hostname TEXT, fqdn TEXT, pid INT, "
               "command_line TEXT, exe TEXT, image_path TEXT, user TEXT, sid TEXT, "
               "md5_hash TEXT, sha1_hash TEXT, sha256_hash TEXT)")
    db.execute("INSERT INTO process VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (PROC_GUID, WHEN, HOST, None, 4242, "cmd  /c whoami", r"C:\Windows\System32\cmd.exe",
                r"C:\Windows\System32\cmd.exe", "JDH", "S-1-5-21-1", None, None,
                "a" * 64))
    db.execute("CREATE TABLE file (guid TEXT, timestamp TEXT, hostname TEXT, fqdn TEXT, file_name TEXT, "
               "file_path TEXT, md5_hash TEXT, sha1_hash TEXT, sha256_hash TEXT)")
    db.commit()
    db.close()


def _write_detections(root):
    (root / "suricata").mkdir()
    (root / "hayabusa").mkdir()
    (root / "yara").mkdir()
    # suricata: an alert to the C2 IP carrying the masscan technique in ET metadata
    with open(root / "suricata" / "cap.eve.jsonl", "w") as fh:
        fh.write(json.dumps({
            "event_type": "alert", "timestamp": "2024-01-19T05:34:22.500000+0000",
            "src_ip": "10.0.0.5", "dest_ip": C2_IP, "dest_port": 22, "proto": "TCP",
            "alert": {"signature": "ET SCAN NETWORK Outgoing Masscan detected", "signature_id": 2024364,
                      "category": "Detection of a Network Scan",
                      "metadata": {"mitre_technique_id": [T_SCAN]}}}) + "\n")
        fh.write(json.dumps({"event_type": "flow", "src_ip": "10.0.0.5", "dest_ip": C2_IP}) + "\n")  # not an alert
    # hayabusa: the high T1059 record on the process (Sysmon ProcessGuid = PGUID)
    with open(root / "hayabusa" / "timeline.jsonl", "w") as fh:
        fh.write(json.dumps({
            "Timestamp": "2024-01-19 05:34:22.833 +00:00", "RuleTitle": "Cmd.EXE Missing Space Anomaly",
            "Level": "high", "Computer": HOST, "Channel": "Sysmon", "EventID": 1, "RecordID": 5261,
            "MitreTags": [f"{T_EXEC} ¦ T1204.002"],
            "Details": {"Cmdline": "cmd /c whoami", "Proc": r"C:\Windows\System32\cmd.exe",
                        "PGUID": PROC_GUID, "PID": 4242}}) + "\n")
        fh.write(json.dumps({  # an info record with no technique -> no attack-pattern
            "Timestamp": WHEN, "RuleTitle": "Proc Exec", "Level": "info", "Computer": HOST,
            "Channel": "Sysmon", "EventID": 1, "RecordID": 5209, "OtherTags": ["sysmon"],
            "Details": {"PGUID": PROC_GUID, "PID": 4242}}) + "\n")
    # yara: a memory match on the process pid (rule name carries no technique)
    with open(root / "yara" / "memory.jsonl", "w") as fh:
        fh.write(json.dumps({"tool": "yara", "source": "memory", "rule": "SUSP_cmd_obfuscation",
                             "pid": 4242, "process": "cmd.exe", "target": "memdump.mem"}) + "\n")


@pytest.fixture()
def car_and_detections(tmp_path):
    car_db = tmp_path / "car.db"
    _make_car_db(str(car_db))
    det_dir = tmp_path / "signatures"
    det_dir.mkdir()
    _write_detections(det_dir)
    return str(car_db), str(det_dir)


# ------------------------------------------------------------------- the join
def test_car_index_joins_by_ip_guid_and_pid(car_and_detections):
    car_db, _ = car_and_detections
    idx = behaviour.CarIndex()
    idx.add_store(car_db)
    # suricata: dest IP -> the flow
    suri = behaviour.Detection(source="suricata", detection_id="sig-suricata-alert",
                               name="x", ips=[C2_IP])
    assert [r.object_type for r in idx.match(suri)] == ["flow"]
    assert idx.match(suri)[0].guid == FLOW_GUID
    # hayabusa: ProcessGuid -> the process
    haya = behaviour.Detection(source="hayabusa", detection_id="sig-hayabusa-high",
                               name="x", process_guid=PROC_GUID, host=HOST, pid=4242)
    assert idx.match(haya)[0].guid == PROC_GUID
    # yara: pid -> the process
    ya = behaviour.Detection(source="yara", detection_id="sig-yara-match", name="x", pid=4242, host=HOST)
    assert idx.match(ya)[0].guid == PROC_GUID


def test_detection_parsers_extract_techniques_and_keys(car_and_detections):
    _, det_dir = car_and_detections
    dets = behaviour.load_detections(det_dir)
    by_src = {d.source: d for d in dets if d.techniques}
    assert by_src["suricata"].techniques == [T_SCAN]
    assert C2_IP in by_src["suricata"].ips        # both endpoints indexed; the C2 IP joins the flow
    haya = next(d for d in dets if d.source == "hayabusa" and d.techniques)
    assert haya.techniques[0] == T_EXEC and haya.process_guid == PROC_GUID and haya.pid == 4242
    # the info hayabusa row parses but carries no technique
    assert any(d.source == "hayabusa" and not d.techniques for d in dets)


# --------------------------------------------------------------- the sightings
def test_sighting_of_attack_pattern_over_spindle_observed_data(car_and_detections):
    car_db, det_dir = car_and_detections
    idx = behaviour.CarIndex()
    idx.add_store(car_db)
    ai = attack_index.load_attack_index()
    dets = behaviour.load_detections(det_dir)
    objs, report = behaviour.behaviour_objects(dets, idx, case_id="case-1", attack=ai)

    sightings = [x for x in objs.values() if x["type"] == "sighting"]
    ap_scan = ai.resolve(T_SCAN).technique.id
    ap_exec = ai.resolve(T_EXEC).technique.id

    # every sighting sights an ATT&CK attack-pattern (never an indicator/SCO)
    assert sightings, "expected at least the masscan + cmd sightings"
    for s in sightings:
        assert s["sighting_of_ref"].startswith("attack-pattern--")
    sighted = {s["sighting_of_ref"] for s in sightings}
    assert ap_scan in sighted and ap_exec in sighted

    # the suricata sighting's observed-data is keyed on the FLOW's spindle guid
    od_flow_id = objects.case_scoped_id("observed-data", "case-1", FLOW_GUID, "network")
    scan_sight = next(s for s in sightings if s["sighting_of_ref"] == ap_scan)
    assert scan_sight["observed_data_refs"] == [od_flow_id]
    assert objects.extension_of(scan_sight)["car_guid"] == FLOW_GUID
    assert objects.extension_of(scan_sight)["car_object"] == "flow"

    # that observed-data resolves the C2 IP to its domain (the cross-source expand)
    od_flow = objs[od_flow_id]
    scos = [objs[r] for r in od_flow["object_refs"]]
    domains = [s for s in scos if s["type"] == "domain-name"]
    addrs = [s for s in scos if s["type"] == "ipv4-addr"]
    assert any(d["value"] == C2_FQDN for d in domains)
    assert any(a["value"] == C2_IP for a in addrs)
    dom = domains[0]
    assert dom.get("resolves_to_refs") and dom["resolves_to_refs"][0] in {a["id"] for a in addrs}

    # the cmd sighting is where-sighted on the host, over the PROCESS spindle guid
    od_proc_id = objects.case_scoped_id("observed-data", "case-1", PROC_GUID, "process")
    exec_sight = next(s for s in sightings if s["sighting_of_ref"] == ap_exec)
    assert exec_sight["observed_data_refs"] == [od_proc_id]
    host_id = objects.host_identity(HOST, "x")["id"]
    assert exec_sight["where_sighted_refs"] == [host_id]
    assert objs[host_id]["type"] == "identity"

    # the report counts what joined + the info row with no technique
    assert report["sightings"] == len(sightings)
    assert report["entities"] == 2                       # the flow and the process
    # the info hayabusa + the (technique-less) yara match joined an entity but
    # carry no ATT&CK technique -> counted as joined, never as no_car_entity
    assert report["skipped"].get("joined_no_technique", 0) >= 1
    assert report["skipped"].get("no_car_entity", 0) == 0


def test_shared_observed_data_across_detectors(car_and_detections):
    """hayabusa (T1059) and — if it resolved a technique — yara both touch the same
    process; whichever sights it references the ONE process observed-data (spindle
    guid = the shared key)."""
    car_db, det_dir = car_and_detections
    idx = behaviour.CarIndex()
    idx.add_store(car_db)
    dets = behaviour.load_detections(det_dir)
    objs, _ = behaviour.behaviour_objects(dets, idx, case_id="case-1")
    od_proc_id = objects.case_scoped_id("observed-data", "case-1", PROC_GUID, "process")
    proc_sightings = [x for x in objs.values() if x["type"] == "sighting"
                      and x.get("observed_data_refs") == [od_proc_id]]
    assert proc_sightings, "the cmd sighting anchors to the process observed-data"
    # exactly one observed-data object exists for the process guid (shared, not duplicated)
    assert sum(1 for x in objs.values()
               if x["type"] == "observed-data" and x["id"] == od_proc_id) == 1


def test_bundle_validates_clean_with_attack_ids_as_external(car_and_detections):
    car_db, det_dir = car_and_detections
    idx = behaviour.CarIndex()
    idx.add_store(car_db)
    ai = attack_index.load_attack_index()
    dets = behaviour.load_detections(det_dir)
    bundle, _ = behaviour.build_behaviour_bundle(dets, idx, case_id="case-1", attack=ai)
    errors, warnings = export.validate_bundle(bundle, external_ids=ai.ids)
    assert errors == []
    # the attack-pattern references are non-local by design (external_ids) -> no warning about them
    assert not [w for w in warnings if "attack-pattern--" in w]


def test_ids_are_deterministic(car_and_detections):
    car_db, det_dir = car_and_detections
    ai = attack_index.load_attack_index()

    def run():
        idx = behaviour.CarIndex()
        idx.add_store(car_db)
        b, _ = behaviour.build_behaviour_bundle(behaviour.load_detections(det_dir), idx,
                                                case_id="case-1", attack=ai)
        return sorted(o["id"] for o in b["objects"])
    assert run() == run()


def test_run_behaviour_writes_bundle(tmp_path, car_and_detections):
    car_db, det_dir = car_and_detections
    out = tmp_path / "behaviour.json"
    summary, bundle = behaviour.run_behaviour(
        car_paths=[car_db], detections_dir=det_dir, case_id="case-1", out=str(out))
    assert summary["ok"] and summary["validation"]["errors"] == []
    assert summary["bundle"] == str(out) and out.is_file()
    assert summary["summary"]["sightings"] >= 2
    on_disk = json.loads(out.read_text())
    assert on_disk["type"] == "bundle" and on_disk["id"] == bundle["id"]


def test_no_car_entity_is_skipped_not_invented(tmp_path):
    """A detection that joins to nothing produces no sighting (never a fabricated
    entity) and is counted."""
    car_db = tmp_path / "car.db"
    _make_car_db(str(car_db))
    idx = behaviour.CarIndex()
    idx.add_store(str(car_db))
    orphan = behaviour.Detection(source="suricata", detection_id="sig-suricata-alert",
                                 name="ET nothing", techniques=[T_SCAN], ips=["203.0.113.9"],
                                 timestamp=WHEN)
    objs, report = behaviour.behaviour_objects([orphan], idx, case_id="c")
    assert not [x for x in objs.values() if x["type"] == "sighting"]
    assert report["skipped"].get("no_car_entity") == 1
