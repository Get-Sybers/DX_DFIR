"""Unit tests for the car-detections lookup-index writer (detect/car_detections.py).

No Elastic, no Byakugan import: a hand-built ``stix_bundle.json`` tree, shaped
exactly as ``byakugan/stix.py``'s behaviour layer emits one (verified against
Byakugan's own ``tests/test_stix_behaviour.py`` / ``tests/test_stix.py``), and
a stdlib ``http.server`` stub for the ``--post`` path (the writer's ``Es``
client has no injectable transport, unlike ``stix/opencti.py``'s, so it needs
a real socket to test against).
"""
import base64
import copy
import http.server
import json
import os
import threading

import pytest

from get_sybers_dxdfir.detect import car_detections as cd
from get_sybers_dxdfir.detect import rules_loader as rl
from get_sybers_dxdfir.stix.hits import flatten

T_EXEC = "T1059"       # Command and Scripting Interpreter — real, resolves; tactic TA0002 Execution
T_DISC = "T1046"       # Network Service Discovery — real, resolves; tactic TA0007 Discovery
T_BOGUS = "T9999.999"  # not in the committed ATT&CK index — never resolves

EPOCH = "1970-01-01T00:00:00.000Z"


# --------------------------------------------------------------------------- #
# fixture builders — the subset of a Byakugan behaviour bundle this writer
# reads (indicator / observed-data / sighting); see the module docstring.
# --------------------------------------------------------------------------- #
def _indicator(iid, analytic_id, name, car_object="process"):
    return {"type": "indicator", "spec_version": "2.1", "id": iid, "created": EPOCH, "modified": EPOCH,
            "name": name, "pattern_type": "car", "pattern": analytic_id, "valid_from": EPOCH,
            "external_references": [{"source_name": "mitre-car", "external_id": analytic_id,
                                     "url": "https://car.mitre.org/analytics/" + analytic_id}],
            "x_car_analytic": analytic_id, "x_car_car_object": car_object, "x_car_car_action": "create"}


def _observed_data(oid, event_id, when, *, car_object="process", process_entity_id=None, host="HOSTA"):
    o = {"type": "observed-data", "spec_version": "2.1", "id": oid, "created": when, "modified": when,
         "first_observed": when, "last_observed": when, "number_observed": 1, "object_refs": [],
         "labels": [f"car:{car_object}"], "x_car_object": car_object, "x_car_action": "create",
         "x_car_event_id": event_id, "x_car_source_host": host, "x_car_timestamp": when}
    if process_entity_id:
        o["x_car_process_entity_id"] = process_entity_id
    return o


def _sighting(sid, ind_id, event_id, when, *, analytic_id, techniques=(), observed_data_ref=None,
             car_object="process", host="HOSTA", title=""):
    o = {"type": "sighting", "spec_version": "2.1", "id": sid, "created": when, "modified": when,
         "sighting_of_ref": ind_id, "count": 1, "first_seen": when, "last_seen": when,
         "x_car_analytic": analytic_id, "x_car_title": title, "x_car_object": car_object,
         "x_car_action": "create", "x_car_event_id": event_id, "x_car_source_host": host,
         "x_car_techniques": list(techniques)}
    if observed_data_ref:
        o["observed_data_refs"] = [observed_data_ref]
    return o


DET_A, DET_B = "CAR-2013-05-002", "CAR-9999-01-001"
IND_A, IND_B = "indicator--A", "indicator--B"


def _bundle_a():
    """host-a: one analytic, two CAR rows — P1 (process, owns itself) and F1
    (a file owned by P1: process.entity_id cascades) and F2 (a file whose
    owner never resolved: no process.entity_id at all — the honest-omission
    side of the same field)."""
    od_p1 = _observed_data("observed-data--P1", "P1", "2024-01-19T05:34:22.000Z",
                           car_object="process", process_entity_id="P1")
    od_f1 = _observed_data("observed-data--F1", "F1", "2024-01-19T05:34:23.000Z",
                           car_object="file", process_entity_id="P1")
    s1 = _sighting("sighting--S1", IND_A, "P1", "2024-01-19T05:34:22.000Z", analytic_id=DET_A,
                   techniques=[T_EXEC], observed_data_ref=od_p1["id"], car_object="process")
    s2 = _sighting("sighting--S2", IND_A, "F1", "2024-01-19T05:34:23.000Z", analytic_id=DET_A,
                   techniques=[T_EXEC], observed_data_ref=od_f1["id"], car_object="file")
    return {"type": "bundle", "id": "bundle--a",
            "objects": [_indicator(IND_A, DET_A, "Processes Spawning cmd.exe"), od_p1, od_f1, s1, s2]}


def _bundle_b():
    """host-b: a second analytic over a flow row with no owning process
    (process.entity_id absent), two clauses hitting the SAME row (S3, S4 —
    ``analytics.py``'s one-hit-per-clause; the writer must collapse them to
    one document), one technique that resolves (T1046) and one that does not
    (T_BOGUS) — partial resolution. Plus a dangling ``sighting_of_ref`` and a
    sighting with no ``x_car_event_id`` — both must be skipped, not guessed."""
    od_flow = _observed_data("observed-data--FLOW1", "FLOW1", "2024-02-01T00:00:00.000Z",
                             car_object="flow", host="HOSTB")
    s3 = _sighting("sighting--S3", IND_B, "FLOW1", "2024-02-01T00:00:00.000Z", analytic_id=DET_B,
                   techniques=[T_DISC, T_BOGUS], observed_data_ref=od_flow["id"], car_object="flow",
                   host="HOSTB", title="clause-1")
    s4 = _sighting("sighting--S4", IND_B, "FLOW1", "2024-02-01T00:00:00.000Z", analytic_id=DET_B,
                   techniques=[T_DISC], observed_data_ref=od_flow["id"], car_object="flow",
                   host="HOSTB", title="clause-2")
    s5_dangling = _sighting("sighting--S5", "indicator--nowhere", "GHOST1", "2024-02-01T00:00:01.000Z",
                            analytic_id="nope")
    s6_no_event = dict(_sighting("sighting--S6", IND_B, "IGNORED", "2024-02-01T00:00:02.000Z",
                                 analytic_id=DET_B))
    del s6_no_event["x_car_event_id"]
    return {"type": "bundle", "id": "bundle--b",
            "objects": [_indicator(IND_B, DET_B, "Suspicious Network Scan", car_object="flow"),
                       od_flow, s3, s4, s5_dangling, s6_no_event]}


@pytest.fixture()
def tree(tmp_path):
    (tmp_path / "host-a").mkdir()
    (tmp_path / "host-b").mkdir()
    (tmp_path / "host-c").mkdir()
    (tmp_path / "host-a" / "stix_bundle.json").write_text(json.dumps(_bundle_a()))
    (tmp_path / "host-b" / "stix_bundle.json").write_text(json.dumps(_bundle_b()))
    (tmp_path / "host-c" / "stix_bundle.json").write_text("not json{{{")  # a bad source: skipped, not fatal
    return str(tmp_path)


@pytest.fixture(scope="module")
def contract():
    template, join_keys = rl.load_car_detections()
    rl.validate_car_detections(template, join_keys)
    return template, join_keys


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
def test_iter_bundles_finds_every_source_sorted(tree):
    found = cd.iter_bundles(tree)
    assert [s for s, _ in found] == ["host-a", "host-b", "host-c"]
    assert all(p.endswith("stix_bundle.json") for _, p in found)


def test_load_bundle_is_none_for_malformed_input(tree):
    assert cd.load_bundle(tree + "/host-c/stix_bundle.json") is None
    assert cd.load_bundle(tree + "/does-not-exist.json") is None


# --------------------------------------------------------------------------- #
# extract_rows — the join
# --------------------------------------------------------------------------- #
def test_extract_rows_maps_the_join_and_reports_skips(tree):
    rows, report = cd.extract_rows(tree)
    assert report["sources"] == 2                       # host-a, host-b — host-c is malformed
    assert report["sources_skipped"] == {tree + "/host-c/stix_bundle.json": "unreadable_or_malformed"}
    assert report["sightings"] == 6                      # S1..S6
    assert report["skipped"] == {"no_indicator": 1, "no_event_id": 1}
    assert report["rows"] == 3                            # P1, F1, FLOW1 (S3+S4 collapse)

    by_event = {r["hit"].event_id: r for r in rows}
    assert set(by_event) == {"P1", "F1", "FLOW1"}

    p1 = by_event["P1"]["hit"]
    assert p1.detection_id == DET_A and p1.rule_name == "Processes Spawning cmd.exe"
    assert p1.process_entity_id == "P1"                   # a process row: its own guid
    assert p1.source_index == "logs-car.process-*"
    assert p1.source_id == "sighting--S1"
    assert by_event["P1"]["run_id"] == "host-a"

    f1 = by_event["F1"]["hit"]
    assert f1.process_entity_id == "P1"                   # the cascade: owned by P1
    assert f1.source_index == "logs-car.file-*"

    flow = by_event["FLOW1"]["hit"]
    assert flow.process_entity_id is None                 # never resolved: honestly absent
    assert flow.source_id == "sighting--S3"                # the FIRST-encountered clause wins
    assert by_event["FLOW1"]["technique_ids"] == (T_DISC, T_BOGUS)  # union of S3 + S4, sorted


def test_extract_rows_is_order_independent_of_dict_hashing(tree):
    # two fresh calls must agree byte-for-byte on order (sorted sources /
    # bundle order within), not just on membership.
    rows1, _ = cd.extract_rows(tree)
    rows2, _ = cd.extract_rows(tree)
    assert [(r["hit"].detection_id, r["hit"].event_id) for r in rows1] == \
           [(r["hit"].detection_id, r["hit"].event_id) for r in rows2] == \
           [(DET_A, "P1"), (DET_A, "F1"), (DET_B, "FLOW1")]


# --------------------------------------------------------------------------- #
# stamp_doc — the field-for-field contract
# --------------------------------------------------------------------------- #
def test_stamp_doc_matches_the_template_exactly_for_a_fully_resolved_hit(tree, contract):
    template, _join_keys = contract
    mapped = cd._mapped_fields(((template.get("template") or {}).get("mappings") or {}).get("properties"))
    rows, _ = cd.extract_rows(tree)
    attack = cd.load_attack_index()
    phases = cd._tactics_by_phase()
    p1 = next(r for r in rows if r["hit"].event_id == "P1")
    doc = cd.stamp_doc(p1["hit"], p1["run_id"], p1["technique_ids"], attack, phases)

    flat = flatten(doc)
    assert set(flat) <= mapped, f"stamped field(s) not in the template: {set(flat) - mapped}"
    assert set(flat) == {
        "event.id", "process.entity_id",
        "detection.id", "detection.status", "detection.run_id", "detection.detected_at",
        "detection.source_index", "detection.source_id", "detection.join_via",
        "rule.id", "rule.name",
        "threat.framework", "threat.tactic.id", "threat.tactic.name",
        "threat.technique.id", "threat.technique.name",
    }
    # the two fields this writer can never honestly supply (see the module docstring)
    assert "detection.severity" not in flat and "event.risk_score" not in flat
    # never @timestamp — the field-shadowing decision the module docstring justifies
    assert "@timestamp" not in doc

    assert doc["event"]["id"] == "P1"
    assert doc["process"]["entity_id"] == "P1"
    assert doc["detection"] == {
        "id": DET_A, "status": "car-analytic", "run_id": "host-a",
        "detected_at": "2024-01-19T05:34:22.000Z", "source_index": "logs-car.process-*",
        "source_id": "sighting--S1", "join_via": "direct",
    }
    assert doc["rule"] == {"id": DET_A, "name": "Processes Spawning cmd.exe"}
    assert doc["threat"] == {"framework": "MITRE ATT&CK",
                             "technique": {"id": "T1059", "name": "Command and Scripting Interpreter"},
                             "tactic": {"id": "TA0002", "name": "Execution"}}


def test_stamp_doc_omits_process_entity_id_when_never_resolved(tree, contract):
    rows, _ = cd.extract_rows(tree)
    attack, phases = cd.load_attack_index(), cd._tactics_by_phase()
    flow = next(r for r in rows if r["hit"].event_id == "FLOW1")
    doc = cd.stamp_doc(flow["hit"], flow["run_id"], flow["technique_ids"], attack, phases)
    assert "process" not in doc
    assert "process.entity_id" not in flatten(doc)


def test_stamp_doc_multi_technique_is_a_list_partial_resolution_is_honest(tree, contract):
    rows, _ = cd.extract_rows(tree)
    attack, phases = cd.load_attack_index(), cd._tactics_by_phase()
    flow = next(r for r in rows if r["hit"].event_id == "FLOW1")
    doc = cd.stamp_doc(flow["hit"], flow["run_id"], flow["technique_ids"], attack, phases)
    # both ids ride (Byakugan asserted them); only the one this repo's ATT&CK
    # index actually knows contributes a name and a tactic.
    assert doc["threat"]["technique"]["id"] == [T_DISC, T_BOGUS]
    assert doc["threat"]["technique"]["name"] == "Network Service Discovery"
    assert doc["threat"]["tactic"] == {"id": "TA0007", "name": "Discovery"}


def test_stamp_doc_never_invents_technique_metadata_when_nothing_resolves():
    hit = cd.Hit(detection_id="d", rule_name="r", event_id="e", process_entity_id=None,
                detected_at=None, source_index="logs-car.process-*", source_id="s",
                technique_ids=(T_BOGUS,))
    doc = cd.stamp_doc(hit, "run", hit.technique_ids, cd.load_attack_index(), cd._tactics_by_phase())
    assert doc["threat"] == {"framework": "MITRE ATT&CK", "technique": {"id": T_BOGUS}}
    assert "detection" in doc and "detected_at" not in doc["detection"]   # honest null, omitted


def test_document_id_is_detection_id_colon_event_id():
    assert cd.document_id(DET_A, "P1") == f"{DET_A}:P1"


def test_bulk_lines_are_index_actions_keyed_by_document_id():
    docs = [{"a": 1}, {"b": 2}]
    lines = list(cd.bulk_lines(zip(["x:1", "x:2"], docs), "car-detections"))
    assert len(lines) == 4
    assert json.loads(lines[0]) == {"index": {"_index": "car-detections", "_id": "x:1"}}
    assert json.loads(lines[1]) == {"a": 1}
    assert json.loads(lines[2]) == {"index": {"_index": "car-detections", "_id": "x:2"}}
    assert json.loads(lines[3]) == {"b": 2}


# --------------------------------------------------------------------------- #
# run_stamp — the file + determinism + template-drift guard
# --------------------------------------------------------------------------- #
def test_run_stamp_writes_ndjson_next_to_the_tree_and_is_deterministic(tree, contract):
    template, join_keys = contract
    summary1, docs1, lines1 = cd.run_stamp(tree, template=template, join_keys=join_keys)
    assert summary1["out"] == tree + "/car-detections.bulk.ndjson"
    assert summary1["docs"] == 3 and summary1["index"] == "car-detections"
    with open(summary1["out"], encoding="utf-8") as fh:
        on_disk_1 = fh.read()
    assert on_disk_1 == "\n".join(lines1) + "\n"

    summary2, docs2, lines2 = cd.run_stamp(tree, template=template, join_keys=join_keys)
    with open(summary2["out"], encoding="utf-8") as fh:
        on_disk_2 = fh.read()
    assert on_disk_1 == on_disk_2                          # byte-identical re-run
    assert docs1 == docs2 and lines1 == lines2


def test_run_stamp_honours_out_and_index_overrides(tree, contract, tmp_path):
    template, join_keys = contract
    out = str(tmp_path / "elsewhere" / "car-detections.bulk.ndjson")
    summary, _docs, lines = cd.run_stamp(tree, template=template, join_keys=join_keys,
                                         out=out, index="car-detections-riskgate")
    assert summary["out"] == out and summary["index"] == "car-detections-riskgate"
    assert json.loads(lines[0])["index"]["_index"] == "car-detections-riskgate"
    assert os.path.isfile(out)


def test_run_stamp_raises_on_template_drift(tree, contract):
    template, join_keys = contract
    broken = copy.deepcopy(template)
    del broken["template"]["mappings"]["properties"]["rule"]["properties"]["name"]
    with pytest.raises(ValueError, match="rule.name"):
        cd.run_stamp(tree, template=broken, join_keys=join_keys)


# --------------------------------------------------------------------------- #
# main() — the CLI, file + stdout summary
# --------------------------------------------------------------------------- #
def _run(argv, capsys):
    code = cd.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def test_main_writes_file_and_prints_one_summary_line(tree, capsys):
    code, out, err = _run([tree], capsys)
    assert code == 0 and err == ""
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len(lines) == 1                                  # "a small manifest/summary line"
    summary = json.loads(lines[0])
    assert summary["ok"] is True and summary["docs"] == 3
    assert summary["out"] == tree + "/car-detections.bulk.ndjson"


def test_main_errors_cleanly_on_bad_tree_permissions(tmp_path, capsys, monkeypatch):
    # an out path under a file (not a directory) cannot be created -> OSError,
    # caught and reported on stderr with exit 1, never a traceback.
    (tmp_path / "notadir").write_text("x")
    code, out, err = _run([str(tmp_path), "--out", str(tmp_path / "notadir" / "x.ndjson")], capsys)
    assert code == 1 and out == ""
    assert json.loads(err)["tool"] == "car-detections-stamp"


# --------------------------------------------------------------------------- #
# resolve_es — credential / CA resolution
# --------------------------------------------------------------------------- #
def test_resolve_es_reads_docker_elastic_env(tmp_path):
    envp = tmp_path / ".env"
    envp.write_text('ELASTIC_PASSWORD="s3cr3t"\nELASTICSEARCH_USERNAME=byakugan_loader\n# comment\n')
    es = cd.resolve_es(env={}, env_file=str(envp), insecure=True)
    assert es.url == cd.DEFAULT_ES_URL
    assert base64.b64decode(es.auth.split(" ", 1)[1]).decode() == "byakugan_loader:s3cr3t"


def test_resolve_es_requires_a_password():
    with pytest.raises(cd.EsError, match="password"):
        cd.resolve_es(env={}, env_file="/does/not/exist")


def test_resolve_es_requires_ca_or_insecure_over_https():
    with pytest.raises(cd.EsError, match="CA"):
        cd.resolve_es(env={}, env_file="/does/not/exist", password="x")
    # explicit --insecure is enough
    cd.resolve_es(env={}, env_file="/does/not/exist", password="x", insecure=True)


def test_resolve_es_flags_beat_env_beat_dotenv(tmp_path):
    envp = tmp_path / ".env"
    envp.write_text("ELASTIC_PASSWORD=dotenv-pw\n")
    es = cd.resolve_es(env={cd.ENV_PASSWORD: "env-pw"}, env_file=str(envp),
                       password="flag-pw", insecure=True)
    assert base64.b64decode(es.auth.split(" ", 1)[1]).decode().endswith(":flag-pw")


# --------------------------------------------------------------------------- #
# --post — a real stdlib http.server stub (the Es client has no injectable
# transport, unlike stix/opencti.py's, so it needs a socket to test against).
# --------------------------------------------------------------------------- #
class _StubHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        pass

    def _send(self, status, doc):
        body = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.calls.append(("GET", self.path))
        if self.path == "/_index_template/" + self.server.template_name:
            if self.server.live_template is None:
                self._send(404, {"error": {"reason": "index_template_missing_exception"}})
            else:
                self._send(200, {"index_templates": [{"name": self.server.template_name,
                                                       "index_template": self.server.live_template}]})
        else:
            self._send(404, {"error": {"reason": "no route: " + self.path}})

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n).decode()) if n else {}
        self.server.calls.append(("PUT", self.path, body))
        self.server.live_template = body
        self._send(200, {"acknowledged": True})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        text = self.rfile.read(n).decode()
        lines = [ln for ln in text.splitlines() if ln.strip()]
        self.server.calls.append(("POST", self.path, lines))
        items = []
        for i in range(0, len(lines), 2):
            doc_id = json.loads(lines[i])["index"]["_id"]
            if doc_id == self.server.fail_id:
                items.append({"index": {"_id": doc_id, "status": 400, "error": {"reason": "boom"}}})
            else:
                items.append({"index": {"_id": doc_id, "status": 200}})
        self._send(200, {"items": items})


@pytest.fixture()
def stub_es():
    server = http.server.HTTPServer(("127.0.0.1", 0), _StubHandler)
    server.calls, server.template_name, server.live_template, server.fail_id = [], "car-detections", None, None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _client(stub_es):
    return cd.Es(f"http://127.0.0.1:{stub_es.server_port}", "elastic", "x", None, True)


def test_put_template_if_needed_puts_when_absent(stub_es, contract):
    template, _join_keys = contract
    result = cd.put_template_if_needed(_client(stub_es), "car-detections", template)
    assert result == {"action": "put", "status": 200}
    assert [c[0:2] for c in stub_es.calls] == [("GET", "/_index_template/car-detections"),
                                               ("PUT", "/_index_template/car-detections")]


def test_put_template_if_needed_skips_when_already_equal(stub_es, contract):
    template, _join_keys = contract
    # the live template has extra, ES-defaulted fields this repo never commits
    # — still a match: skip means "diff-first", not "byte-for-byte GET == file".
    stub_es.live_template = dict(template, composed_of=[], allow_auto_create=None)
    result = cd.put_template_if_needed(_client(stub_es), "car-detections", template)
    assert result == {"action": "skipped", "reason": "already up to date"}
    assert [c[0] for c in stub_es.calls] == ["GET"]         # never PUT


def test_put_template_if_needed_puts_when_different(stub_es, contract):
    template, _join_keys = contract
    stub_es.live_template = {"index_patterns": ["car-detections"], "priority": 1, "template": {}}
    result = cd.put_template_if_needed(_client(stub_es), "car-detections", template)
    assert result["action"] == "put"
    assert [c[0] for c in stub_es.calls] == ["GET", "PUT"]


def test_post_bulk_accounts_accepted_and_errors(stub_es, tree, contract):
    template, join_keys = contract
    _summary, _docs, lines = cd.run_stamp(tree, template=template, join_keys=join_keys)
    stub_es.fail_id = f"{DET_A}:F1"
    result = cd.post_bulk(_client(stub_es), lines)
    assert result["total"] == 3 and result["accepted"] == 2
    assert len(result["errors"]) == 1 and DET_A + ":F1" in result["errors"][0]
    (post_call,) = [c for c in stub_es.calls if c[0] == "POST"]
    assert post_call[1] == "/_bulk?refresh=true" and len(post_call[2]) == 6  # 3 action/doc pairs


def test_post_bulk_is_a_noop_on_no_rows(stub_es):
    assert cd.post_bulk(_client(stub_es), []) == {"accepted": 0, "errors": [], "total": 0}
    assert stub_es.calls == []                              # never even called out


def test_main_post_end_to_end(tree, stub_es, capsys):
    code, out, _err = _run([tree, "--post", "--url", f"http://127.0.0.1:{stub_es.server_port}",
                            "--user", "elastic", "--password", "x", "--insecure"], capsys)
    assert code == 0
    summary = json.loads(out.splitlines()[-1])
    assert summary["template"]["action"] == "put"           # nothing live yet
    assert summary["bulk"] == {"accepted": 3, "errors": [], "total": 3}
    assert summary["ok"] is True
    methods = [c[0] for c in stub_es.calls]
    assert methods == ["GET", "PUT", "POST"]


def test_main_post_reports_bulk_errors_as_not_ok(tree, stub_es, capsys):
    stub_es.fail_id = f"{DET_A}:P1"
    code, out, _err = _run([tree, "--post", "--url", f"http://127.0.0.1:{stub_es.server_port}",
                            "--password", "x", "--insecure"], capsys)
    assert code == 1
    summary = json.loads(out.splitlines()[-1])
    assert summary["bulk"]["errors"] and summary["ok"] is False
