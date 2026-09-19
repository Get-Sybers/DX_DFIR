"""Unit tests for the Elastic detection rules-as-code loader (no Elastic needed).

The rule files are data; these tests are what makes them a contract: the rule
set is pinned (a detection can neither be dropped silently nor added unnoticed),
ported rules carry structurally sound ES|QL/EQL that stamps what their evidence
contract promises, stubs are explicit about what is still missing, and the
car-detections lookup index agrees with the loader's join keys.
"""
import copy
import datetime
import os
import re

import pytest
import yaml

from get_sybers_dxdfir.detect import rules_loader as rl

# The detection set, pinned. These are the ids the retired Kusto registry carried
# — each rule file keeps its provenance in `source` — so a rule cannot disappear
# silently, and a new one is a deliberate addition here.
EXPECTED_IDS = (
    "sig-hayabusa-high", "sig-suricata-alert", "sig-yara-match",
    "mem-malfind-injection",
    "win-defender-tamper", "win-eventlog-cleared", "win-prefetch-dualuse-tool",
    "win-service-suspicious-path",
    "zeek-dns-oversized-query", "zeek-notice-promoted",
)


@pytest.fixture(scope="module")
def rules():
    return rl.list_rules()


# ---- the seeded rule set ---------------------------------------------------
def test_seeded_rules_validate(rules):
    rl.validate(rules)                      # list_rules() already did; explicit


def test_rule_set_is_pinned(rules):
    # The full detection set is enumerated in Elastic — ported or stub — never
    # silently dropped, and no rule exists that is not pinned above.
    assert sorted(r["id"] for r in rules) == sorted(EXPECTED_IDS)
    assert all(r["source"]["registry"] == r["id"] for r in rules)


def test_rule_ids_unique_kebab_and_match_file_names(rules):
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    for r in rules:
        assert r["id"] == r["id"].lower() and " " not in r["id"]
        assert os.path.basename(r["_path"]) == r["id"] + ".yml"


def test_required_fields_present(rules):
    for r in rules:
        for field in rl.REQUIRED:
            assert field in r, f"{r['id']} lacks {field}"
        assert r["severity"] in rl.SEVERITIES
        assert r["language"] in rl.LANGUAGES
        assert r["status"] in rl.STATUSES
        assert all(i.startswith("logs-") for i in r["index"])
        assert r["risk_score"] == rl.RISK_SCORES[r["severity"]]   # defaulted on load


def test_rules_keep_their_source_provenance(rules):
    # Each rule records what it was ported from: the verbatim KQL of a query
    # detection, or the signature-lane matcher's name — the record outlives the
    # retired registry, so a port can always be checked against its source.
    for r in rules:
        src = r["source"]
        assert src["kind"] in rl.SOURCE_KINDS
        if src["kind"] == "kusto":
            assert src["kql"].strip()
            assert "match" not in src
        else:
            assert src["match"].startswith("match_")
            assert "kql" not in src
    assert {r["source"]["kind"] for r in rules} == set(rl.SOURCE_KINDS)


def test_at_least_three_ported_rules_well_formed(rules):
    ported = rl.ported(rules)
    assert len(ported) >= 3
    assert {"win-eventlog-cleared", "win-defender-tamper", "win-service-suspicious-path"} \
        <= {r["id"] for r in ported}
    for r in ported:
        assert r["query"].strip() and "todo" not in r
        assert rl.check_query(r) == []
        if r["language"] == "esql":
            assert r["query"].lstrip().upper().startswith("FROM ")
            assert r["evidence"]["stamped_by"] == "query"
            # the evidence line carries the rule identity inline ...
            assert {"rule.id", "rule.name"} <= set(r["evidence"]["fields"])
            assert f'rule.id = "{r["id"]}"' in r["query"]
            # ... and its ATT&CK techniques, when it has any
            if r["attack"]:
                assert "threat.technique.id" in r["evidence"]["fields"]
                assert all(t in r["query"] for t in r["attack"])
        else:
            assert re.search(r"\bwhere\b", r["query"])
            assert r["evidence"]["stamped_by"] == "engine"
            assert "kibana.alert.rule.threat" in r["evidence"]["fields"]


def test_ported_languages_cover_both_dialects(rules):
    langs = {r["language"] for r in rl.ported(rules)}
    assert langs == {"esql", "eql"}


def test_stubs_are_explicit(rules):
    stubs = rl.stubs(rules)
    assert stubs, "the scaffold keeps the unported detections as explicit stubs"
    for r in stubs:
        assert r["query"] is None
        assert r["todo"]["query"].lstrip().upper().startswith("FROM ")
        assert r["todo"]["blockers"]
        assert r["index"][0] in r["todo"]["query"]
        # the source detection is still fully described
        assert r["source"]["kind"] in rl.SOURCE_KINDS
    assert {r["id"] for r in stubs} >= {"sig-hayabusa-high", "sig-suricata-alert", "sig-yara-match"}


def test_ported_plus_stub_is_the_whole_set(rules):
    assert len(rl.ported(rules)) + len(rl.stubs(rules)) == len(rules) == len(EXPECTED_IDS)


def test_summary_counts(rules):
    s = rl.summary(rules)
    assert s["rules"] == len(rules)
    assert s["ported"] + s["stub"] == s["rules"]
    assert set(s["detections"]) == {r["id"] for r in rules}
    assert sum(s["by_language"].values()) == s["rules"]


# ---- validate() rejects malformed rules ------------------------------------
_BASE = {
    "id": "x-1", "name": "t", "status": "ported", "severity": "low", "attack": ["T1055"],
    "language": "esql", "index": ["logs-dxdfir.x-*"],
    "query": ('FROM logs-dxdfir.x-* METADATA _id, _index, _version\n'
              '| WHERE a == 1\n'
              '| EVAL rule.id = "x-1", threat.technique.id = "T1055"\n'
              '| LIMIT 10'),
    "evidence": {"shape": "line", "stamped_by": "query",
                 "fields": ["rule.id", "threat.technique.id"]},
    "car_join": {"key": "event.id", "via": "direct"},
    "source": {"registry": "x-1", "kind": "kusto", "kql": "T"},
}


def _patched(**patch):
    return {**copy.deepcopy(_BASE), **patch}


def test_base_rule_validates():
    rl.validate([_patched()])


@pytest.mark.parametrize("patch", [
    {"id": "Bad_Case"},
    {"status": "draft"},
    {"severity": "info"},                              # Elastic has no info
    {"severity": "urgent"},
    {"risk_score": 101},
    {"language": "kql"},
    {"name": 'has "quotes"'},
    {"attack": "T1055"},
    {"attack": ["T10"]},
    {"tactics": ["T1055"]},
    {"index": []},
    {"index": ["host.EvtxEcmdJson"]},
    {"index": ["logs-dxdfir.x-*", "logs-dxdfir.y-*"]},     # FROM reads only one of them
    {"evidence": {"shape": "line", "stamped_by": "query", "fields": []}},
    {"evidence": {"shape": "line", "stamped_by": "query", "fields": ["rule.id"]}},   # attack set, technique unstamped
    {"evidence": {"shape": "aggregate", "stamped_by": "query",
                  "fields": ["rule.id", "threat.technique.id"]}},                  # no STATS
    {"evidence": {"shape": "line", "stamped_by": "engine",
                  "fields": ["rule.id", "threat.technique.id"]}},                  # engine stamps kibana.alert.*
    {"car_join": {"key": "guid", "via": "direct"}},
    {"car_join": {"key": "event.id", "via": "provenance"}},                        # needs provenance fields
    {"fields": [{"ecs": "event.code"}]},
    {"source": {"registry": "x-1", "kind": "sql", "kql": "T"}},
    {"source": {"registry": "x-1", "kind": "kusto"}},
    {"source": {"registry": "x-1", "kind": "jsonl", "match": "not_a_matcher"}},
    {"todo": {"query": "FROM x", "blockers": ["b"]}},                              # ported rules carry no todo
    {"query": "   "},
    {"created": "yesterday"},                                                      # not ISO 8601
    {"created": "2026-09-02", "updated": "last week"},
    {"updated": "2026-09-02"},                                                     # updated without created
    {"created": "2026-09-02", "updated": "2026-09-01"},                            # updated before created
])
def test_validate_rejects_bad_rules(patch):
    with pytest.raises(ValueError):
        rl.validate([_patched(**patch)])


def test_validate_rejects_duplicate_ids_and_misnamed_files():
    with pytest.raises(ValueError, match="duplicate id"):
        rl.validate([_patched(), _patched()])
    with pytest.raises(ValueError, match="named <id>.yml"):
        rl.validate([_patched(_path="/rules/other-name.yml")])


def test_validate_stub_contract():
    stub = _patched(status="stub", query=None,
                    todo={"query": "FROM logs-dxdfir.x-* | WHERE a == 1", "blockers": ["why"]})
    rl.validate([stub])
    with pytest.raises(ValueError, match="query null"):
        rl.validate([_patched(status="stub", todo={"query": "FROM x", "blockers": ["why"]})])
    with pytest.raises(ValueError, match="todo.query"):
        rl.validate([_patched(status="stub", query=None, todo={"blockers": ["why"]})])
    with pytest.raises(ValueError, match="blockers"):
        rl.validate([_patched(status="stub", query=None, todo={"query": "FROM x", "blockers": []})])


def test_attackless_rule_must_not_stamp_technique():
    ok = _patched(attack=[], query='FROM logs-dxdfir.x-* METADATA _id, _index, _version\n| EVAL rule.id = "x-1"',
                  evidence={"shape": "line", "stamped_by": "query", "fields": ["rule.id"]})
    rl.validate([ok])
    with pytest.raises(ValueError, match="cannot be stamped"):
        rl.validate([_patched(attack=[])])


def test_rule_dates_are_iso_and_every_shipped_rule_is_dated(rules):
    # created / updated: the STIX indicator's created / valid_from and modified (STIX 2.1 §3.2, §3.6),
    # so every shipped rule carries created and the pair is ordered
    for r in rules:
        assert rl.rule_date(r.get("created")) is not None, r["id"]
        assert rl.rule_date(r.get("updated", r["created"])) >= rl.rule_date(r["created"]), r["id"]
    rl.validate([_patched(created="2026-09-02")])
    rl.validate([_patched(created="2026-09-02", updated="2026-09-02T07:01:04Z")])
    rl.validate([_patched(created=datetime.date(2026, 9, 2), updated=datetime.datetime(2026, 9, 3, 1, 2, 3))])
    assert rl.rule_date("2026-09-02").isoformat() == "2026-09-02T00:00:00+00:00"
    assert rl.rule_date("2026-09-02T09:01:04+02:00").isoformat() == "2026-09-02T07:01:04+00:00"
    assert rl.rule_date(datetime.date(2026, 9, 2)) == rl.rule_date("2026-09-02")
    assert rl.rule_date(None) is None and rl.rule_date(True) is None and rl.rule_date("") is None


# ---- structural query checks -----------------------------------------------
def _esql(query, **extra):
    return _patched(query=query, **extra)


def test_check_query_esql_shape():
    assert rl.check_query(_patched()) == []
    # missing METADATA on a non-aggregating query
    probs = rl.check_query(_esql('FROM logs-dxdfir.x-*\n| WHERE a == 1\n| EVAL rule.id = "x-1", threat.technique.id = "T1055"'))
    assert any("METADATA" in p for p in probs)
    # aggregating query needs no METADATA but must declare the aggregate shape
    agg = 'FROM logs-dxdfir.x-*\n| STATS n = COUNT(*) BY host.name\n| EVAL rule.id = "x-1", threat.technique.id = "T1055"'
    assert any("aggregate" in p for p in rl.check_query(_esql(agg)))
    assert rl.check_query(_esql(agg, evidence={"shape": "aggregate", "stamped_by": "query",
                                               "fields": ["host.name", "n", "rule.id", "threat.technique.id"]})) == []
    # not starting with FROM / wrong sources / unknown command
    assert any("FROM" in p for p in rl.check_query(_esql("ROW a = 1")))
    assert any("index declares" in p for p in rl.check_query(_esql(_BASE["query"].replace("logs-dxdfir.x-*", "logs-dxdfir.y-*"))))
    assert any("unknown ES|QL command" in p for p in rl.check_query(_esql(_BASE["query"] + "\n| PROJECT a")))


def test_check_query_promised_fields_must_be_stamped():
    probs = rl.check_query(_patched(evidence={"shape": "line", "stamped_by": "query",
                                              "fields": ["rule.id", "threat.technique.id", "threat.tactic.id"]}))
    assert probs == ["evidence field 'threat.tactic.id' is promised but never stamped by the query"]


def test_check_query_kql_leftovers_and_brackets():
    probs = rl.check_query(_esql('FROM logs-dxdfir.x-* METADATA _id, _index, _version\n| WHERE tostring(a) == "1" =~ b\n| EVAL rule.id = "x-1", threat.technique.id = "T1055"'))
    assert any("tostring(" in p for p in probs) and any("=~" in p for p in probs)
    # DATE_DIFF( is not the KQL iff(
    assert not any("iff(" in p for p in rl.check_query(
        _esql(_BASE["query"].replace("a == 1", "DATE_DIFF(\"hour\", a, b) > 1"))))
    assert any("unclosed" in p for p in rl.check_query(_esql(_BASE["query"].replace("== 1", "== (1"))))
    assert any("unexpected" in p for p in rl.check_query(_esql(_BASE["query"].replace("== 1", "== 1)"))))
    assert any("unterminated" in p for p in rl.check_query(_esql(_BASE["query"] + '\n| WHERE b == "open')))


def test_check_query_ignores_bracket_and_pipe_characters_inside_strings():
    q = (_BASE["query"] + '\n| WHERE TO_LOWER(a) RLIKE """.*(\\\\users\\\\|\\\\c[$]).*""" AND b != "(|["')
    assert rl.check_query(_esql(q)) == []


def test_check_query_eql_shape():
    eql = _patched(language="eql", query='any where event.code == "1102"',
                   evidence={"shape": "line", "stamped_by": "engine",
                             "fields": ["kibana.alert.rule.threat"]})
    assert rl.check_query(eql) == []
    assert rl.check_query({**eql, "query": 'sequence by host.name [any where a == 1] [any where b == 2]'}) == []
    assert any("<category> where" in p for p in rl.check_query({**eql, "query": 'event.code == "1102"'}))
    # EQL cannot stamp: the evidence contract must say the engine does
    bad = {**eql, "evidence": {"shape": "line", "stamped_by": "query", "fields": ["rule.id", "threat.technique.id"]}}
    assert any("stamped_by" in p for p in rl.check_query(bad))


# ---- loading from disk -----------------------------------------------------
def test_load_reads_only_top_level_rule_files(tmp_path):
    (tmp_path / "car-detections").mkdir()
    (tmp_path / "car-detections" / "ignored.yml").write_text("id: nope\n")
    (tmp_path / "x-1.yml").write_text(yaml.safe_dump(_BASE))
    rules = rl.load(str(tmp_path))
    assert [r["id"] for r in rules] == ["x-1"]
    assert rules[0]["_path"].endswith("x-1.yml") and rules[0]["risk_score"] == 21
    assert [r["id"] for r in rl.list_rules(str(tmp_path))] == ["x-1"]


def test_load_rejects_non_mapping_and_bad_yaml(tmp_path):
    (tmp_path / "x-1.yml").write_text("- just\n- a list\n")
    with pytest.raises(ValueError, match="one YAML mapping"):
        rl.load(str(tmp_path))
    (tmp_path / "x-1.yml").write_text("id: [unclosed\n")
    with pytest.raises(ValueError, match="not valid YAML"):
        rl.load(str(tmp_path))


def test_main_prints_summary_and_fails_on_bad_dir(tmp_path, capsys):
    assert rl.main([]) == 0
    out = capsys.readouterr().out
    assert '"ported"' in out and '"win-eventlog-cleared"' in out
    (tmp_path / "x-1.yml").write_text("id: Bad\n")
    assert rl.main(["--rules-dir", str(tmp_path)]) == 1
    assert "kebab-case" in capsys.readouterr().err


# ---- the car-detections lookup index contract ------------------------------
@pytest.fixture(scope="module")
def car_contract():
    return rl.load_car_detections()


def test_car_detections_contract_validates(car_contract):
    template, join_keys = car_contract
    rl.validate_car_detections(template, join_keys)
    assert template["template"]["settings"]["index.mode"] == "lookup"
    assert join_keys["lookup_index"] == "car-detections"
    assert {j["lookup_field"] for j in join_keys["join"]} == set(rl.CAR_JOIN_KEYS)
    assert "LOOKUP JOIN car-detections ON event.id" in join_keys["example_query"]
    assert "logs-car." in join_keys["example_query"]


def test_car_detections_stamps_the_threat_fields(car_contract):
    _template, join_keys = car_contract
    stamped = set(join_keys["stamped_fields"])
    assert {"threat.technique.id", "threat.tactic.id", "rule.id", "detection.id"} <= stamped


def test_every_rule_joins_on_a_declared_key(rules, car_contract):
    _template, join_keys = car_contract
    keys = {j["lookup_field"] for j in join_keys["join"]}
    for r in rules:
        assert r["car_join"]["key"] in keys, r["id"]


def test_validate_car_detections_rejects_drift(car_contract):
    template, join_keys = (copy.deepcopy(c) for c in car_contract)
    with pytest.raises(ValueError, match="index.mode"):
        rl.validate_car_detections({**template, "template": {**template["template"], "settings": {}}}, join_keys)
    bad = copy.deepcopy(join_keys)
    bad["join"][0]["lookup_field"] = "guid"
    with pytest.raises(ValueError, match="same field name"):
        rl.validate_car_detections(template, bad)
    bad = copy.deepcopy(join_keys)
    bad["join"] = bad["join"][:1]
    with pytest.raises(ValueError, match="CAR_JOIN_KEYS"):
        rl.validate_car_detections(template, bad)
    bad = copy.deepcopy(join_keys)
    bad["example_query"] = "FROM logs-car.*-*"
    with pytest.raises(ValueError, match="example_query"):
        rl.validate_car_detections(template, bad)

