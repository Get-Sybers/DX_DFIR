"""Unit tests for the OpenCTI / CTI wiring around Elastic's indicator match.

Three legs, none of them live: OpenCTI's indicators pulled through a
recording transport and copied into cti-* documents (threat.indicator.*),
the indicator-match rule contract validated against the cti-* template, and
indicator-match alerts turned into sightings of the platform's own indicators
and pushed back through the same stub. No network, no platform, no
Elasticsearch, no secrets.
"""
import copy
import json
import uuid

import pytest

from get_sybers_dxdfir.detect import rules_loader as rl
from get_sybers_dxdfir.stix import cli as stix_cli
from get_sybers_dxdfir.stix import config, export, objects, opencti
from get_sybers_dxdfir.stix.cti import indicators as ind
from get_sybers_dxdfir.stix.cti import sightings as sg
from get_sybers_dxdfir.stix.hits import flatten

NOW = "2026-09-02T10:00:00.000Z"
SCO_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
TLP_AMBER = objects.TLP_MARKING_IDS["amber"]


def _sid(kind, name):
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, 'test-cti/' + name)}"


IND_IP, IND_HASH, IND_DOMAIN = _sid("indicator", "ip"), _sid("indicator", "hash"), _sid("indicator", "domain")
IND_YARA, IND_CIDR, IND_URL = _sid("indicator", "yara"), _sid("indicator", "cidr"), _sid("indicator", "url")
IDENTITY = _sid("identity", "acme")
MARKING_STRICT = _sid("marking-definition", "amber-strict")
SHA256, MD5 = "a" * 64, "b" * 32


def _indicator(sid, pattern, **extra):
    base = {"type": "indicator", "spec_version": "2.1", "id": sid, "name": "n",
            "created": "2026-08-01T00:00:00.000Z", "modified": "2026-08-15T00:00:00.000Z",
            "pattern": pattern, "pattern_type": "stix", "valid_from": "2026-08-01T00:00:00.000Z",
            "created_by_ref": IDENTITY, "object_marking_refs": [TLP_AMBER]}
    base.update(extra)
    return base


# What a pull yields (or any STIX bundle holds): indicators plus the marking /
# identity objects they reference.
BUNDLE_OBJECTS = [
    _indicator(IND_IP, "[ipv4-addr:value = '203.0.113.9']", name="C2 beacon", confidence=85, labels=["c2"],
               external_references=[{"source_name": "x", "url": "https://ref.example.test/1"}],
               x_opencti_id="oc-1", x_opencti_score=80, x_opencti_detection=True,
               x_opencti_main_observable_type="IPv4-Addr"),
    _indicator(IND_HASH, f"[file:hashes.'SHA-256' = '{SHA256}' OR file:hashes.MD5 = '{MD5}']",
               confidence=40, valid_until="2027-01-01T00:00:00.000Z", revoked=False),
    _indicator(IND_DOMAIN, "[domain-name:value = 'evil.example' AND domain-name:value != 'good.example']",
               confidence=0, object_marking_refs=[MARKING_STRICT]),
    _indicator(IND_YARA, "rule x { condition: true }", pattern_type="yara"),
    _indicator(IND_CIDR, "[ipv4-addr:value = '203.0.113.0/24']"),
    _indicator(IND_URL, "[url:value = 'https://evil.example/p?q=1'] FOLLOWEDBY [mutex:name = 'm']", revoked=True),
    {"type": "identity", "spec_version": "2.1", "id": IDENTITY, "created": NOW, "modified": NOW,
     "name": "ACME CTI", "identity_class": "organization"},
    objects.tlp_marking("amber"),
    {"type": "marking-definition", "spec_version": "2.1", "id": MARKING_STRICT, "created": NOW,
     "definition_type": "tlp", "name": "TLP:AMBER+STRICT", "definition": {"tlp": "amber+strict"}},
]


class RecordingTransport:
    def __init__(self, responses=None, status=200, text='{"data": {"stixBundlePush": true}}'):
        self.calls, self.responses, self.status, self.text = [], list(responses or []), status, text

    def post(self, url, headers, body, timeout):
        self.calls.append((url, dict(headers), body, timeout))
        return self.responses.pop(0) if self.responses else (self.status, self.text)


# ---- the data: pattern mapping + index template ----------------------------
def test_pattern_mapping_and_template_agree():
    m, t = ind.load_pattern_mapping(), ind.load_template()
    ind.validate_pattern_mapping({"indicator_path": m.indicator_path, "comparisons": m.comparisons})
    ind.validate_template(t, m)
    fields = ind.template_fields(t)
    assert t["index_patterns"] == ["cti-*"] and t["template"]["mappings"]["dynamic"] == "strict"
    assert fields["threat.indicator.ip"] == "ip" and fields["threat.indicator.id"] == "keyword"
    assert m.indicator_path == "threat.indicator" == t["_meta"]["indicator_path"]
    assert m.ecs_fields <= set(fields)                      # every comparison lands in a mapped field
    assert {c["type"] for c in m.comparisons} >= {"ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "email-addr"}
    assert m.lookup("file:hashes.'SHA-256'")["ecs"] == "threat.indicator.file.hash.sha256"
    assert m.lookup("file:hashes.sha256")["ecs"] == "threat.indicator.file.hash.sha256"   # forgiving spelling
    assert m.lookup("process:pid") is None


def test_validate_pattern_mapping_and_template_reject_drift():
    m, t = ind.load_pattern_mapping(), ind.load_template()
    with pytest.raises(ValueError, match="mapped twice"):
        ind.validate_pattern_mapping({"indicator_path": "threat.indicator", "comparisons": m.comparisons + [m.comparisons[0]]})
    with pytest.raises(ValueError, match="under threat.indicator"):
        ind.validate_pattern_mapping({"indicator_path": "threat.indicator", "comparisons": [
            {"stix": "a:b", "ecs": "source.ip", "type": "a", "value_type": "ip"}]})
    props = lambda tpl: tpl["template"]["mappings"]["properties"]["threat"]["properties"]["indicator"]["properties"]  # noqa: E731
    bad = copy.deepcopy(t)
    bad["template"]["mappings"]["dynamic"] = True
    with pytest.raises(ValueError, match="strict"):
        ind.validate_template(bad, m)
    bad = copy.deepcopy(t)
    del props(bad)["ip"]
    with pytest.raises(ValueError, match="not mapped"):
        ind.validate_template(bad, m)
    bad = copy.deepcopy(t)
    props(bad)["ip"] = {"type": "keyword"}
    with pytest.raises(ValueError, match="does not hold"):
        ind.validate_template(bad, m)
    bad = copy.deepcopy(t)
    bad["index_patterns"] = ["logs-*"]
    with pytest.raises(ValueError, match="cti-"):
        ind.validate_template(bad, m)
    bad = copy.deepcopy(t)
    bad["index_patterns"] = ["cti-"]              # an empty dataset after "cti-" is not a valid index
    with pytest.raises(ValueError, match="cti-"):
        ind.validate_template(bad, m)


# ---- the pattern reader ----------------------------------------------------
def test_parse_pattern_lifts_only_unnegated_equalities():
    assert ind.parse_pattern("[ipv4-addr:value = '203.0.113.9']") == [("ipv4-addr:value", "203.0.113.9")]
    assert ind.parse_pattern("[file:hashes.'SHA-256' = 'ab' OR file:hashes.MD5 = 'cd']") == \
        [("file:hashes.SHA-256", "ab"), ("file:hashes.MD5", "cd")]
    compound = ("[domain-name:value = 'a.example' AND domain-name:value != 'b.example' AND url:value NOT = 'c'"
                " AND file:name LIKE 'x%' AND file:size > 10] FOLLOWEDBY [ipv6-addr:value = '2001:db8::1'] WITHIN 600 SECONDS")
    assert ind.parse_pattern(compound) == [("domain-name:value", "a.example"), ("ipv6-addr:value", "2001:db8::1")]
    assert ind.parse_pattern("[file:name = 'it\\'s.exe']") == [("file:name", "it's.exe")]
    assert ind.parse_pattern("[autonomous-system:number = 64512]") == [("autonomous-system:number", "64512")]
    assert ind.parse_pattern("rule x { condition: true }") == [] and ind.parse_pattern("") == []


# ---- indicators -> cti-* documents ------------------------------------------
def test_indicators_become_cti_docs_with_threat_indicator_fields():
    docs, report = ind.to_cti_docs(BUNDLE_OBJECTS, now=NOW, template=ind.load_template())
    assert report["indicators"] == 6 and report["docs"] == 4
    assert report["skipped"] == {"pattern_type:yara": 1, "bad_value": 1}      # a YARA rule, a CIDR: counted, not guessed
    by_id = {ind.document_id(d): d for d in docs}
    ip = by_id[IND_IP]
    assert ip["@timestamp"] == NOW
    assert ip["event"] == {"kind": "enrichment", "category": ["threat"], "type": ["indicator"],
                           "dataset": "cti.opencti", "module": "opencti"}
    ti = ip["threat"]["indicator"]
    assert ti["id"] == IND_IP and ti["type"] == "ipv4-addr" and ti["ip"] == "203.0.113.9"
    assert ti["name"] == "C2 beacon" and ti["confidence"] == "High" and ti["provider"] == "ACME CTI"
    assert ti["marking"] == {"tlp": "AMBER"} and ti["reference"] == "https://ref.example.test/1"
    assert ti["first_seen"] == "2026-08-01T00:00:00.000Z" and ti["modified_at"] == "2026-08-15T00:00:00.000Z"
    assert ip["threat"]["feed"] == {"name": "opencti"} and ip["tags"] == ["c2"]
    assert ip["stix"]["pattern"] == "[ipv4-addr:value = '203.0.113.9']" and ip["stix"]["revoked"] is False
    assert ip["stix"]["confidence"] == 85 and ip["stix"]["id"] == IND_IP
    assert ip["opencti"] == {"id": "oc-1", "score": 80, "detection": True, "main_observable_type": "IPv4-Addr"}
    h = by_id[IND_HASH]["threat"]["indicator"]
    assert h["type"] == "file" and h["file"]["hash"] == {"sha256": SHA256, "md5": MD5} and h["confidence"] == "Medium"
    assert by_id[IND_HASH]["stix"]["valid_until"] == "2027-01-01T00:00:00.000Z"
    d = by_id[IND_DOMAIN]["threat"]["indicator"]
    assert d["url"] == {"domain": "evil.example"} and d["confidence"] == "None"    # the != comparison is not atomic
    assert d["marking"] == {"tlp": "AMBER+STRICT", "tlp_version": "2.0"}         # resolved through its marking object
    u = by_id[IND_URL]
    assert u["threat"]["indicator"]["url"] == {"original": "https://evil.example/p?q=1"} and u["stix"]["revoked"] is True
    # every field written is one the STRICT template maps (else the bulk would be rejected)
    fields = ind.template_fields(ind.load_template())
    for doc in docs:
        assert set(flatten(doc)) <= set(fields)


def test_cti_doc_skip_reasons_values_and_markings():
    m = ind.load_pattern_mapping()

    def one(**extra):
        obj = _indicator(IND_IP, "[ipv4-addr:value = '1.1.1.1']")
        obj.update(extra)
        return ind.to_cti_doc(obj, mapping=m, now=NOW)
    assert one().doc["threat"]["indicator"]["ip"] == "1.1.1.1"
    assert one(pattern="[mutex:name = 'x']").reason == "unmapped"
    assert one(pattern="[ipv4-addr:value != '1.1.1.1']").reason == "no_comparison"
    assert one(pattern="").reason == "no_pattern"
    assert one(pattern_type="sigma").reason == "pattern_type:sigma"
    assert one(id="indicator--not-a-uuid").reason == "bad_id"
    assert ind.to_cti_doc({"type": "identity", "id": IDENTITY}, mapping=m, now=NOW).reason == "not_indicator"
    two = one(pattern="[ipv4-addr:value = '1.1.1.1' OR ipv4-addr:value = '2.2.2.2' OR ipv4-addr:value = '1.1.1.1'"
                      " OR ipv4-addr:value = '10.0.0.0/8']")
    assert two.doc["threat"]["indicator"]["ip"] == ["1.1.1.1", "2.2.2.2"] and two.dropped == 1
    assert one(confidence=None).doc["threat"]["indicator"]["confidence"] == "Not Specified"
    assert (ind.confidence_label(29), ind.confidence_label(30), ind.confidence_label(70)) == ("Low", "Medium", "High")
    assert ind.confidence_label(101) == "Not Specified" and ind.confidence_label(0) == "None"
    # an unknown marking id resolves to no TLP; the spec's four ids need no context; the strictest wins
    unknown = one(object_marking_refs=["marking-definition--" + str(uuid.uuid4())])
    assert "marking" not in unknown.doc["threat"]["indicator"]
    assert one(object_marking_refs=[TLP_AMBER, objects.TLP_MARKING_IDS["red"]]).doc["threat"]["indicator"]["marking"] == {"tlp": "RED"}
    # a mapping target the template does not map is a defect, surfaced — not a rejected bulk later
    off = ind.PatternMapping({"indicator_path": "threat.indicator", "comparisons": [
        {"stix": "ipv4-addr:value", "ecs": "threat.indicator.nope", "type": "ipv4-addr", "value_type": "ip"}]})
    with pytest.raises(ValueError, match="does not map"):
        ind.to_cti_docs(BUNDLE_OBJECTS[:1], mapping=off, now=NOW, template=ind.load_template())


def test_bulk_lines_are_upserts_keyed_on_the_stix_id():
    docs, _ = ind.to_cti_docs(BUNDLE_OBJECTS, now=NOW)
    lines = list(ind.bulk_lines(docs, "cti-opencti"))
    assert len(lines) == 2 * len(docs) and all("\n" not in line for line in lines)
    assert json.loads(lines[0]) == {"index": {"_index": "cti-opencti", "_id": IND_IP}}
    assert json.loads(lines[1]) == docs[0]
    for bad in ("cti-*", "logs-cti", ""):
        with pytest.raises(ValueError):
            list(ind.bulk_lines(docs, bad))


# ---- the pull, through the stubbed transport -------------------------------
def _node(sid, pattern, **extra):
    node = {"id": "oc-" + sid[-4:], "standard_id": sid, "name": "n", "description": None, "pattern": pattern,
            "pattern_type": "stix", "valid_from": "2026-08-01T00:00:00.000Z", "valid_until": None, "revoked": False,
            "confidence": 85, "created": "2026-08-01T00:00:00.000Z", "modified": "2026-08-15T00:00:00.000Z",
            "indicator_types": ["malicious-activity"], "x_opencti_score": 80, "x_opencti_detection": True,
            "x_opencti_main_observable_type": "IPv4-Addr",
            "objectLabel": [{"value": "c2"}],
            "objectMarking": [{"standard_id": TLP_AMBER, "definition_type": "TLP", "definition": "TLP:AMBER",
                               "created": "2017-01-20T00:00:00.000Z"}],
            "createdBy": {"standard_id": IDENTITY, "name": "ACME CTI", "identity_class": "organization",
                          "created": NOW, "modified": NOW},
            "externalReferences": {"edges": [{"node": {"source_name": "x", "url": "https://ref.example.test/1",
                                                       "external_id": None}}]},
            "killChainPhases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]}
    node.update(extra)
    return node


def _page(nodes, cursor, more):
    return 200, json.dumps({"data": {"indicators": {
        "edges": [{"node": n} for n in nodes],
        "pageInfo": {"endCursor": cursor, "hasNextPage": more, "globalCount": 3}}}})


def test_pull_indicators_pages_through_the_stubbed_transport():
    strict = [{"standard_id": MARKING_STRICT, "definition_type": "TLP", "definition": "TLP:AMBER+STRICT",
               "created": None}]
    rec = RecordingTransport(responses=[
        _page([_node(IND_IP, "[ipv4-addr:value = '203.0.113.9']"),
               _node(IND_HASH, f"[file:hashes.'SHA-256' = '{SHA256}']")], "c1", True),
        _page([_node(IND_DOMAIN, "[domain-name:value = 'evil.example']", objectMarking=strict,
                     createdBy={"standard_id": IDENTITY, "name": "ACME CTI", "identity_class": "organization"}),
               {"standard_id": "indicator--x", "pattern": None}], "c2", False),
    ])
    client = opencti.OpenCTIClient("https://opencti.example.test", "tok-123", transport=rec, timeout=5)
    result = client.pull_indicators(since="2026-08-01T00:00:00Z", page_size=2)
    assert result.ok and result.indicators == 3 and result.pages == 2 and result.skipped == 1
    # the exact requests: endpoint, bearer, the indicators query, cursor pagination, the since filter
    assert [c[0] for c in rec.calls] == ["https://opencti.example.test/graphql"] * 2
    assert rec.calls[0][1]["Authorization"] == "Bearer tok-123" and rec.calls[0][3] == 5.0
    first, second = (json.loads(c[2]) for c in rec.calls)
    assert first["query"].startswith("query DxdfirIndicators") and "indicators(" in first["query"]
    assert first["variables"]["first"] == 2 and first["variables"]["after"] is None
    assert first["variables"]["filters"]["filters"] == [
        {"key": "modified", "values": ["2026-08-01T00:00:00.000Z"], "operator": "gt", "mode": "or"}]
    assert second["variables"]["after"] == "c1"
    # the bundle: the three indicators plus the identity and the NON-spec marking they reference —
    # the spec's own TLP instance is referenced, never shipped (BP §3.5) — valid STIX 2.1
    bundle = result.bundle
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    assert export.summarise(bundle)["by_type"] == {"identity": 1, "indicator": 3, "marking-definition": 1}
    errors, warnings = export.validate_bundle(bundle)
    assert errors == [] and warnings and all("x_opencti" in w for w in warnings)   # the platform's own x_ props
    ip = next(x for x in bundle["objects"] if x["id"] == IND_IP)
    assert ip["pattern_type"] == "stix" and ip["created_by_ref"] == IDENTITY and ip["object_marking_refs"] == [TLP_AMBER]
    assert ip["labels"] == ["c2"] and ip["external_references"] == [{"source_name": "x", "url": "https://ref.example.test/1"}]
    assert ip["kill_chain_phases"] == [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]
    assert ip["x_opencti_id"] == "oc-" + IND_IP[-4:] and ip["x_opencti_score"] == 80 and ip["revoked"] is False
    marking = next(x for x in bundle["objects"] if x["type"] == "marking-definition")
    assert marking["id"] == MARKING_STRICT and marking["definition"] == {"tlp": "amber+strict"}
    assert marking["created"] == "2026-08-01T00:00:00.000Z"          # undated on the platform: the indicator's created
    identity = next(x for x in bundle["objects"] if x["type"] == "identity")
    assert identity["created"] == identity["modified"] == NOW        # the first page's creator carried its dates
    # ... and normalises straight into cti-* documents, provider and TLP resolved from the bundle
    docs, report = ind.to_cti_docs(bundle["objects"], now=NOW)
    assert report["docs"] == 3 and {ind.document_id(d) for d in docs} == {IND_IP, IND_HASH, IND_DOMAIN}
    assert docs[0]["threat"]["indicator"]["provider"] == "ACME CTI"
    assert docs[0]["threat"]["indicator"]["marking"] == {"tlp": "AMBER"}
    assert docs[2]["threat"]["indicator"]["marking"] == {"tlp": "AMBER+STRICT", "tlp_version": "2.0"}
    # the token never reaches a summary; the summary counts the bundle instead of repeating it
    assert "tok-123" not in json.dumps(result.as_dict()) and result.as_dict()["objects"] == 5
    assert "tok-123" not in repr(client)


def test_pull_indicators_reports_refusals_and_max_pages():
    def pull(*responses, **kw):
        client = opencti.OpenCTIClient("https://x.test", "t", transport=RecordingTransport(responses=list(responses)))
        return client.pull_indicators(**kw)
    assert not pull((401, "")).ok and "token" in pull((401, "")).message
    refused = pull((200, '{"errors": [{"message": "Cannot query field filters"}]}'))
    assert not refused.ok and "Cannot query field filters" in refused.message
    down = pull((0, "connection refused"))
    assert not down.ok and "unreachable" in down.message
    drift = pull((200, '{"data": {"nope": 1}}'))
    assert not drift.ok and "schema drift" in drift.message
    assert not pull((500, "<html>boom</html>")).ok
    # max_pages stops a runaway pull and says so
    page = _page([_node(IND_IP, "[ipv4-addr:value = '1.1.1.1']")], "c", True)
    capped = pull(page, page, page, max_pages=2)
    assert capped.ok and capped.pages == 2 and "max_pages" in capped.message and capped.indicators == 1
    # non-positive paging is rejected up front, before any request
    with pytest.raises(ValueError, match="page_size"):
        pull(page_size=0)
    with pytest.raises(ValueError, match="max_pages"):
        pull(max_pages=0)
    # an empty platform is an empty (valid) result; a bad --since is refused before any request
    empty = pull(_page([], None, False))
    assert empty.ok and empty.indicators == 0 and empty.bundle["objects"] == []
    with pytest.raises(ValueError):
        pull(page, since="yesterday")
    assert opencti.indicator_filters(None) is None


# ---- indicator-match alerts -> sightings -----------------------------------
def _alert(atomic="203.0.113.9", field="source.ip", ref=IND_IP, host="PC1", uuid_="al-1",
           when="2026-08-31T12:00:00Z", extra_enrichment=None):
    enrichments = [{"indicator": {"id": ref, "type": "ipv4-addr", "name": "C2 beacon", "provider": "ACME CTI",
                                  "marking": {"tlp": "AMBER"}},
                    "matched": {"atomic": atomic, "field": field, "id": ref, "index": "cti-opencti",
                                "type": "indicator_match_rule"},
                    "feed": {"name": "opencti"}}]
    if extra_enrichment:
        enrichments.append(extra_enrichment)
    doc = {"@timestamp": "2026-09-02T09:00:00Z", "_index": ".alerts-security.alerts-default", "_id": uuid_,
           "kibana": {"alert": {"uuid": uuid_, "original_time": when,
                                "rule": {"rule_id": "cti-indicator-match", "name": "CTI indicator match",
                                         "execution": {"uuid": "exec-1"}}}},
           "source": {"ip": atomic}, "threat": {"enrichments": enrichments}}
    if host:
        doc["host"] = {"name": host}
    return doc


def test_indicator_match_alert_becomes_a_sighting_of_the_platform_indicator():
    hash_hit = {"indicator": {"id": IND_HASH, "type": "file"},
                "matched": {"atomic": SHA256, "field": "file.hash.sha256", "id": IND_HASH, "index": "cti-opencti",
                            "type": "indicator_match_rule"}, "feed": {"name": "opencti"}}
    bundle = sg.build_sightings_bundle([_alert(extra_enrichment=hash_hit)], case_id="CASE-17")
    sightings = [x for x in bundle["objects"] if x["type"] == "sighting"]
    by_ref = {s["sighting_of_ref"]: s for s in sightings}
    assert set(by_ref) == {IND_IP, IND_HASH}                 # OpenCTI's own indicator ids ...
    assert not [x for x in bundle["objects"] if x["type"] == "indicator"]   # ... never re-emitted
    s = by_ref[IND_IP]
    assert s["id"].startswith("sighting--") and s["spec_version"] == "2.1" and s["count"] == 1
    assert s["first_seen"] == s["last_seen"] == "2026-08-31T12:00:00.000Z"
    assert s["created"] == "2026-08-31T12:00:00.000Z"       # the observation, never the export clock (§3.2)
    assert s["modified"] == "2026-09-02T09:00:00.000Z"      # the alert's own time
    host = next(x for x in bundle["objects"] if x["type"] == "identity" and x["name"] == "PC1")
    assert s["where_sighted_refs"] == [host["id"]] and host["identity_class"] == "system"
    od = next(x for x in bundle["objects"] if x["id"] == s["observed_data_refs"][0])
    assert od["created"] == od["first_observed"] == "2026-08-31T12:00:00.000Z" and od["object_marking_refs"] == [TLP_AMBER]
    ip = next(x for x in bundle["objects"] if x["id"] == od["object_refs"][0])
    assert ip == {"type": "ipv4-addr", "spec_version": "2.1", "value": "203.0.113.9",
                  "id": "ipv4-addr--" + str(uuid.uuid5(SCO_NS, '{"value":"203.0.113.9"}'))}   # unmarked (BP §3.5)
    assert next(x for x in bundle["objects"] if x["type"] == "file")["hashes"] == {"SHA-256": SHA256}
    dx = objects.extension_of(s)
    assert dx["matched"] == {"field": "source.ip", "atomic": "203.0.113.9", "index": "cti-opencti", "id": IND_IP}
    assert dx["detection_id"] == "cti-indicator-match" and dx["alert_ids"] == ["al-1"]
    assert dx["case_id"] == "CASE-17" and dx["feed"] == "opencti" and dx["indicator"]["name"] == "C2 beacon"
    assert not any(k.startswith("x_") for x in bundle["objects"] for k in x)
    assert next(x for x in bundle["objects"] if x["type"] == "extension-definition")["id"] == objects.EXTENSION_ID
    assert not [x for x in bundle["objects"] if x["type"] == "marking-definition"]   # TLP referenced, not shipped
    assert "203.0.113.9" in s["description"] and "PC1" in s["description"]
    schema = json.loads(open(objects.__file__.replace("objects.py", "extension/dxdfir-extension.schema.json")).read())
    for k, v in dx.items():
        assert k in schema["properties"] and (not isinstance(v, dict) or set(v) <= set(schema["properties"][k]["properties"]))
    errors, warnings = export.validate_bundle(bundle)
    assert errors == [] and warnings and all("sighting_of_ref" in w for w in warnings)   # lives on the platform: warned
    assert export.summarise(bundle)["sightings"] == 2


def test_sightings_collapse_and_scope():
    a1 = _alert(uuid_="al-1", when="2026-08-31T12:00:00Z")
    a2 = _alert(uuid_="al-2", when="2026-08-30T08:00:00Z")
    other_host, no_host = _alert(uuid_="al-3", host="PC2"), _alert(uuid_="al-4", host=None)
    objs, report = sg.alert_sightings(
        [a1, a2, other_host, no_host, {"event": {"id": "no enrichment"}}, _alert(ref="not-an-id", uuid_="al-5")],
        case_id="CASE-1")
    assert report == {"alerts": 6, "enrichments": 5, "sightings": 3,
                      "skipped": {"no_enrichment": 1, "no_indicator_ref": 1}}
    sightings = [x for x in objs.values() if x["type"] == "sighting"]
    collapsed = next(s for s in sightings if s["count"] == 2)
    assert collapsed["first_seen"] == "2026-08-30T08:00:00.000Z" and collapsed["last_seen"] == "2026-08-31T12:00:00.000Z"
    assert collapsed["created"] == "2026-08-30T08:00:00.000Z" and collapsed["modified"] == "2026-09-02T09:00:00.000Z"
    assert objects.extension_of(collapsed)["alert_ids"] == ["al-1", "al-2"]
    assert len(collapsed["observed_data_refs"]) == 2                 # one observation per alert time
    producer = next(x for x in objs.values() if x["type"] == "identity" and x["name"] == "DX_DFIR")
    unhosted = next(s for s in sightings if objects.extension_of(s)["alert_ids"] == ["al-4"])
    assert unhosted["where_sighted_refs"] == [producer["id"]]       # nobody named: the pipeline saw it
    # case-scoped ids: idempotent within a case (the same objects, byte for byte), distinct across cases;
    # no case given: the rule execution id
    ids = {s["id"] for s in sightings}
    again, _ = sg.alert_sightings([a1, a2, other_host, no_host], case_id="CASE-1")
    assert {k for k, v in again.items() if v["type"] == "sighting"} == ids
    assert all(again[k] == objs[k] for k in again)
    reordered, _ = sg.alert_sightings([no_host, other_host, a2, a1], case_id="CASE-1")
    assert reordered[collapsed["id"]]["created"] == collapsed["created"]
    elsewhere, _ = sg.alert_sightings([a1], case_id="CASE-2")
    assert not {k for k, v in elsewhere.items() if v["type"] == "sighting"} & ids
    uncased, _ = sg.alert_sightings([a1])
    assert objects.extension_of(next(v for v in uncased.values() if v["type"] == "sighting"))["case_id"] == "exec-1"


def test_matched_observables():
    assert sg.matched_observable("destination.ip", "2001:db8::1")["type"] == "ipv6-addr"
    assert sg.matched_observable("process.hash.md5", MD5)["hashes"] == {"MD5": MD5}
    assert sg.matched_observable("dns.question.name", "Evil.Example.")["value"] == "evil.example"
    assert sg.matched_observable("url.full", "https://evil.example/x")["type"] == "url"
    assert sg.matched_observable("registry.key", "HKLM\\x") is None      # sighted without an observable
    assert sg.matched_observable("source.ip", "PC1") is None            # not an address: nothing invented
    assert objects.domain_name("") is None and objects.url(" ") is None
    assert objects.domain_name("evil.example")["id"] == "domain-name--" + str(uuid.uuid5(SCO_NS, '{"value":"evil.example"}'))


def test_run_sightings_pushes_through_the_stubbed_transport(tmp_path):
    alerts = tmp_path / "alerts.json"
    alerts.write_text(json.dumps({"took": 1, "hits": {"total": {"value": 1}, "hits": [
        {"_index": ".alerts-security.alerts-default", "_id": "al-1", "_source": _alert()}]}}))
    out = tmp_path / "exchange" / "sightings.json"
    rec = RecordingTransport()
    cfg = config.StixConfig(case_id="CASE-9", out=str(out), push=True, opencti_url="https://opencti.example.test",
                            opencti_token="tok-123", opencti_connector_id="conn-1")
    summary, bundle = sg.run_sightings(cfg, [str(alerts)], transport=rec)
    assert summary["ok"] and summary["push"]["ok"] and summary["sightings"]["sightings"] == 1
    assert json.loads(out.read_text()) == bundle and summary["validation"]["errors"] == []
    url, headers, body, _timeout = rec.calls[0]
    assert url == "https://opencti.example.test/graphql" and headers["Authorization"] == "Bearer tok-123"
    payload = json.loads(body)
    assert "stixBundlePush" in payload["query"] and payload["variables"]["connectorId"] == "conn-1"
    pushed = json.loads(payload["variables"]["bundle"])
    assert pushed == bundle
    assert next(x for x in pushed["objects"] if x["type"] == "sighting")["sighting_of_ref"] == IND_IP
    assert "tok-123" not in json.dumps(summary)
    # a refused push is not ok; alerts without an enrichment, or no alerts at all, are refused up front
    summary, _ = sg.run_sightings(cfg, [str(alerts)], transport=RecordingTransport(status=403, text=""))
    assert not summary["ok"] and "token" in summary["push"]["message"]
    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps([{"event": {"id": "x"}}]))
    with pytest.raises(ValueError, match="enrichment"):
        sg.run_sightings(config.StixConfig(), [str(plain)])
    empty = tmp_path / "empty.json"
    empty.write_text("")
    with pytest.raises(ValueError, match="no alerts"):
        sg.run_sightings(config.StixConfig(), [str(empty)])


# ---- the pull verb + config + CLI -------------------------------------------
def test_run_pull_from_bundle_and_via_client(tmp_path):
    bundle_path = tmp_path / "indicators.json"
    bundle_path.write_text(json.dumps({"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": BUNDLE_OBJECTS}))
    out = tmp_path / "copy" / "cti.ndjson"
    summary, lines = ind.run_pull(config.StixConfig(cti_index="cti-case17"), from_bundle=str(bundle_path),
                                  out=str(out), now=NOW)
    assert summary["ok"] and summary["copy"]["docs"] == 4 and summary["index"] == "cti-case17"
    written = out.read_text().splitlines()
    assert written == lines and json.loads(written[0]) == {"index": {"_index": "cti-case17", "_id": IND_IP}}
    # via the client: the transport is the stub, the pulled bundle is kept, the summary counts the pull
    rec = RecordingTransport(responses=[_page([_node(IND_IP, "[ipv4-addr:value = '203.0.113.9']")], None, False)])
    cfg = config.StixConfig(opencti_url="https://x.test", opencti_token="t")
    keep = tmp_path / "pulled.json"
    summary, lines = ind.run_pull(cfg, bundle_out=str(keep), transport=rec, now=NOW)
    assert summary["ok"] and summary["pull"]["indicators"] == 1 and summary["copy"]["docs"] == 1 and len(lines) == 2
    assert export.validate_bundle(json.loads(keep.read_text()))[0] == []
    assert summary["validation"]["errors"] == [] and summary["config"]["opencti_token"] == "***"
    # a refused pull: not ok, nothing written
    never = tmp_path / "never.ndjson"
    summary, lines = ind.run_pull(cfg, out=str(never), transport=RecordingTransport(status=401, text=""), now=NOW)
    assert not summary["ok"] and lines == [] and not never.exists()


def test_config_cti_index_layers(tmp_path):
    f = tmp_path / "stix.yml"
    f.write_text("cti:\n  index: cti-file\n")
    assert config.load_config(str(f), env={}).cti_index == "cti-file"
    assert config.load_config(str(f), env={"DXDFIR_CTI_INDEX": "cti-env"}).cti_index == "cti-env"
    assert config.load_config(str(f), env={"DXDFIR_CTI_INDEX": "cti-env"}, cti_index="cti-flag").cti_index == "cti-flag"
    assert config.load_config(env={}).cti_index == "cti-opencti"


def _stix(argv, capsys):
    """Drive the argparse CLI exactly as the Go passthrough does — an argv list to
    ``main`` — and return (exit_code, stdout, stderr)."""
    try:
        stix_cli.main(argv)
        code = 0
    except SystemExit as e:
        code = e.code if e.code is not None else 0
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_stix_pull_and_sightings(tmp_path, monkeypatch, capsys):
    for var in ("DXDFIR_OPENCTI_URL", "DXDFIR_OPENCTI_TOKEN", "DXDFIR_CTI_INDEX"):
        monkeypatch.delenv(var, raising=False)
    bundle_path = tmp_path / "indicators.json"
    bundle_path.write_text(json.dumps({"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": BUNDLE_OBJECTS}))
    out = tmp_path / "cti.ndjson"
    code, stdout, stderr = _stix(["pull", "--from-bundle", str(bundle_path), "--out", str(out), "--index", "cti-case7"],
                                 capsys)
    assert code == 0, stdout + stderr
    assert json.loads(out.read_text().splitlines()[0])["index"]["_index"] == "cti-case7"
    summary = json.loads(stdout)
    assert summary["copy"]["docs"] == 4 and summary["out"] == str(out)
    # without --out the bulk lines are stdout; without endpoint/token (and no bundle) it is exit 2
    code, stdout, stderr = _stix(["pull", "--from-bundle", str(bundle_path)], capsys)
    assert code == 0, stdout + stderr
    assert json.loads(stdout.splitlines()[0]) == {"index": {"_index": "cti-opencti", "_id": IND_IP}}
    assert _stix(["pull"], capsys)[0] == 2
    # a live-shaped pull goes through the (stubbed) transport with endpoint/token/index from the environment
    rec = RecordingTransport(responses=[_page([_node(IND_IP, "[ipv4-addr:value = '203.0.113.9']")], None, False)])
    monkeypatch.setattr(opencti, "UrllibTransport", lambda: rec)
    monkeypatch.setenv("DXDFIR_OPENCTI_URL", "https://env.test")
    monkeypatch.setenv("DXDFIR_OPENCTI_TOKEN", "env-token")
    monkeypatch.setenv("DXDFIR_CTI_INDEX", "cti-env")
    code, stdout, stderr = _stix(["pull", "--out", str(out), "--since", "2026-08-01T00:00:00Z"], capsys)
    assert code == 0, stdout + stderr
    assert rec.calls[0][0] == "https://env.test/graphql" and rec.calls[0][1]["Authorization"] == "Bearer env-token"
    assert json.loads(rec.calls[0][2])["variables"]["filters"]["filters"][0]["values"] == ["2026-08-01T00:00:00.000Z"]
    assert json.loads(out.read_text().splitlines()[0])["index"]["_index"] == "cti-env"
    assert "env-token" not in stdout + stderr
    # a refused pull is exit 1; a bad --since is exit 2
    monkeypatch.setattr(opencti, "UrllibTransport", lambda: RecordingTransport(status=403, text=""))
    assert _stix(["pull"], capsys)[0] == 1
    assert _stix(["pull", "--since", "yesterday"], capsys)[0] == 2
    # sightings: alerts -> bundle on disk, --push through the transport
    alerts = tmp_path / "alerts.jsonl"
    alerts.write_text(json.dumps(_alert()) + "\n")
    sightings_out = tmp_path / "sightings.json"
    pushed = RecordingTransport()
    monkeypatch.setattr(opencti, "UrllibTransport", lambda: pushed)
    code, stdout, stderr = _stix(["sightings", "--alerts", str(alerts), "--out", str(sightings_out),
                                  "--case", "CASE-7", "--push"], capsys)
    assert code == 0, stdout + stderr
    bundle = json.loads(sightings_out.read_text())
    assert export.validate_bundle(bundle)[0] == []
    assert next(x for x in bundle["objects"] if x["type"] == "sighting")["sighting_of_ref"] == IND_IP
    assert json.loads(json.loads(pushed.calls[0][2])["variables"]["bundle"]) == bundle
    assert json.loads(stdout)["push"]["ok"] and "env-token" not in stdout + stderr
    # no alerts given, or alerts without an enrichment: exit 2
    assert _stix(["sightings"], capsys)[0] == 2
    plain = tmp_path / "plain.jsonl"
    plain.write_text(json.dumps({"event": {"id": "x"}}) + "\n")
    assert _stix(["sightings", "--alerts", str(plain)], capsys)[0] == 2


# ---- the indicator-match rule contract -------------------------------------
@pytest.fixture(scope="module")
def cti_contract():
    return rl.load_cti_contract()


def test_indicator_match_rule_validates_against_the_cti_template(cti_contract):
    rule, template = cti_contract
    rl.validate_indicator_match(rule, template)
    assert rule["id"] == "cti-indicator-match" and rule["type"] == "threat_match" and rule["risk_score"] == 73
    assert rule["threat_index"] == ["cti-*"] and rule["threat_indicator_path"] == "threat.indicator"
    assert rule["language"] == rule["threat_language"] == "kuery"
    assert set(rule["index"]) == {"logs-dxdfir.*-*", "logs-car.*-*"}      # every Byakugan evidence stream
    assert rule["evidence"]["stamped_by"] == "engine" and rule["evidence"]["shape"] == "line"
    assert set(rl.ROUND_TRIP_FIELDS) <= set(rule["evidence"]["fields"])  # what the sightings push reads
    assert template == ind.load_template()                              # one template, both sides


def test_indicator_match_targets_are_fields_the_copy_fills(cti_contract):
    rule, template = cti_contract
    mapping = ind.load_pattern_mapping()
    values = {e["value"] for g in rule["threat_mapping"] for e in g["entries"]}
    assert values <= mapping.ecs_fields                 # every match target is one a STIX comparison lands in
    assert {"threat.indicator.ip", "threat.indicator.file.hash.sha256", "threat.indicator.url.domain"} <= values
    fields = {e["field"] for g in rule["threat_mapping"] for e in g["entries"]}
    assert {"source.ip", "destination.ip", "file.hash.sha256", "dns.question.name"} <= fields
    tf = ind.template_fields(template)                  # the threat_query reads mapped fields
    assert tf["stix.revoked"] == "boolean" and tf["stix.valid_until"] == "date"
    assert "stix.revoked" in rule["threat_query"] and "stix.valid_until" in rule["threat_query"]


def test_indicator_match_rule_is_beside_the_registry_pinned_set(cti_contract):
    rule, _template = cti_contract
    assert rule["id"] not in {r["id"] for r in rl.list_rules()}
    assert rl.main([]) == 0             # the loader's CLI validates the contract alongside the rule set


@pytest.mark.parametrize("patch", [
    {"type": "query"},
    {"language": "esql"},
    {"threat_language": "kql"},
    {"query": "FROM logs-dxdfir.*-* | WHERE a == 1"},                    # ES|QL is not a Kibana language
    {"query": "source.ip:* and (x"},
    {"query": "tostring(a) == 1"},                                     # a Kusto left-over
    {"status": "stub"},
    {"todo": {"query": "x", "blockers": ["y"]}},
    {"severity": "info"},
    {"index": ["cti-*"]},
    {"threat_index": []},
    {"threat_index": ["logs-*"]},                                      # not what the template covers
    {"threat_indicator_path": "threat.feed.name"},                     # a leaf, not an object
    {"threat_indicator_path": "threat.enrichments"},                   # not mapped
    {"threat_mapping": []},
    {"threat_mapping": [{"entries": []}]},
    {"threat_mapping": [{"entries": [{"field": "source.ip", "type": "mapping", "value": "source.ip"}]}]},
    {"threat_mapping": [{"entries": [{"field": "source.ip", "type": "mapping", "value": "threat.indicator.nope"}]}]},
    {"threat_mapping": [{"entries": [{"field": "source.ip", "type": "lookup", "value": "threat.indicator.ip"}]}]},
    {"threat_mapping": [{"entries": [{"field": "source.ip", "type": "mapping", "value": "threat.indicator.ip"}]}] * 2},
    {"items_per_search": 0},
    {"evidence": {"shape": "line", "stamped_by": "engine", "fields": ["rule.id"]}},
    {"evidence": {"shape": "line", "stamped_by": "query",
                  "fields": ["threat.enrichments.matched.atomic", "threat.enrichments.indicator.id"]}},
    {"evidence": {"shape": "line", "stamped_by": "engine", "fields": ["kibana.alert.rule.rule_id"]}},
    {"car_join": {"key": "guid", "via": "direct"}},
    {"attack": ["T1"]},
])
def test_validate_indicator_match_rejects_drift(cti_contract, patch):
    rule, template = (copy.deepcopy(c) for c in cti_contract)
    with pytest.raises(ValueError):
        rl.validate_indicator_match({**rule, **patch}, template)


def test_validate_indicator_match_without_template_skips_only_the_cross_checks(cti_contract):
    rule, _template = cti_contract
    loose = {**copy.deepcopy(rule), "threat_index": ["cti-anything-*"],
             "threat_mapping": [{"entries": [{"field": "a.b", "type": "mapping", "value": "threat.indicator.nope"}]}]}
    rl.validate_indicator_match(loose)                       # no template: nothing to cross-check against
    with pytest.raises(ValueError, match="not mapped"):
        rl.validate_indicator_match(loose, ind.load_template())
    with pytest.raises(ValueError, match="threat_index"):
        rl.validate_indicator_match({**copy.deepcopy(rule), "threat_index": ["logs-*"]}, ind.load_template())


def test_existing_rule_set_and_car_contract_still_validate():
    rules = rl.list_rules()
    rl.validate(rules)
    rl.validate_car_detections(*rl.load_car_detections())
    # the engine-prefix relaxation is opt-in: a plain rule's engine-stamped fields stay kibana.alert.* only
    eql = next(r for r in rules if r["language"] == "eql")
    with pytest.raises(ValueError, match="kibana.alert"):
        rl.validate([{**eql, "evidence": {"shape": "line", "stamped_by": "engine",
                                          "fields": ["threat.enrichments.matched.atomic"]}}])
