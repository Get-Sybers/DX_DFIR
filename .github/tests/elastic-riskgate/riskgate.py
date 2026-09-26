#!/usr/bin/env python3
"""Byakugan Phase-0 RISK GATE — the runner behind .github/tests/elastic-riskgate/riskgate.sh.

Proves the two load-bearing assumptions of the Elastic-native design against a
RUNNING docker/elastic stack (Elasticsearch 9.4.3, security on, Basic licence):

  proof 1  a detection runs ON DEMAND over an EVIDENCE-TIME window — dead-box
           evidence whose @timestamps lie years in the past — and nothing old is
           silently dropped, re-stamped or aged out on the way in;
  proof 2  ES|QL LOOKUP JOIN against the car-detections lookup index (the wave-1
           contract, read verbatim from the submodule's byakugan/rules/)
           flags logs-car.* rows in place — the tagged-evidence-line model.

Stands up NOTHING. Loads a small synthetic fixture into a `riskgate` namespace
(the logs-car.<object>-riskgate data streams and the car-detections-riskgate
lookup index; nothing else in the cluster is touched), runs the ES|QL under
queries/ through POST /_query, compares each result table with expected/, and
removes the fixture again. Standard library only.

  riskgate.py selftest        offline: fixtures, queries and expected tables agree
  riskgate.py all             clean, load, proof1, proof2, probe, clean   (default)
  riskgate.py load|proof1|proof2|probe|clean
      --keep                  `all`: leave the fixture in the cluster afterwards
      --drop-template         `clean`: also delete the car-detections index template

Connection (riskgate.sh discovers these from docker/elastic): ES_URL, ES_USER,
ES_PASSWORD, ES_CA (PEM), RISKGATE_INSECURE=1. docs/riskgate.md is the manual.
"""
from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir, os.pardir))
# The wave-1 contract (read-only): the lookup index template the deploy step PUTs.
CONTRACT_TEMPLATE = os.path.join(
    REPO_ROOT, "docker", "GoDFIR-toolz", "byakugan", "rules", "car-detections",
    "car-detections.index-template.json")
FIXTURES = os.path.join(HERE, "fixtures")
QUERIES = os.path.join(HERE, "queries")
EXPECTED = os.path.join(HERE, "expected")
FIXTURE_CAR = os.path.join(FIXTURES, "logs-car.ndjson")
FIXTURE_LOOKUP = os.path.join(FIXTURES, "car-detections.ndjson")

# Everything the harness creates lives in this namespace.
NAMESPACE = "riskgate"
CAR_STREAMS = ("logs-car.process-riskgate", "logs-car.file-riskgate")
CAR_PATTERN = "logs-car.*-riskgate"
LOOKUP_INDEX = "car-detections-riskgate"
TEMPLATE_NAME = "car-detections"
# Every fixture row predates this — the dead-box bar every stored row must clear.
EVIDENCE_CUTOFF = "2020-01-01T00:00:00.000Z"
REQUIRED_MAJOR = 9          # LOOKUP JOIN: 9.x (technical preview in 8.18)
PINNED_VERSION = "9.4.3"    # docker/elastic pins this; other versions are indicative only
# The two fixture guids the probe reads (see fixtures/logs-car.ndjson).
PROCESS_GUID = "{6f2a4c1e-8b3d-5cb0-0000-00105a7e3c01}"
FILE_GUID = "WS01-filestat-000ef2a1"

# (check id, query/expected stem) — the gated tables.
PROOF1_TABLES = (("1.4", "10-manual-detection-window"),
                 ("1.5", "11-manual-detection-outside-window"))
PROOF2_TABLES = (("2.4", "20-lookup-join-flag"),
                 ("2.5", "21-lookup-join-cascade"),
                 ("2.6", "22-lookup-join-collapse"))
PROBE_QUERY = "29-lookup-join-shadowing-probe"


class RiskgateError(Exception):
    """The harness cannot continue (unreachable cluster, malformed fixture)."""


# ------------------------------------------------------------------ reporting
class Report:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    @staticmethod
    def section(title: str) -> None:
        print(f"\n── {title}")

    def ok(self, cid: str, msg: str) -> None:
        self.passed += 1
        print(f"    ✓ {cid} {msg}")

    def bad(self, cid: str, msg: str) -> None:
        self.failed += 1
        print(f"    ✗ {cid} {msg}")

    @staticmethod
    def info(msg: str) -> None:
        print(f"    · {msg}")

    def check(self, cid: str, cond: bool, ok_msg: str, bad_msg: str) -> bool:
        (self.ok if cond else self.bad)(cid, ok_msg if cond else bad_msg)
        return cond

    def summary(self) -> int:
        print("\n═══════════════════════════════════════════")
        print(f"  passed: {self.passed:<4} failed: {self.failed}")
        print("═══════════════════════════════════════════")
        if self.failed:
            print(f"  ❌ RISK GATE FAILED — {self.failed} check(s); see docs/riskgate.md 'if it fails'")
            return 1
        print("  ✅ RISK GATE PASSED")
        return 0


# ------------------------------------------------------------------ the client
def reason(doc) -> str:
    """The human-readable reason in an Elasticsearch error body."""
    if isinstance(doc, dict):
        err = doc.get("error")
        if isinstance(err, dict):
            root = err.get("root_cause") or []
            if root and isinstance(root[0], dict) and root[0].get("reason"):
                return str(root[0]["reason"])
            return str(err.get("reason") or err)
        if err:
            return str(err)
        if "raw" in doc:
            return str(doc["raw"])[:300]
    return str(doc)[:300]


class Es:
    """Just enough of an Elasticsearch client: basic auth, own CA, no proxy."""

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
            raise RiskgateError(
                f"{method} {path}: cannot reach {self.url}: {getattr(e, 'reason', e)} "
                "(is docker/elastic up? ES_URL / ES_CA right?)") from e
        try:
            doc = json.loads(text) if text.strip() else {}
        except ValueError:
            doc = {"raw": text}
        return status, doc


def connect_from_env() -> Es:
    url = os.environ.get("ES_URL", "https://127.0.0.1:9200")
    user = os.environ.get("ES_USER", "elastic")
    password = os.environ.get("ES_PASSWORD", "")
    ca = os.environ.get("ES_CA") or None
    insecure = os.environ.get("RISKGATE_INSECURE", "0") == "1"
    if not password:
        raise RiskgateError("ES_PASSWORD is not set (riskgate.sh reads the elastic.env handoff; or export it)")
    if ca and not os.path.isfile(ca):
        raise RiskgateError(f"ES_CA={ca} is not a file")
    if url.startswith("https://") and not ca and not insecure:
        raise RiskgateError("https without a CA: set ES_CA (riskgate.sh fetches it from the certs "
                            "volume) or RISKGATE_INSECURE=1")
    return Es(url, user, password, ca, insecure)


# ------------------------------------------------------------------ helpers
def read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def read_bulk(path: str) -> list[tuple[dict, dict]]:
    """A bulk NDJSON fixture as (action, document) pairs."""
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    if len(lines) % 2:
        raise RiskgateError(f"{path}: bulk NDJSON needs action/document line pairs")
    pairs = []
    for i in range(0, len(lines), 2):
        try:
            pairs.append((json.loads(lines[i]), json.loads(lines[i + 1])))
        except ValueError as e:
            raise RiskgateError(f"{path}: line {i + 1}/{i + 2}: {e}") from e
    return pairs


def read_query(stem: str) -> str:
    """The ES|QL text with the full-line // comments removed (ES|QL accepts
    them; stripping keeps the request body to the query itself)."""
    with open(os.path.join(QUERIES, stem + ".esql"), encoding="utf-8") as fh:
        keep = [ln for ln in fh.read().splitlines() if not ln.strip().startswith("//")]
    return "\n".join(keep).strip()


def keep_columns(query: str) -> list[str]:
    """The columns of the LAST `KEEP` command of a query (the table it returns)."""
    cols: list[str] = []
    for cmd in query.split("|"):
        words = cmd.strip().split(None, 1)
        if words and words[0].upper() == "KEEP" and len(words) > 1:
            cols = [c.strip() for c in words[1].replace("\n", " ").split(",") if c.strip()]
    return cols


def leaf_paths(doc, prefix: str = "") -> set[str]:
    out: set[str] = set()
    for k, v in doc.items():
        path = prefix + k
        if isinstance(v, dict):
            out |= leaf_paths(v, path + ".")
        else:
            out.add(path)
    return out


def mapped_paths(properties: dict, prefix: str = "") -> set[str]:
    out: set[str] = set()
    for name, spec in (properties or {}).items():
        path = prefix + name
        if isinstance(spec, dict) and "properties" in spec:
            out |= mapped_paths(spec["properties"], path + ".")
        else:
            out.add(path)
    return out


def esql(es: Es, stem: str) -> dict:
    status, doc = es.call("POST", "/_query?format=json", {"query": read_query(stem)})
    if status != 200:
        raise RiskgateError(f"{stem}.esql: HTTP {status}: {reason(doc)}")
    return doc


def rows_as_dicts(result: dict) -> list[dict]:
    cols = [c["name"] for c in result.get("columns", [])]
    return [dict(zip(cols, row)) for row in result.get("values", [])]


def compare_table(result: dict, expected: dict) -> tuple[bool, str]:
    """Order-insensitive comparison of the query result with an expected table."""
    cols = [c["name"] for c in result.get("columns", [])]
    missing = [c for c in expected["columns"] if c not in cols]
    if missing:
        return False, f"result lacks column(s) {missing}; got {cols}"
    extra = [c for c in cols if c not in expected["columns"]]
    if extra:
        # the expected table pins the query's KEEP contract, so extra columns
        # (a query change, or ES returning more) are a failure, not a pass.
        return False, f"result has unexpected column(s) {extra}; the query must KEEP exactly {expected['columns']}"
    idx = [cols.index(c) for c in expected["columns"]]
    got = sorted(json.dumps([row[i] for i in idx]) for row in result.get("values", []))
    want = sorted(json.dumps(row) for row in expected["rows"])
    if got == want:
        return True, f"{len(want)} row(s), exactly as expected"
    unexpected = [g for g in got if g not in want]
    absent = [w for w in want if w not in got]
    detail = f"expected {len(want)} row(s), got {len(got)}"
    if absent:
        detail += "; missing: " + " ".join(absent[:3])
    if unexpected:
        detail += "; unexpected: " + " ".join(unexpected[:3])
    return False, detail


def run_table(es: Es, rep: Report, cid: str, stem: str, what: str) -> None:
    expected = read_json(os.path.join(EXPECTED, stem + ".json"))
    try:
        result = esql(es, stem)
    except RiskgateError as e:
        rep.bad(cid, f"{what}: {e}")
        return
    ok, detail = compare_table(result, expected)
    rep.check(cid, ok, f"{what} — {detail}", f"{what} — {detail} (queries/{stem}.esql vs expected/{stem}.json)")


def count(es: Es, target: str, query=None) -> int:
    status, doc = es.call("POST", f"/{target}/_count", {"query": query} if query else None)
    if status != 200:
        raise RiskgateError(f"_count {target}: HTTP {status}: {reason(doc)}")
    return int(doc.get("count", -1))


def bulk(es: Es, path: str) -> tuple[int, list[str]]:
    """POST a bulk fixture; returns (documents accepted, error reasons)."""
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
    if not body.endswith("\n"):
        body += "\n"
    status, doc = es.call("POST", "/_bulk?refresh=true", body, ctype="application/x-ndjson")
    if status != 200:
        return 0, [f"HTTP {status}: {reason(doc)}"]
    accepted, errors = 0, []
    for item in doc.get("items", []):
        (_, res), = item.items()
        if res.get("error"):
            errors.append(f"{res.get('_index')}: {reason({'error': res['error']})}")
        else:
            accepted += 1
    return accepted, errors


# ------------------------------------------------------------------ commands
def preflight(es: Es, rep: Report) -> None:
    rep.section(f"preflight — {es.url}")
    status, doc = es.call("GET", "/")
    if status != 200:
        rep.bad("0.1", f"GET / returned HTTP {status}: {reason(doc)} (ES_USER / ES_PASSWORD?)")
        return
    version = str(doc.get("version", {}).get("number", "?"))
    major = int(version.split(".")[0]) if version[:1].isdigit() else 0
    rep.check("0.1", major >= REQUIRED_MAJOR,
              f"Elasticsearch {version}, cluster {doc.get('cluster_name', '?')}",
              f"Elasticsearch {version}: LOOKUP JOIN needs {REQUIRED_MAJOR}.x (technical preview in 8.18)")
    if version != PINNED_VERSION:
        rep.info(f"docker/elastic pins {PINNED_VERSION}; a result on {version} is indicative only")
    status, doc = es.call("GET", "/_license")
    lic = doc.get("license", {}) if status == 200 else {}
    rep.info(f"licence: {lic.get('type', '?')} ({lic.get('status', '?')}) — Basic is enough for everything here")
    status, doc = es.call("GET", "/_security/_authenticate")
    if status == 200:
        rep.info(f"authenticated as {doc.get('username')} (roles: {', '.join(doc.get('roles', []))})")


def cmd_clean(es: Es, rep: Report, drop_template: bool = False, quiet: bool = False) -> None:
    if not quiet:
        rep.section("clean — remove the riskgate fixture")
    targets = [("DELETE", f"/_data_stream/{CAR_PATTERN}", "data streams " + CAR_PATTERN),
               ("DELETE", f"/{LOOKUP_INDEX}", "lookup index " + LOOKUP_INDEX)]
    if drop_template:
        targets.append(("DELETE", f"/_index_template/{TEMPLATE_NAME}", "index template " + TEMPLATE_NAME))
    for method, path, what in targets:
        status, doc = es.call(method, path)
        if status not in (200, 404):
            rep.bad("clean", f"{what}: HTTP {status}: {reason(doc)}")
        elif not quiet:
            rep.info(f"{what}: {'removed' if status == 200 else 'absent'}")


def cmd_load(es: Es, rep: Report) -> None:
    rep.section("load — the riskgate fixture (namespace 'riskgate'; nothing else is touched)")
    cmd_clean(es, rep, quiet=True)
    # 2.1 — the contract template, verbatim. index.mode: lookup is what makes an
    # index joinable; a cluster that rejects it cannot run proof 2 at all.
    template = read_json(CONTRACT_TEMPLATE)
    status, doc = es.call("PUT", f"/_index_template/{TEMPLATE_NAME}", template)
    rep.check("2.1", status == 200 and bool(doc.get("acknowledged")),
              f"contract template accepted: PUT _index_template/{TEMPLATE_NAME} "
              f"({os.path.relpath(CONTRACT_TEMPLATE, REPO_ROOT)})",
              f"contract template rejected: HTTP {status}: {reason(doc)}")
    # 1.1 — dead-box CAR rows into the logs-car.* streams (created on first write
    # by Elasticsearch's built-in logs-*-* template, exactly as the loader will).
    n_car = len(read_bulk(FIXTURE_CAR))
    accepted, errors = bulk(es, FIXTURE_CAR)
    rep.check("1.1", accepted == n_car and not errors,
              f"{accepted} CAR rows with 2019 @timestamps accepted into {', '.join(CAR_STREAMS)}",
              f"CAR fixture: {accepted}/{n_car} accepted; {'; '.join(errors[:3]) or 'count mismatch'}")
    # 2.2 — the lookup rows; the index is created from the template on first write.
    n_lookup = len(read_bulk(FIXTURE_LOOKUP))
    accepted, errors = bulk(es, FIXTURE_LOOKUP)
    status, doc = es.call("GET", f"/{LOOKUP_INDEX}/_settings")
    settings = doc.get(LOOKUP_INDEX, {}).get("settings", {}).get("index", {}) if status == 200 else {}
    rep.check("2.2", accepted == n_lookup and not errors
              and settings.get("mode") == "lookup" and settings.get("number_of_shards") == "1",
              f"{accepted} detection rows in {LOOKUP_INDEX} (index.mode=lookup, 1 shard)",
              f"lookup fixture: {accepted}/{n_lookup} accepted; {'; '.join(errors[:3]) or ''} "
              f"index.mode={settings.get('mode')!r} shards={settings.get('number_of_shards')!r}")


def cmd_proof1(es: Es, rep: Report) -> None:
    rep.section("proof 1 — a manual detection run over an EVIDENCE-TIME window")
    n_car = len(read_bulk(FIXTURE_CAR))
    # 1.2 — every stored row still carries its evidence time: nothing dropped,
    # nothing re-stamped to ingest time (the built-in logs@default-pipeline only
    # sets @timestamp when it is missing).
    total = count(es, CAR_PATTERN)
    old = count(es, CAR_PATTERN, {"range": {"@timestamp": {"lt": EVIDENCE_CUTOFF}}})
    rep.check("1.2", total == n_car and old == n_car,
              f"all {n_car} rows stored with their evidence time (@timestamp < {EVIDENCE_CUTOFF[:10]})",
              f"{total} rows stored, {old} with an evidence-time @timestamp — expected {n_car} and {n_car}")
    # 1.3 — nothing that could age evidence out later: no data-stream-lifecycle
    # retention, no ILM delete phase. Retention counts from rollover, not from
    # @timestamp, but a case store must never carry one at all.
    problems = []
    for ds in CAR_STREAMS:
        status, doc = es.call("GET", f"/_data_stream/{ds}")
        if status != 200:
            problems.append(f"{ds}: GET _data_stream HTTP {status}: {reason(doc)}")
            continue
        info = (doc.get("data_streams") or [{}])[0]
        retention = (info.get("lifecycle") or {}).get("data_retention")
        if retention:
            problems.append(f"{ds}: data stream lifecycle retention {retention}")
        status, ldoc = es.call("GET", f"/_data_stream/{ds}/_lifecycle")
        if status == 200:
            effective = ((ldoc.get("data_streams") or [{}])[0].get("lifecycle") or {}).get("effective_retention")
            if effective:
                problems.append(f"{ds}: effective retention {effective}")
        policy = info.get("ilm_policy")
        if policy:
            status, pdoc = es.call("GET", f"/_ilm/policy/{policy}")
            phases = pdoc.get(policy, {}).get("policy", {}).get("phases", {}) if status == 200 else {}
            if "delete" in phases:
                problems.append(f"{ds}: ILM policy {policy} has a delete phase")
    rep.check("1.3", not problems,
              "no retention on the riskgate streams (no lifecycle retention, no ILM delete phase)",
              "; ".join(problems))
    for cid, stem in PROOF1_TABLES:
        what = {"1.4": "rule run over the 2019-04-12 evidence window flags exactly the wevtutil row",
                "1.5": "the same rule over the last 24 h flags nothing (window honoured)"}[cid]
        run_table(es, rep, cid, stem, what)


def cmd_proof2(es: Es, rep: Report) -> None:
    rep.section("proof 2 — LOOKUP JOIN car-detections against logs-car.* on Elasticsearch 9.x")
    # 2.3 — LOOKUP JOIN needs the key under the same name AND type on both
    # sides. The CAR side is mapped by the built-in ecs@mappings (strings ->
    # keyword); the lookup side by the contract template.
    status, doc = es.call("GET", f"/{CAR_PATTERN},{LOOKUP_INDEX}/_mapping/field/event.id,process.entity_id")
    types: dict[str, dict[str, str]] = {}
    if status == 200:
        for index, spec in doc.items():
            for field, fspec in (spec.get("mappings") or {}).items():
                # An unmapped field yields an empty mapping (and a conflict yields
                # several); either way record "?" so check 2.3 fails cleanly rather
                # than the harness aborting on a bad unpack.
                vals = list((fspec.get("mapping") or {}).values())
                leaf = vals[0] if len(vals) == 1 else {}
                types.setdefault(index, {})[field] = leaf.get("type", "?")
    wrong = [f"{i}: {f}={t}" for i, fs in types.items() for f, t in fs.items() if t != "keyword"]
    lacking = [i for i, fs in types.items() if {"event.id", "process.entity_id"} - set(fs)]
    rep.check("2.3", status == 200 and len(types) == len(CAR_STREAMS) + 1 and not wrong and not lacking,
              f"event.id / process.entity_id are keyword on all {len(types)} sides (join-key type parity)",
              f"join-key mapping: HTTP {status}; not keyword: {wrong or '-'}; missing a key: {lacking or '-'}; "
              f"indices seen: {sorted(types)}")
    for cid, stem in PROOF2_TABLES:
        what = {"2.4": "direct join ON event.id flags exactly the detected rows, stamped, evidence time and owner link intact",
                "2.5": "cascade join ON process.entity_id reaches the process row and the file it owns",
                "2.6": "fan-out collapses to one row per guid with STATS ... BY event.id"}[cid]
        run_table(es, rep, cid, stem, what)


def cmd_probe(es: Es, rep: Report) -> None:
    rep.section("probe — LOOKUP JOIN field shadowing on this cluster (informational, not gated)")
    try:
        rows = rows_as_dicts(esql(es, PROBE_QUERY))
    except RiskgateError as e:
        rep.info(f"probe query failed: {e}")
        return
    if not rows:
        rep.info("probe returned no rows (proof 2 will have said why)")
        return
    shadowed = [r for r in rows if not str(r.get("@timestamp", "")).startswith("2019")]
    if shadowed:
        rep.info(f"@timestamp: SHADOWED on {len(shadowed)}/{len(rows)} flagged lines — the naive join "
                 "shape reports the lookup row's detection time, not the evidence time")
        rep.info("  -> every joining query must stash/restore @timestamp (queries/20), or the writer "
                 "must stop setting @timestamp on lookup rows (detection.detected_at carries it)")
    else:
        rep.info(f"@timestamp: kept on all {len(rows)} flagged lines under the naive join shape")
    file_rows = [r for r in rows if r.get("event.id") == FILE_GUID]
    if file_rows:
        owner = file_rows[0].get("process.entity_id")
        if owner == PROCESS_GUID:
            rep.info("process.entity_id: a lookup row WITHOUT the field leaves the source value (owner link kept)")
        else:
            rep.info(f"process.entity_id: a lookup row WITHOUT the field replaces the source value with "
                     f"{owner!r} (owner link lost) -> stash/restore it around every join ON event.id (queries/20)")
    else:
        rep.info("process.entity_id: the Security.evtx line was not flagged, nothing to report")


def cmd_selftest(rep: Report) -> None:
    """Offline: the harness agrees with itself and with the read-only contract."""
    rep.section("selftest — fixtures, queries and expected tables agree (no cluster needed)")
    template = read_json(CONTRACT_TEMPLATE)
    patterns = template.get("index_patterns") or []
    settings = (template.get("template") or {}).get("settings") or {}
    rep.check("S.1", any(fnmatch.fnmatchcase(LOOKUP_INDEX, p) for p in patterns)
              and settings.get("index.mode") == "lookup",
              f"contract template covers {LOOKUP_INDEX} and sets index.mode: lookup",
              f"contract template: patterns {patterns}, index.mode={settings.get('index.mode')!r}")
    mapped = mapped_paths(((template.get("template") or {}).get("mappings") or {}).get("properties"))

    car = read_bulk(FIXTURE_CAR)
    guids: set[str] = set()
    problems: list[str] = []
    for i, (action, doc) in enumerate(car, 1):
        (op, meta), = action.items()
        stream = meta.get("_index", "")
        if op != "create" or stream not in CAR_STREAMS:
            problems.append(f"row {i}: {op} into {stream!r} (data streams take `create` into {CAR_STREAMS})")
        if "_id" in meta:
            problems.append(f"row {i}: sets _id (leave it to the cluster; logsdb streams own it)")
        ts = str(doc.get("@timestamp", ""))
        if not ts or ts >= EVIDENCE_CUTOFF:
            problems.append(f"row {i}: @timestamp {ts!r} is not dead-box evidence (< {EVIDENCE_CUTOFF})")
        ds = doc.get("data_stream") or {}
        if f"{ds.get('type')}-{ds.get('dataset')}-{ds.get('namespace')}" != stream:
            problems.append(f"row {i}: data_stream.* does not name {stream}")
        guid = (doc.get("event") or {}).get("id")
        if not guid:
            problems.append(f"row {i}: no event.id (the CAR guid)")
        guids.add(guid)
        if (doc.get("car") or {}).get("object") != stream.split(".")[1].split("-")[0]:
            problems.append(f"row {i}: car.object does not match the stream")
    rep.check("S.2", not problems, f"{len(car)} CAR rows: create into the riskgate streams, all dated < "
              f"{EVIDENCE_CUTOFF[:10]}, guid + data_stream.* consistent", "; ".join(problems))

    lookup = read_bulk(FIXTURE_LOOKUP)
    problems = []
    for i, (action, doc) in enumerate(lookup, 1):
        (op, meta), = action.items()
        if op != "index" or meta.get("_index") != LOOKUP_INDEX:
            problems.append(f"row {i}: {op} into {meta.get('_index')!r}")
        unmapped = leaf_paths(doc) - mapped
        if unmapped:
            problems.append(f"row {i}: fields the strict template does not map: {sorted(unmapped)}")
        did = (doc.get("detection") or {}).get("id")
        guid = (doc.get("event") or {}).get("id")
        if meta.get("_id") != f"{did}:{guid}":
            problems.append(f"row {i}: _id must be <detection.id>:<event.id>, is {meta.get('_id')!r}")
        if guid not in guids:
            problems.append(f"row {i}: event.id {guid!r} is not a CAR row of the fixture")
        pe = (doc.get("process") or {}).get("entity_id")
        if pe is not None and pe != guid:
            problems.append(f"row {i}: process.entity_id must equal the detected process guid or be absent")
    rep.check("S.3", not problems, f"{len(lookup)} lookup rows: strict-mapped fields only, "
              "_id = <detection.id>:<event.id>, every guid is a fixture row", "; ".join(problems))

    for cid, stem in PROOF1_TABLES + PROOF2_TABLES:
        problems = []
        query = read_query(stem)
        expected = read_json(os.path.join(EXPECTED, stem + ".json"))
        cols = keep_columns(query)
        if cols != expected["columns"]:
            problems.append(f"KEEP {cols} != expected columns {expected['columns']}")
        bad_rows = [r for r in expected["rows"] if len(r) != len(expected["columns"])]
        if bad_rows:
            problems.append(f"{len(bad_rows)} expected row(s) have the wrong width")
        head = query.split("|", 1)[0].strip()
        if not head.upper().startswith("FROM ") or f"-{NAMESPACE}" not in head:
            problems.append(f"FROM must read only the {NAMESPACE} namespace: {head!r}")
        if "LOOKUP JOIN" in query.upper() and f"LOOKUP JOIN {LOOKUP_INDEX} ON " not in query:
            problems.append(f"LOOKUP JOIN must target {LOOKUP_INDEX}")
        rep.check(f"S.4 ({cid})", not problems,
                  f"queries/{stem}.esql and expected/{stem}.json agree ({len(expected['rows'])} row(s))",
                  "; ".join(problems))
    probe = read_query(PROBE_QUERY)
    rep.check("S.5", f"LOOKUP JOIN {LOOKUP_INDEX} ON event.id" in probe and f"-{NAMESPACE}" in probe,
              f"probe query joins {LOOKUP_INDEX} inside the {NAMESPACE} namespace",
              "probe query strays outside the riskgate namespace")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="riskgate.py",
        description="Byakugan Phase-0 risk gate: proves manual evidence-time detection runs and "
                    "LOOKUP JOIN flagging against a running docker/elastic stack (docs/riskgate.md).")
    ap.add_argument("command", nargs="?", default="all",
                    choices=["all", "selftest", "load", "proof1", "proof2", "probe", "clean"])
    ap.add_argument("--keep", action="store_true", help="`all`: leave the fixture in the cluster")
    ap.add_argument("--drop-template", action="store_true",
                    help="`clean`: also delete the car-detections index template")
    args = ap.parse_args(argv)
    rep = Report()
    try:
        if args.command == "selftest":
            cmd_selftest(rep)
            return rep.summary()
        es = connect_from_env()
        preflight(es, rep)
        if rep.failed:
            return rep.summary()
        if args.command == "clean":
            cmd_clean(es, rep, drop_template=args.drop_template)
        elif args.command == "load":
            cmd_load(es, rep)
        elif args.command == "proof1":
            cmd_proof1(es, rep)
        elif args.command == "proof2":
            cmd_proof2(es, rep)
        elif args.command == "probe":
            cmd_probe(es, rep)
        else:
            cmd_load(es, rep)
            cmd_proof1(es, rep)
            cmd_proof2(es, rep)
            cmd_probe(es, rep)
            if args.keep:
                rep.info(f"--keep: fixture left in place (streams {CAR_PATTERN}, index {LOOKUP_INDEX}); "
                         "`riskgate.sh clean` removes it")
            else:
                cmd_clean(es, rep)
    except RiskgateError as e:
        print(f"\n❌ riskgate | {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        # Any other failure (missing fixture/template, JSON parse, transport) is
        # still "the harness could not run" -> documented exit 2, not a traceback.
        # Set RISKGATE_DEBUG=1 to re-raise for debugging.
        if os.environ.get("RISKGATE_DEBUG"):
            raise
        print(f"\n❌ riskgate | unexpected error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    return rep.summary()


if __name__ == "__main__":
    sys.exit(main())
