#!/bin/bash
# ==============================================================================
# DX_DFIR repository checks — everything verifiable without Docker or
# evidence (docs/reference/build-and-test.md "Checks"). -v shows passing
# checks too; non-zero on any failure.
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT="$(realpath "$SCRIPT_DIR/../..")"
cd "$REPO_ROOT" || exit 1

VERBOSE=0
[[ "${1:-}" == "-v" || "${1:-}" == "--verbose" ]] && VERBOSE=1

PASS=0; FAIL=0; SKIP=0
pass() { PASS=$((PASS+1)); [[ $VERBOSE -eq 1 ]] && echo "    ✓ $1"; return 0; }
fail() { FAIL=$((FAIL+1)); echo "    ✗ $1"; return 0; }
skip() { SKIP=$((SKIP+1)); echo "    – skipped: $1"; return 0; }
group() { echo ""; echo "── $1"; }

# ------------------------------------------------------------------------------
group "Shell syntax"
# ------------------------------------------------------------------------------
while IFS= read -r f; do
    if bash -n "$f" 2>/dev/null; then pass "$f"; else fail "$f does not parse"; fi
done < <(find scripts .github/tests -name "*.sh" -type f 2>/dev/null | sort)

# ------------------------------------------------------------------------------
group "Shellcheck"
# ------------------------------------------------------------------------------
if command -v shellcheck >/dev/null 2>&1; then
    while IFS= read -r f; do
        # -S error: only hard errors gate. Style warnings are noise for now.
        if shellcheck -S error "$f" >/dev/null 2>&1; then pass "$f"; else fail "shellcheck errors in $f"; fi
    done < <(find scripts .github/tests -name "*.sh" -type f 2>/dev/null | sort)
else
    skip "shellcheck not installed"
fi

# ------------------------------------------------------------------------------
group "Collection requirements"
# ------------------------------------------------------------------------------
# the requirements gate: parses, exact pins only, every galaxy.yml dep covered, setup installs it
REQS="ansible/collections/get_sybers.dxdfir/requirements.yml"
GALAXY="ansible/collections/get_sybers.dxdfir/galaxy.yml"
if command -v python3 >/dev/null 2>&1 && [[ -f "$REQS" ]]; then
    _req_out=$(python3 - "$REQS" "$GALAXY" <<'PY'
import re, sys
try:
    import yaml
except ImportError:
    print("SKIP: python3-yaml not available"); sys.exit(0)
reqs = yaml.safe_load(open(sys.argv[1]))
problems = []
pinned = {}
for entry in (reqs or {}).get("collections", []):
    name, ver = entry.get("name"), str(entry.get("version", ""))
    is_git = entry.get("type") == "git" or str(name).startswith(("http", "git+"))
    if is_git:
        # a git-URL collection (imported by URL): the version must be a reproducible
        # ref — a vX.Y.Z tag or a full 40-hex sha, never a bare branch
        if not (re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+", ver) or re.fullmatch(r"[0-9a-f]{40}", ver)):
            problems.append(f"{name}: git version '{ver}' is not a tag (vX.Y.Z) or full-sha pin")
        # the FQCN it supplies is the #/ansible_collections/<ns>/<name> fragment
        m = re.search(r"#.*/ansible_collections/([^/]+)/([^/,]+)", str(name))
        if m:
            pinned[f"{m.group(1)}.{m.group(2)}"] = ver
    else:
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", ver):
            problems.append(f"{name}: version '{ver}' is not an exact X.Y.Z pin")
        pinned[name] = ver
# a dep may instead be SUPPLIED BY A SUBMODULE: a declared submodule whose galaxy.yml carries the FQCN covers it
import os
gitlinked = {}
if os.path.isfile(".gitmodules"):
    for line in open(".gitmodules"):
        if line.strip().startswith("path = "):
            path = line.split("=", 1)[1].strip()
            gpath = os.path.join(path, "galaxy.yml")
            if os.path.isfile(gpath):
                gy = yaml.safe_load(open(gpath)) or {}
                gitlinked[f"{gy.get('namespace')}.{gy.get('name')}"] = path
galaxy = yaml.safe_load(open(sys.argv[2]))
for dep in (galaxy.get("dependencies") or {}):
    if dep in pinned or dep in gitlinked:
        continue
    problems.append(
        f"galaxy.yml dependency '{dep}' has no pinned entry in requirements.yml "
        "and no submodule supplies it (submodule not initialised?)")
print("\n".join(problems))
PY
)
    if [[ "$_req_out" == SKIP:* ]]; then
        skip "${_req_out#SKIP: }"
    elif [[ -n "$_req_out" ]]; then
        while IFS= read -r _line; do fail "requirements: $_line"; done <<< "$_req_out"
    else
        pass "requirements.yml pins are exact and cover every galaxy.yml dependency"
    fi
    if grep -q "requirements.yml" scripts/setup-environment.sh; then
        pass "setup-environment.sh installs requirements.yml"
    else
        fail "setup-environment.sh does not install requirements.yml"
    fi
    # -i: the repo is canonically GoDFIR-toolz (capital), used throughout the
    # tree; the URL in requirements.yml keeps that case, so match insensitively.
    if grep -Eqi 'godfir-toolz\.git#.*/godfir_run' "$REQS"; then
        pass "requirements.yml imports get_sybers.godfir_run by URL (no submodule)"
    else
        fail "requirements.yml does not import get_sybers.godfir_run by its git URL"
    fi
    if grep -Eq '^roles_path *=.*docker/GoDFIR-toolz' ansible.cfg; then
        fail "ansible.cfg roles_path still carries the docker/GoDFIR-toolz submodule — it is retired"
    else
        pass "ansible.cfg roles_path carries no submodule (godfir_run resolves via collections_path)"
    fi
else
    fail "missing $REQS"
fi

# ------------------------------------------------------------------------------
group "Ansible lint"
# ------------------------------------------------------------------------------
# production-profile ansible-lint; skipped when not installed (CI installs it)
if command -v ansible-lint >/dev/null 2>&1; then
    # Capture (don't discard) the output so a failure is diagnosable in the log
    # instead of an opaque "reported violations" with no detail.
    if _al_out="$(ansible-lint --profile production 2>&1)"; then
        pass "ansible-lint (production profile) on the collection + container ansible"
    else
        fail "ansible-lint reported violations (run: ansible-lint --profile production)"
        printf '%s\n' "$_al_out" | sed 's/^/      /'
    fi
else
    skip "ansible-lint not installed"
fi

# ------------------------------------------------------------------------------
group "Elastic config tree (pipelines, templates, Kibana saved objects)"
# ------------------------------------------------------------------------------
# the tree is JSON data deploy PUTs/imports verbatim: parse every file, check
# the references between the saved objects, and keep the Malcolm-era field
# names out of the dashboards derived from it
ELASTIC_TREE="elastic"
if command -v python3 >/dev/null 2>&1 && [[ -d "$ELASTIC_TREE/dashboards" ]]; then
    # stderr is captured too and the exit status checked: a crash of the
    # checker itself (a traceback, empty stdout) must fail, not pass
    _tree_out=$(python3 - "$ELASTIC_TREE" 2>&1 <<'PY'
import glob, json, os, re, sys
tree = sys.argv[1]
problems = []
def err(msg): problems.append(msg)
def ndjson(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]

# ---- pipelines and templates parse; the router names pipelines the tree ships
pipelines = {}
for fn in sorted(glob.glob(os.path.join(tree, "pipelines", "*.json"))):
    with open(fn, encoding="utf-8") as fh:
        pipelines[os.path.basename(fn)[:-5]] = json.load(fh)
for name, body in pipelines.items():
    for pr in body.get("processors", []):
        target = pr.get("pipeline", {}).get("name")
        if target and target not in pipelines: err(f"pipelines/{name}.json hands to {target}, which the tree does not ship")
templates = {}
for kind in ("component", "index"):
    for fn in sorted(glob.glob(os.path.join(tree, "templates", kind, "*.json"))):
        with open(fn, encoding="utf-8") as fh:
            templates[(kind, os.path.basename(fn)[:-5])] = json.load(fh)
for (kind, name), body in templates.items():
    if kind == "component":
        dp = body.get("template", {}).get("settings", {}).get("index", {}).get("default_pipeline")
        if dp and dp not in pipelines: err(f"templates/component/{name}.json binds {dp}, which the tree does not ship")
    else:
        for comp in body.get("composed_of", []):
            if comp.startswith("logs-dxdfir") and ("component", comp) not in templates: err(f"templates/index/{name}.json composes {comp}, which the tree does not ship")

# ---- what the pipelines produce and what they take away: a field a processor
# sets (set/rename/convert/json/lowercase targets, grok captures, ctx.x.y =
# assignments in scripts) is a field a dashboard may read even when its name is
# one Malcolm's enrichment would have produced; the source of a conditional
# rename (zeek's string `id`, `source`, `host`; yara's `rule`) is NOT a column a
# dashboard may read — the record that carries it has it renamed on the way in
PRODUCED, RENAMED_AWAY = set(), set()
for name, body in pipelines.items():
    for pr in body.get("processors", []) + body.get("on_failure", []):
        for kind, cfg in pr.items():
            if not isinstance(cfg, dict): continue
            if kind == "rename":
                PRODUCED.add(cfg.get("target_field", "")); RENAMED_AWAY.add(cfg.get("field", ""))
            elif kind in ("set", "convert", "json", "lowercase", "uppercase", "date"):
                PRODUCED.add(cfg.get("target_field") or cfg.get("field", ""))
            elif kind == "grok":
                PRODUCED.update(re.findall(r"\(\?<([\w.@]+)>", " ".join(cfg.get("patterns", []))))
                PRODUCED.update(re.findall(r"%\{\w+:([\w.@]+)", " ".join(cfg.get("patterns", []))))
            elif kind == "script":
                PRODUCED.update(re.findall(r"ctx\.([A-Za-z_][\w.]*)\s*=[^=]", cfg.get("source", "")))
PRODUCED.discard(""); RENAMED_AWAY.discard("")

# ---- saved objects: the default space's files, then every space directory
LENS = {"lnsDatatable", "lnsPie", "lnsMetric", "lnsXY", "lnsTagcloud"}
MALCOLM = ("network.protocol", "rule.", "event.action", "event.result", "event.severity", "event.provider",
           "related.", "url.", "user_agent.", "file.")
def check_objects(label, files):
    views = {}
    objs_by_file = {}
    for fn in files:
        objs_by_file[fn] = ndjson(fn)
        for o in objs_by_file[fn]:
            if o["type"] == "index-pattern": views[o["id"]] = o
    seen = {}
    dashboard_ids = {o["id"] for objs in objs_by_file.values() for o in objs if o["type"] == "dashboard"}
    for fn, objs in objs_by_file.items():
        rel = f"{label}/{os.path.basename(fn)}"
        for o in objs:
            if o["type"] not in ("index-pattern", "search", "dashboard", "visualization", "lens"): err(f"{rel}: object type {o['type']}")
            # the deploy concatenates a space's files into ONE import, and
            # Kibana rejects a repeated id in an import even when the copies
            # are identical ("Non-unique import objects detected")
            if o["id"] in seen: err(f"{rel}: id {o['id']} is also in {seen[o['id']][0]}")
            seen[o["id"]] = (os.path.basename(fn), o)
        for s in (o for o in objs if o["type"] == "search"):
            refs = {r["name"]: r for r in s.get("references", [])}
            if refs.get("kibanaSavedObjectMeta.searchSourceJSON.index", {}).get("id") not in views: err(f"{rel}: search {s['id']} references a data view the space does not define")
            for col in s["attributes"].get("columns", []):
                if col in RENAMED_AWAY: err(f"{rel}: search {s['id']} column {col}: a pipeline renames that field away (to {', '.join(sorted(t for n, b in pipelines.items() for p in b.get('processors', []) for k, c in p.items() if k == 'rename' and c.get('field') == col for t in [c.get('target_field')]))})")
        for dash in (o for o in objs if o["type"] == "dashboard"):
            refs = {r["name"]: r for r in dash.get("references", [])}
            searches = {o["id"] for objs2 in objs_by_file.values() for o in objs2 if o["type"] == "search"}
            panels = json.loads(dash["attributes"]["panelsJSON"])
            if len({p["panelIndex"] for p in panels}) != len(panels): err(f"{rel}: duplicate panelIndex")
            used = set()
            for p in panels:
                if p["type"] == "search":
                    ref = refs.get(p["panelRefName"], {})
                    if ref.get("type") != "search" or ref.get("id") not in searches: err(f"{rel}: search panel {p.get('panelRefName')}")
                    used.add(p["panelRefName"])
                elif p["type"] == "lens":
                    a = p["embeddableConfig"]["attributes"]
                    if a["visualizationType"] not in LENS: err(f"{rel}: {p.get('title')}: {a['visualizationType']}")
                    if a["state"]["query"]["language"] != "kuery": err(f"{rel}: {p.get('title')}: query language")
                    for layer_id, layer in a["state"]["datasourceStates"]["formBased"]["layers"].items():
                        if set(layer["columnOrder"]) != set(layer["columns"]): err(f"{rel}: {p.get('title')}: columnOrder")
                        for col in layer["columns"].values():
                            f = col["sourceField"]
                            if f.startswith(MALCOLM) and f not in PRODUCED: err(f"{rel}: {p.get('title')}: Malcolm field {f} (no pipeline in the tree sets it)")
                            if f in RENAMED_AWAY: err(f"{rel}: {p.get('title')}: field {f}: a pipeline renames that field away")
                        name = f"indexpattern-datasource-layer-{layer_id}"
                        if not a["references"] or a["references"][0]["name"] != name or a["references"][0]["id"] not in views: err(f"{rel}: {p.get('title')}: layer reference")
                        dash_ref = f"{p['panelIndex']}:{name}"
                        if refs.get(dash_ref, {}).get("id") != a["references"][0]["id"]: err(f"{rel}: {p.get('title')}: dashboard reference")
                        used.add(dash_ref)
                elif p["type"] == "visualization":
                    vis = p.get("embeddableConfig", {}).get("savedVis")
                    if vis and vis["type"] == "markdown":
                        for target in re.findall(r"\(#/view/([0-9a-f-]+)\)", vis["params"]["markdown"]):
                            if target not in dashboard_ids: err(f"{rel}: navigation link to {target}")
                    elif not vis:
                        ref = refs.get(p.get("panelRefName"), {})
                        if ref.get("id") not in seen: err(f"{rel}: visualization panel {p.get('panelRefName')}")
                        used.add(p.get("panelRefName"))
                else:
                    err(f"{rel}: panel type {p['type']}")
            if used - set(refs): err(f"{rel}: panel references missing from the dashboard: {sorted(used - set(refs))}")
        text = open(fn, encoding="utf-8").read()
        for bad in ("MALCOLM_", "arkime"):
            if bad in text: err(f"{rel}: contains {bad!r}")
    if not views: err(f"{label}: no data view")

check_objects("dashboards", sorted(glob.glob(os.path.join(tree, "dashboards", "*.ndjson"))))
for space_file in sorted(glob.glob(os.path.join(tree, "dashboards", "*", "space.json"))):
    d = os.path.dirname(space_file)
    with open(space_file, encoding="utf-8") as fh:
        space = json.load(fh)
    if space.get("id") != os.path.basename(d): err(f"{d}/space.json: id {space.get('id')!r} is not the directory name")
    for key in ("id", "name", "initials", "color", "disabledFeatures"):
        if key not in space: err(f"{d}/space.json: missing {key}")
    files = sorted(glob.glob(os.path.join(d, "*.ndjson")))
    if not files: err(f"{d}: no saved objects")
    check_objects("dashboards/" + os.path.basename(d), files)
print("\n".join(problems))
PY
)
    _tree_rc=$?
    if [[ $_tree_rc -ne 0 ]]; then
        fail "elastic tree: the checker itself failed (exit $_tree_rc)"
        printf '%s\n' "$_tree_out" | tail -3 | sed 's/^/      /'
    elif [[ -n "$_tree_out" ]]; then
        while IFS= read -r _line; do fail "elastic tree: $_line"; done <<< "$_tree_out"
    else
        pass "elastic/ pipelines, templates and saved objects parse and reference each other"
    fi
else
    skip "python3 not available or no elastic/dashboards"
fi

# ------------------------------------------------------------------------------
group "Repo-root path resolution"
# ------------------------------------------------------------------------------
# every script computing REPO_ROOT_DIR must land on the real root, whatever depth it lives at
while IFS= read -r f; do
    line=$(grep -m1 'REPO_ROOT_DIR=' "$f" 2>/dev/null | sed 's/^[[:space:]]*//')
    [[ -z "$line" ]] && continue
    sd="$(dirname "$(readlink -f "$f")")"
    resolved=$(eval "SCRIPT_DIR='$sd'; $line; echo \$REPO_ROOT_DIR" 2>/dev/null)
    if [[ "$resolved" == "$REPO_ROOT" ]]; then pass "$f"
    else fail "$f resolves repo root to '$resolved' (expected '$REPO_ROOT')"; fi
done < <(find scripts -name "*.sh" -type f | sort)

# ------------------------------------------------------------------------------
group "Go front-end (gofmt / vet / build / test)"
# ------------------------------------------------------------------------------
# gofmt clean, go vet, build, tests; skipped when Go is not installed (CI installs it)
if command -v go >/dev/null 2>&1; then
    _gofmt_out="$(gofmt -l go 2>/dev/null)"
    if [[ -z "$_gofmt_out" ]]; then
        pass "gofmt: go/ is formatted"
    else
        fail "gofmt: files need formatting (run: gofmt -w go)"
        printf '%s\n' "$_gofmt_out" | sed 's/^/      /'
    fi
    if _govet_out="$( (cd go && go vet ./...) 2>&1 )"; then
        pass "go vet ./..."
    else
        fail "go vet reported issues (run: cd go && go vet ./...)"
        printf '%s\n' "$_govet_out" | sed 's/^/      /'
    fi
    if _gobuild_out="$( (cd go && go build ./...) 2>&1 )"; then
        pass "go build ./..."
    else
        fail "go build failed (run: cd go && go build ./...)"
        printf '%s\n' "$_gobuild_out" | sed 's/^/      /'
    fi
    if _gotest_out="$( (cd go && go test ./...) 2>&1 )"; then
        pass "go test ./..."
    else
        fail "go test failed (run: cd go && go test ./...)"
        printf '%s\n' "$_gotest_out" | sed 's/^/      /'
    fi
else
    skip "go toolchain not installed"
fi

# ------------------------------------------------------------------------------
group "Versioning and documentation"
# ------------------------------------------------------------------------------
PROJECT_VERSION=$(grep -m1 -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+[^]]*\]' CHANGELOG.md 2>/dev/null | tr -d '#[] ')
if [[ -n "$PROJECT_VERSION" ]]; then
    pass "project version from CHANGELOG: $PROJECT_VERSION"
    # The README must NOT declare the current version in prose — it carries a
    # badge that reads the latest Release, so a promotion is a tag and nothing
    # else. Hardcoding it is what made alpha -> beta a twelve-file edit.
    if grep -qE 'img\.shields\.io/gitlab/v/release|/-/badges/release\.svg' README.md 2>/dev/null; then
        pass "README version comes from a live release badge"
    else
        fail "README has no release badge — the version would have to be hand-maintained"
    fi
    if grep -qE '^> \*\*(Status|Release status):' README.md 2>/dev/null; then
        fail "a hardcoded status/version line is back — let the badge state it"
    else
        pass "no hardcoded status line in README"
    fi
else
    fail "could not read a version heading from CHANGELOG.md"
fi
# No document may restate the number of checks. It was hand-copied into six
# files, every harness change meant editing all six, and one still said 86 long
# after the real count passed 160. The harness prints the number; documents
# point at the harness.
_counts=$(grep -rnE '[0-9]{2,4} (static )?checks' --include='*.md' . 2>/dev/null \
          | grep -vE '^\./(\.git|\.go|\.cache|\.venv|build|data_store|docker/GoDFIR-toolz)/' \
          | grep -v '/\.ansible/' || true)
if [[ -z "$_counts" ]]; then
    pass "no document hardcodes the check count"
else
    fail "documents restate the check count (it goes stale): $(printf '%s' "$_counts" | head -3 | tr '\n' ' ')"
fi

# The project is past alpha; a stray "Alpha" label contradicts the release.
if grep -rIl -E '(Status:.*Alpha|🧪 Alpha)' --include='*.md' . 2>/dev/null | grep -qv '^./.git/'; then
    fail "a document still labels this project Alpha"
else
    pass "no stale Alpha status labels"
fi

# ------------------------------------------------------------------------------
group "Evidence safety"
# ------------------------------------------------------------------------------
# data_store/.gitignore must deny by default. An extension blocklist silently
# missed VMware exports once already.
probe_dir="data_store/raw/VM_files/.checkprobe"
mkdir -p "$probe_dir" 2>/dev/null
leaked=0
for name in probe.vmdk probe-flat.vmdk probe.E01 probe.pcap probe.vmx probe.ova probe.unknownext noextension; do
    : > "$probe_dir/$name" 2>/dev/null || continue
    git check-ignore -q "$probe_dir/$name" 2>/dev/null || { fail "$name is NOT gitignored under data_store"; leaked=1; }
done
[[ $leaked -eq 0 ]] && pass "all evidence probes gitignored (incl. extensionless)"
rm -rf "$probe_dir" 2>/dev/null

# The skeleton must survive the deny-by-default rules.
for keep in data_store/README.md data_store/raw/disk_images/.gitkeep; do
    [[ -f "$keep" ]] || continue
    if git check-ignore -q "$keep" 2>/dev/null; then fail "$keep is wrongly ignored"; else pass "$keep kept"; fi
done

# No un-negated `**` allowlist may point at a directory that does not exist.
# The deny-by-default rewrite carried over `!dependencies/SuperMem/**` from the
# old blocklist without checking: SuperMem was deleted in 2025-09, so that was
# an open-ended hole aimed at a memory-forensics tool's directory. A stale
# allowlist is invisible until someone puts evidence behind it.
stale_allow=0
while IFS= read -r rule; do
    target="${rule#!}"; target="${target%%\**}"; target="${target%/}"
    [[ -z "$target" || "$target" == .* ]] && continue
    if [[ ! -e "data_store/$target" ]]; then
        fail "data_store/.gitignore allowlists '$target', which does not exist"
        stale_allow=1
    fi
done < <(grep -E '^!.*\*\*' data_store/.gitignore 2>/dev/null)
[[ $stale_allow -eq 0 ]] && pass "no stale ** allowlist rules in data_store/.gitignore"

# ------------------------------------------------------------------------------
group "Secrets"
# ------------------------------------------------------------------------------
if git grep -InE '(BEGIN [A-Z ]*PRIVATE KEY|A[KS]IA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})' -- . >/dev/null 2>&1; then
    fail "possible secret material in the working tree"
else
    pass "no secret patterns in tree"
fi

# ------------------------------------------------------------------------------
group "Documentation links"
# ------------------------------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
    broken=$(python3 - <<'PY'
import re, pathlib
root = pathlib.Path(".").resolve()
lr = re.compile(r'\[[^\]]*\]\(([^)]+)\)')
bad = []
for md in sorted(root.rglob("*.md")):
    rel = str(md.relative_to(root))
    # Skip VCS internals, evidence corpora — data_store/ holds raw and
    # processed forensic samples (whole disk images, vendored OS docs), whose
    # internal links are not this project's documentation to validate — third-
    # party caches (ansible-lint installs the collection's pinned deps under
    # .ansible/), and the GoDFIR-toolz submodule (its docs are validated in its
    # own repo; the Byakugan CAR engine lives in an external checkout outside
    # the repo, so it never enters this walk).
    if ".git/" in str(md) or rel.startswith("data_store/"): continue
    if "/.ansible/" in str(md) or rel.startswith(".ansible/"): continue
    # the repo's own ansible venv (scripts/setup-environment.sh puts it at
    # .venv/): pip's site-packages carry their projects' docs, not ours
    if rel.startswith(".venv/") or "/.venv/" in str(md): continue
    # CI working dirs: the checks job keeps GOPATH at .go/ and pip's cache at
    # .cache/ — third-party module READMEs, not ours
    if rel.startswith((".go/", ".cache/")): continue
    if rel.startswith("docker/GoDFIR-toolz/") or "/GoDFIR-toolz/" in str(md): continue
    if rel.startswith("build/"): continue
    for m in lr.finditer(md.read_text(errors="ignore")):
        t = m.group(1).split("#")[0].strip()
        if not t or t.startswith(("http://", "https://", "mailto:")): continue
        tgt = (root / t.lstrip("/")) if t.startswith("/") else (md.parent / t)
        if not tgt.exists():
            bad.append(f"{md.relative_to(root)} -> {t}")
print("\n".join(bad))
PY
)
    if [[ -z "$broken" ]]; then pass "all internal doc links resolve"
    else while IFS= read -r b; do fail "broken link: $b"; done <<< "$broken"; fi
else
    skip "python3 not available"
fi

# ------------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════"
printf "  passed: %-4s failed: %-4s skipped: %s\n" "$PASS" "$FAIL" "$SKIP"
echo "═══════════════════════════════════════════"
if [[ $FAIL -gt 0 ]]; then
    echo "  ❌ $FAIL check(s) failed"
    exit 1
fi
echo "  ✅ all checks passed"
