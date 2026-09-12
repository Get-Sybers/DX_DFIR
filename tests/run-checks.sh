#!/bin/bash
# ==============================================================================
# DX_DFIR — repository checks
#
# The project had no automated verification of any kind, which meant every "✅"
# on the task board was a claim rather than a result. This script codifies the
# checks that can be run without Docker or evidence.
#
# It does NOT test the pipeline. It catches the class of defect that has
# actually bitten this repo: path-resolution bugs, literal-string config
# values, stale documentation links, and evidence-gitignore gaps.
#
#   ./tests/run-checks.sh          run everything
#   ./tests/run-checks.sh -v       show each passing check too
#
# Exit code is non-zero if any check fails, so this can gate CI.
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT="$(realpath "$SCRIPT_DIR/..")"
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
done < <(find scripts dev-scripts tests -name "*.sh" -type f 2>/dev/null | sort)

# ------------------------------------------------------------------------------
group "Shellcheck"
# ------------------------------------------------------------------------------
if command -v shellcheck >/dev/null 2>&1; then
    while IFS= read -r f; do
        # -S error: only hard errors gate. Style warnings are noise for now.
        if shellcheck -S error "$f" >/dev/null 2>&1; then pass "$f"; else fail "shellcheck errors in $f"; fi
    done < <(find scripts dev-scripts tests -name "*.sh" -type f 2>/dev/null | sort)
else
    skip "shellcheck not installed"
fi

# ------------------------------------------------------------------------------
group "Collection requirements"
# ------------------------------------------------------------------------------
# requirements.yml is the single source of pinned Ansible dependencies. This
# gate (which runs on every PR via CI) enforces the contract: it parses, every
# collection is pinned to an exact version (never :latest, never a branch —
# ANSIBLE-STANDARDS galaxy §2), every galaxy.yml dependency is covered by a
# pin, and setup-environment.sh actually installs it.
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
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", ver):
        problems.append(f"{name}: version '{ver}' is not an exact X.Y.Z pin")
    pinned[name] = ver
galaxy = yaml.safe_load(open(sys.argv[2]))
for dep in (galaxy.get("dependencies") or {}):
    if dep not in pinned:
        problems.append(f"galaxy.yml dependency '{dep}' has no pinned entry in requirements.yml")
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
else
    fail "missing $REQS"
fi

# ------------------------------------------------------------------------------
group "Ansible lint"
# ------------------------------------------------------------------------------
# Production-profile ansible-lint over the collection (config: the collection's
# .ansible-lint). Skipped when ansible-lint is not installed (CI installs it).
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
group "Repo-root path resolution"
# ------------------------------------------------------------------------------
# The now-deleted scripts/v2 shipped four scripts computing $SCRIPT_DIR/..
# while living one directory deeper, so they resolved the repo root to
# <repo>/scripts. Three more in scripts/deprecated/ had the same bug and were
# only found by this check. Every script that computes REPO_ROOT_DIR must land
# on the real repo root, whatever depth it lives at.
while IFS= read -r f; do
    line=$(grep -m1 'REPO_ROOT_DIR=' "$f" 2>/dev/null | sed 's/^[[:space:]]*//')
    [[ -z "$line" ]] && continue
    sd="$(dirname "$(readlink -f "$f")")"
    resolved=$(eval "SCRIPT_DIR='$sd'; $line; echo \$REPO_ROOT_DIR" 2>/dev/null)
    if [[ "$resolved" == "$REPO_ROOT" ]]; then pass "$f"
    else fail "$f resolves repo root to '$resolved' (expected '$REPO_ROOT')"; fi
done < <(find scripts -name "*.sh" -type f | sort)

# ------------------------------------------------------------------------------
group "Python unit tests (get_sybers_dxdfir)"
# ------------------------------------------------------------------------------
# The package's pure-logic tests — the processors, the CAR gate (carcheck), the
# Elastic rules-as-code loader, the STIX exchange (and its argparse verbs — the
# Go binary owns the CLI now). No docker, no
# evidence, no backend. Skipped when pytest is not installed (CI installs it
# together with the package's own dependencies).
if python3 -c 'import pytest' >/dev/null 2>&1; then
    if (cd python && PYTHONPATH=. python3 -m pytest -q -p no:cacheprovider tests >/dev/null 2>&1); then
        pass "pytest: python/tests"
    else
        fail "pytest reported failures (run: cd python && PYTHONPATH=. python3 -m pytest tests)"
    fi
else
    skip "pytest not installed"
fi

# ------------------------------------------------------------------------------
group "Go front-end (gofmt / vet / build / test)"
# ------------------------------------------------------------------------------
# The Go/termui dxdfir front-end (go/): gofmt must be clean, `go vet` must pass,
# the module must build, and the package tests must pass. Skipped when the Go
# toolchain is not installed (CI installs it via actions/setup-go).
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
# One project version, stated in one form. Relabelling alpha -> beta touched a
# dozen files by hand; this is what stops the next one leaving a stray behind.
# The package must agree with itself: pyproject.toml and __init__.__version__
# drift silently otherwise (the CLI prints the stale one).
_pyproject_v=$(grep -m1 -oE '^version = "[0-9.]+"' python/pyproject.toml | grep -oE '[0-9.]+')
_init_v=$(grep -m1 -oE '__version__ = "[0-9.]+"' python/get_sybers_dxdfir/__init__.py | grep -oE '[0-9.]+')
if [[ -n "$_pyproject_v" && "$_pyproject_v" == "$_init_v" ]]; then
    pass "pyproject version ($_pyproject_v) matches get_sybers_dxdfir.__version__"
else
    fail "version drift: pyproject=$_pyproject_v __init__=$_init_v"
fi

PROJECT_VERSION=$(grep -m1 -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+[^]]*\]' CHANGELOG.md 2>/dev/null | tr -d '#[] ')
if [[ -n "$PROJECT_VERSION" ]]; then
    pass "project version from CHANGELOG: $PROJECT_VERSION"
    # The README must NOT declare the current version in prose — it carries a
    # badge that reads the latest Release, so a promotion is a tag and nothing
    # else. Hardcoding it is what made alpha -> beta a twelve-file edit.
    if grep -qE 'img\.shields\.io/github/v/release' README.md 2>/dev/null; then
        pass "README version comes from a live release badge"
    else
        fail "README has no release badge — the version would have to be hand-maintained"
    fi
    if grep -qE '^> \*\*(Status|Release status):' README.md project-progress.md 2>/dev/null; then
        fail "a hardcoded status/version line is back — let the badge state it"
    else
        pass "no hardcoded status line in README or task board"
    fi
else
    fail "could not read a version heading from CHANGELOG.md"
fi
# No document may restate the number of checks. It was hand-copied into six
# files, every harness change meant editing all six, and one still said 86 long
# after the real count passed 160. The harness prints the number; documents
# point at the harness.
_counts=$(grep -rnE '[0-9]{2,4} (static )?checks' --include='*.md' . 2>/dev/null \
          | grep -vE '^\./(\.git|data_store)/' || true)
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
    # .ansible/), and third_party/ (the vendored PIIAT-Mem submodule: upstream
    # docs, not ours to validate; the Byakugan CAR engine lives in an external
    # checkout outside the repo, so it never enters this walk).
    if ".git/" in str(md) or rel.startswith("data_store/"): continue
    if "/.ansible/" in str(md) or rel.startswith(".ansible/"): continue
    if rel.startswith("third_party/") or "/third_party/" in str(md): continue
    # setuptools copies package-data docs into python/build/lib/ during
    # `pip install ./python`; that build output is generated, not source.
    if rel.startswith(("build/", "python/build/")): continue
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
