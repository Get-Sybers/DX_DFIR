#!/bin/bash
# ==============================================================================
# Pipeline smoke test — does the pipeline actually WORK, end to end? (issue #10)
#
# run-checks.sh proves the repo is internally consistent; it never runs the
# pipeline, so a green tick there says nothing about correctness. The bug that
# motivated this — EvtxPayload parsing XML while EvtxECmd emits JSON, silently
# zeroing every Sysmon/Security-derived CAR field — passes every static check.
# Only running real evidence through and reading the CAR objects catches it.
#
# What it does, entirely in throwaway temp dirs (never data_store/processed):
#
#   process pinned Sysmon .evtx through the real evtx lane (EvtxECmd) ->
#   normalise the output into materialised CAR (the vendored byakugan engine,
#   formerly PIIAT-MitreCar, via get_sybers_dxdfir.mitrecar) -> assert each
#   Sysmon-sourced CAR object has rows AND its EvtxPayload-derived fields are
#   populated with the expected values -> run the verify-car gate
#   (get_sybers_dxdfir.carcheck) over the same tree.
#
# Fixtures: the `sysmon-attack-samples` group in dev-scripts/samples-manifest.tsv
# (real Sysmon telemetry from sbousseaden/EVTX-ATTACK-SAMPLES, sha256-pinned, a
# few tens of KB each). Fetched on demand if absent. Public research data, never
# real evidence.
#
# FAILS LOUDLY, never skips: a smoke test that no-ops when Docker is missing
# would recreate exactly the "green tick that tested nothing" problem (#10). If a
# prerequisite is missing it exits non-zero and says why.
#
#   ./tests/smoke-test.sh            # process, normalise, assert, gate
#   KEEP=1 ./tests/smoke-test.sh     # leave the temp output in place for inspection
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || exit 1

KEEP="${KEEP:-0}"
FIXTURE_DIR="data_store/raw/logs/winevt/sysmon-attack-samples"
OUT_DIR="$(mktemp -d)"     # the evtx lane's EvtxECmd JSON
CAR_DIR="$(mktemp -d)"     # the materialised CAR built from it
LOG_DIR="$(mktemp -d)"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "    ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "    ✗ $1"; }
die()  { echo "❌ $*" >&2; exit 1; }
section() { echo; echo "── $1"; }

# In-repo run: the get_sybers_dxdfir package is under python/ (a deployed install
# would already be importable). Mirrors dxdfir_evtx_python_path in the role.
export PYTHONPATH="$REPO_ROOT/python${PYTHONPATH:+:$PYTHONPATH}"

cleanup() {
    rm -rf "$LOG_DIR"
    if [[ "$KEEP" == "1" ]]; then
        echo "   (KEEP=1: leaving $OUT_DIR (EvtxECmd JSON) and $CAR_DIR (CAR) in place)"
        return
    fi
    rm -rf "$OUT_DIR" "$CAR_DIR"
}
trap cleanup EXIT

# --- CAR assertion helpers ---------------------------------------------------
# car_count <object> <action|-> <populated-fields,csv|-> <field=needle|->
# Rows of car_<object>.jsonl (across every source under $CAR_DIR) with that
# car_action (or any), every listed field populated, and — when given — the
# needle somewhere in the field's value. Reads the tree through the framework's
# own loader (get_sybers_dxdfir.carcheck), so this test and the gate agree on what
# a row is.
car_count() {
    python3 - "$CAR_DIR" "$1" "$2" "$3" "$4" <<'PY'
import sys
from get_sybers_dxdfir.carcheck import empty, load_rows
car_dir, obj, action, fields, contains = sys.argv[1:6]
want = [] if fields == "-" else [f for f in fields.split(",") if f]
field, _, needle = ("", "", "") if contains == "-" else contains.partition("=")
n = 0
for r in load_rows(car_dir, obj):
    if action != "-" and r.get("car_action") != action:
        continue
    if any(empty(r.get(f)) for f in want):
        continue
    if field and needle not in str(r.get(field) or ""):
        continue
    n += 1
print(n)
PY
}

# assert_has <object> <action|-> <populated-fields,csv|-> <field=needle|-> <description>
assert_has() {
    local obj="$1" action="$2" fields="$3" contains="$4" desc="$5" got
    got="$(car_count "$obj" "$action" "$fields" "$contains" 2>/dev/null)"
    if [[ "$got" =~ ^[0-9]+$ ]] && (( got >= 1 )); then
        pass "$desc ($got row(s))"
    else
        fail "$desc (got '${got:-<none>}', wanted >= 1)"
    fi
}

# =============================================================================
section "Preflight (fail loudly — never skip)"
command -v docker >/dev/null 2>&1 || die "docker not found. This test RUNS the pipeline; it cannot be skipped."
docker info >/dev/null 2>&1 || die "docker daemon not reachable."
command -v python3 >/dev/null 2>&1 || die "python3 not found."
docker image inspect dxdfir/evtxecmd:latest >/dev/null 2>&1 \
    || die "image dxdfir/evtxecmd:latest missing — build it: docker build -t dxdfir/evtxecmd:latest -f docker/evtxecmd/Dockerfile docker"
# The CAR lane reconstructs its model from the engine's nested submodules.
python3 -c 'import sys; from get_sybers_dxdfir import mitrecar; sys.exit(0 if mitrecar._model_sources_present() else 1)' 2>/dev/null \
    || die "byakugan's model sources are missing — run: git submodule update --init --recursive third_party/piiat-mitrecar"
pass "docker, python3, dxdfir/evtxecmd:latest and the vendored CAR engine present"

# =============================================================================
section "Fixtures (sha256-pinned Sysmon .evtx)"
# --fetch is idempotent: it sha256-verifies files already on disk and downloads
# only what is missing. (Don't gate on --verify — it reports missing files as
# "not fetched", not a failure, so it exits 0 on an empty checkout and would skip
# the fetch entirely — exactly what happened on the first CI run.)
echo "   fetching sysmon-attack-samples (checksum-verified, idempotent)…"
./dev-scripts/fetch-samples.sh --fetch sysmon-attack-samples >/dev/null 2>&1 \
    || die "could not fetch the Sysmon fixtures (network? manifest?)."
n_fix=$(find "$FIXTURE_DIR" -iname '*.evtx' 2>/dev/null | wc -l)
(( n_fix > 0 )) || die "no fixtures on disk under $FIXTURE_DIR after fetch."
pass "$n_fix Sysmon .evtx fixtures present and verified"

# =============================================================================
section "Process fixtures through the real evtx lane (EvtxECmd)"
summary="$(python3 -m get_sybers_dxdfir.evtx --evtx-dir "$FIXTURE_DIR" --out-dir "$OUT_DIR" 2>"$LOG_DIR/evtx.err")"
processed="$(printf '%s' "$summary" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("processed",0))' 2>/dev/null)"
if ! [[ "$processed" =~ ^[0-9]+$ ]] || (( processed == 0 )); then
    tail -20 "$LOG_DIR/evtx.err" >&2
    die "evtx processor produced nothing (summary: $summary)"
fi
pass "EvtxECmd processed $processed log(s)"

# =============================================================================
# Normalise the processed evtx into finished CAR (byakugan engine): one
# car_<object>.jsonl per populated object, plus car_relationships.jsonl — the
# materialised CAR every sink reads. Extraction happens in the engine; this is
# the real CAR path.
section "Normalise to materialised CAR (car_<object>.jsonl)"
if ! python3 -m get_sybers_dxdfir.mitrecar --in "$OUT_DIR" --out "$CAR_DIR/windows_logs_sysmon" >"$LOG_DIR/car.out" 2>"$LOG_DIR/car.err"; then
    tail -20 "$LOG_DIR/car.err" >&2
    die "CAR normalise (build-car) failed."
fi
n_car=$(find "$CAR_DIR" -name 'car_*.jsonl' -size +0 2>/dev/null | wc -l)
(( n_car > 0 )) || die "the engine wrote no populated car_<object>.jsonl under $CAR_DIR"
pass "$n_car populated car_<object>.jsonl file(s) written"

# =============================================================================
# The heart of the test: CORRECTNESS. Each CAR object must have rows AND its
# extracted fields must be populated (all empty under the old XML bug), and
# where a fixture value is known, it must be present. Numeric-looking fields
# are strings (honest verbatim values), so "populated" is non-empty, not > 0.
section "CAR correctness assertions (Sysmon EID 1/3/5/6/7/8/11/12/13 -> car_<object>.jsonl)"

assert_has driver   -             image_path,signer     -                       "car_driver (EID6): image_path + signer populated"
assert_has driver   -             -                     image_path=VBoxDrv.sys  "car_driver: known BYOVD driver VBoxDrv.sys present"

assert_has module   -             module_path,pid       -                       "car_module (EID7): module_path + pid populated"

assert_has thread   remote_create tgt_pid,start_address -                       "car_thread (EID8): tgt_pid + start_address populated"

assert_has process  create        command_line          -                       "car_process (EID1): command_line populated"
assert_has process  terminate     -                     -                       "car_process (EID5): terminate rows present"

assert_has flow     -             src_ip,dest_port      -                       "car_flow (EID3): src_ip + dest_port populated"

assert_has file     -             file_path             -                       "car_file (EID11): file_path populated"

assert_has registry -             key                   -                       "car_registry (EID12/13): key populated"

# The superset relationship edges must surface too.
assert_has relationships -        source_guid,target_guid -                     "car_relationships (superset edges) populated"

# =============================================================================
# The same tree through the promotion gate: populated, value-sane, traceable,
# car_action in the engine model's vocabulary.
section "The verify-car gate over the same tree (get_sybers_dxdfir.carcheck)"
if python3 -m get_sybers_dxdfir.carcheck --car-dir "$CAR_DIR" >"$LOG_DIR/gate.out" 2>&1; then
    pass "verify-car: $(grep -oE 'passed: +[0-9]+' "$LOG_DIR/gate.out" | head -1 | tr -s ' '), no failures"
else
    grep -E '✗|❌|not loadable|no materialised CAR' "$LOG_DIR/gate.out" >&2 || tail -20 "$LOG_DIR/gate.out" >&2
    fail "verify-car reported failures (details above)"
fi

# =============================================================================
echo
echo "═══════════════════════════════════════════"
printf "  passed: %-4d failed: %d\n" "$PASS" "$FAIL"
echo "═══════════════════════════════════════════"
if (( FAIL > 0 )); then
    echo "  ❌ smoke test FAILED — the pipeline produced wrong or empty CAR output."
    exit 1
fi
echo "  ✅ pipeline smoke test passed — real evidence → correct materialised CAR."
