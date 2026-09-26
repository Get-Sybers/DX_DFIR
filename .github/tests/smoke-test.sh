#!/bin/bash
# ==============================================================================
# Pipeline smoke test — the real pipeline end to end over sha256-pinned Sysmon
# fixtures, in throwaway temp dirs (docs/reference/build-and-test.md "Smoke").
# FAILS LOUDLY, never skips — a no-op on missing Docker would recreate the
# "green tick that tested nothing" problem (#10). KEEP=1 keeps the temp output.
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

KEEP="${KEEP:-0}"
PLAYBOOKS="ansible/collections/get_sybers.dxdfir/playbooks"
FIXTURE_DIR="$REPO_ROOT/data_store/raw/logs/winevt/sysmon-attack-samples"
OUT_DIR="$(mktemp -d)"     # the processed tree: windows_logs/ from the evtx lane
CAR_DIR="$(mktemp -d)"     # the materialised CAR built from it
LOG_DIR="$(mktemp -d)"
# mktemp defaults to 0700, which would block the containers' uid 2000 — open the tree like the real data_store
chmod 0755 "$OUT_DIR" "$CAR_DIR"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "    ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "    ✗ $1"; }
die()  { echo "❌ $*" >&2; exit 1; }
section() { echo; echo "── $1"; }

# in-repo run: the package under python/ resolves for any python3 helper
export PYTHONPATH="$REPO_ROOT/python${PYTHONPATH:+:$PYTHONPATH}"
# ansible.cfg at the repo root resolves the roles; its log lands in logs/.
export ANSIBLE_CONFIG="$REPO_ROOT/ansible.cfg"

cleanup() {
    rm -rf "$LOG_DIR"
    if [[ "$KEEP" == "1" ]]; then
        echo "   (KEEP=1: leaving $OUT_DIR (goevtx JSON Lines) and $CAR_DIR (CAR) in place)"
        return
    fi
    rm -rf "$OUT_DIR" "$CAR_DIR"
}
trap cleanup EXIT

# --- CAR assertion helpers ---------------------------------------------------
# car_count <object> <action|-> <populated-fields,csv|-> <field=needle|-> —
# matching rows of car_<object>.jsonl across every source under $CAR_DIR
car_count() {
    python3 - "$CAR_DIR" "$1" "$2" "$3" "$4" <<'PY'
import json, os, sys

def empty(v):
    return v is None or (isinstance(v, str) and not v.strip())

def load_rows(car_dir, obj):
    name = f"car_{obj}.jsonl"
    for cur, _dirs, files in os.walk(car_dir):
        if name not in files:
            continue
        with open(os.path.join(cur, name), encoding="utf-8", errors="replace") as fh:
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
command -v ansible-playbook >/dev/null 2>&1 || die "ansible-playbook not found — it ships with 'pip install ./python'."
docker image inspect get-sybers/goevtx:latest >/dev/null 2>&1 \
    || die "image get-sybers/goevtx:latest missing — build it: docker build -t get-sybers/goevtx:latest -f docker/GoDFIR-toolz/goevtx/Dockerfile docker/GoDFIR-toolz/goevtx"
# the CAR lane drives the engine image at its Dockerfile pin
docker image inspect get-sybers/byakugan:latest >/dev/null 2>&1 \
    || die "image get-sybers/byakugan:latest missing — build it: dxdfir build-docker (it clones Byakugan at its Dockerfile's BYAKUGAN_REF pin and builds the hardened engine image)."
pass "docker, python3, ansible-playbook, get-sybers/goevtx:latest and the Byakugan engine image present"

# =============================================================================
section "Fixtures (sha256-pinned Sysmon .evtx)"
# --fetch is idempotent; never gate on --verify (it exits 0 on an empty checkout — bit the first CI run)
echo "   fetching sysmon-attack-samples (checksum-verified, idempotent)…"
./dev-scripts/fetch-samples.sh --fetch sysmon-attack-samples >/dev/null 2>&1 \
    || die "could not fetch the Sysmon fixtures (network? manifest?)."
n_fix=$(find "$FIXTURE_DIR" -iname '*.evtx' 2>/dev/null | wc -l)
(( n_fix > 0 )) || die "no fixtures on disk under $FIXTURE_DIR after fetch."
pass "$n_fix Sysmon .evtx fixtures present and verified"

# =============================================================================
section "Process fixtures through the real evtx lane (dxdfir_evtx -> goevtx)"
if ! ansible-playbook "$PLAYBOOKS/dxdfir-process-evtx.yml" \
        -e "dxdfir_evtx_evtx_dir=$FIXTURE_DIR" -e "dxdfir_evtx_out_dir=$OUT_DIR/windows_logs" \
        >"$LOG_DIR/evtx.out" 2>&1; then
    tail -40 "$LOG_DIR/evtx.out" >&2
    die "the evtx lane failed (see the play output above)"
fi
n_logs=$(find "$OUT_DIR/windows_logs" -name goevtx.jsonl -size +0 2>/dev/null | wc -l)
(( n_logs > 0 )) || die "the evtx lane produced no goevtx.jsonl under $OUT_DIR/windows_logs"
pass "goevtx parsed $n_logs log(s) into goevtx.jsonl"

# =============================================================================
# Normalise the processed evtx into finished CAR (Byakugan engine): one
# car_<object>.jsonl per populated object, plus car_relationships.jsonl — the
# materialised CAR every sink reads. Extraction happens in the engine; this is
# the real CAR path.
section "Normalise to materialised CAR (dxdfir_byakugan build -> car_<object>.jsonl)"
if ! ansible-playbook "$PLAYBOOKS/dxdfir-build-car.yml" \
        -e "dxdfir_byakugan_processed_dir=$OUT_DIR" -e "dxdfir_byakugan_dir=$CAR_DIR" \
        >"$LOG_DIR/car.out" 2>&1; then
    tail -40 "$LOG_DIR/car.out" >&2
    die "CAR normalise (build-car) failed."
fi
n_car=$(find "$CAR_DIR" -name 'car_*.jsonl' -size +0 2>/dev/null | wc -l)
(( n_car > 0 )) || die "the engine wrote no populated car_<object>.jsonl under $CAR_DIR (did it discover the windows_logs source?)"
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

# The relationship edges must surface too.
assert_has relationships -        source_guid,target_guid -                     "car_relationships (relationship edges) populated"

# =============================================================================
# The same tree through the promotion gate: populated, value-sane, traceable,
# car_action in the engine model's vocabulary. `byakugan verify` reads the tree
# as BYAKUGAN_VERIFY_INPUT_DIR (read-only) and writes its report, verify.txt,
# beside the stores; the role passes only on the summary's status == ok and
# shows the report in the play output.
section "The verify-car gate over the same tree (dxdfir_byakugan verify)"
if ansible-playbook "$PLAYBOOKS/dxdfir-verify-car.yml" -e "dxdfir_byakugan_dir=$CAR_DIR" >"$LOG_DIR/gate.out" 2>&1; then
    pass "verify-car: $(grep -oE 'passed: +[0-9]+' "$LOG_DIR/gate.out" | head -1 | tr -s ' '), status ok"
    if [[ -s "$CAR_DIR/verify.txt" ]]; then
        pass "verify.txt written beside the stores"
    else
        fail "verify.txt missing under $CAR_DIR"
    fi
else
    grep -E '✗|❌|not loadable|no materialised CAR|car-verify: status|rc=' "$LOG_DIR/gate.out" >&2 || tail -20 "$LOG_DIR/gate.out" >&2
    fail "verify-car did not pass (details above)"
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
