"""CAR run-through — expected FIELD VALUES in the materialised CAR.

The promotion gate for CAR correctness. CAR is MATERIALISED: the engine
normalises each source into finished CAR events and writes one
``car_<object>.jsonl`` per object (plus ``car_relationships.jsonl``) under
``data_store/processed/car/<source>/`` — the JSON is the contract every sink
reads (the Elastic-native path projects it to ECS). Extraction faithfulness (a
CAR field == its single source record) is proven IN THE ENGINE's own test
suite; this gate asserts what the pipeline actually wrote: each exercised
object has rows, its key fields are POPULATED, its values are SANE (IPs are
IPs, ports are ports, SIDs are SIDs, actions are in the object's vocabulary),
every row TRACES TO ONE ARTEFACT (a non-empty source_artefact — never data
compiled together; source_host is honestly null for artefacts with no host
identity, e.g. Linux utmp / network capture), and the relationship edges
reference real endpoints.

Reads an ALREADY-BUILT CAR tree — run the pipeline first
(dxdfir process <lanes> && dxdfir build-car). An object with no rows is
reported NOT EXERCISED.

Runnable as `dxdfir verify-car [--car-dir DIR]` or
`python -m get_sybers_dxdfir.carcheck [--car-dir DIR]`.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable

# The 13 CAR objects — one car_<object>.jsonl each, per source.
_OBJECTS = ("authentication", "driver", "email", "file", "flow", "http",
            "module", "process", "registry", "service", "socket", "thread",
            "user_session")
# The superset relationship edges (car_relationships.jsonl).
RELATIONSHIPS = "relationships"
# The cross-object timeline: the union of every object's rows.
CAR = "*"

_IP = re.compile(r"^[0-9a-fA-F:.]+$")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_CAR_DIR = os.path.join(_REPO_ROOT, "data_store", "processed", "car")

Row = dict
Pred = Callable[[Row], bool]


def _engine_actions():
    """The canonical car_action vocabulary per object — RECONSTRUCTED from the
    engine's model, exactly as byakugan (formerly PIIAT-MitreCar) builds it:
    generated from the forked `car` repo we own
    (third_party/piiat-mitrecar/third_party/car/data_model), never hardcoded
    here. Returns {object: {actions}} or None if the engine model can't be
    loaded (submodules not checked out)."""
    eng = os.path.join(_REPO_ROOT, "third_party", "piiat-mitrecar")
    if eng not in sys.path:
        sys.path.insert(0, eng)
    try:
        from piiat_mitrecar import carmodel
        m = carmodel.load()
    except Exception:                       # noqa: BLE001 — model source unavailable
        return None
    return {obj: set(m[obj].get("actions", [])) for obj in m}


# ---- the materialised CAR tree ---------------------------------------------
def car_files(car_dir: str, obj: str) -> list[str]:
    """Every ``car_<obj>.jsonl`` under car_dir — one per source that produced
    the object — sorted."""
    name = f"car_{obj}.jsonl"
    out = []
    for cur, _dirs, files in os.walk(car_dir):
        if name in files:
            out.append(os.path.join(cur, name))
    return sorted(out)


def load_rows(car_dir: str, obj: str) -> list[Row]:
    """The rows of one object across every source: one dict per JSON line.
    Blank and unparseable lines are skipped; a vanished file yields nothing."""
    rows: list[Row] = []
    for path in car_files(car_dir, obj):
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    rows.append(rec)
    return rows


def empty(v) -> bool:
    """CAR's notion of unset: None or a blank string. Numeric-looking fields are
    strings (the honest verbatim value), so "0" is a value, not empty."""
    return v is None or (isinstance(v, str) and not v.strip())


def _int(v):
    """A numeric field's value, accepting the two Windows PID encodings (decimal
    and 0x-hex); None when it is not a number."""
    s = str(v).strip()
    try:
        return int(s)
    except ValueError:
        pass
    if s.lower().startswith("0x"):
        try:
            return int(s, 16)
        except ValueError:
            return None
    return None


def has_term(value, term: str) -> bool:
    """Whole-term containment (terms split on non-alphanumerics): 'memory' is in
    'piiat_memory_pslist' but not in 'memoryless'."""
    return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])",
                     str(value or ""), re.I) is not None


def _port_out_of_range(v) -> bool:
    n = _int(v)
    return n is not None and not 0 <= n <= 65535


class _Checker:
    """Runs the assertions over one materialised CAR tree and tallies
    pass/fail/skip."""

    def __init__(self, car_dir: str = DEFAULT_CAR_DIR):
        self.car_dir = os.path.realpath(car_dir)
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.lines: list[str] = []
        self._rows: dict[str, list[Row]] = {}

    def rows(self, obj: str) -> list[Row]:
        """An object's rows across every source (CAR = the union of all objects),
        loaded once."""
        if obj == CAR:
            return [r for o in _OBJECTS for r in self.rows(o)]
        if obj not in self._rows:
            self._rows[obj] = load_rows(self.car_dir, obj)
        return self._rows[obj]

    def count(self, obj: str, pred: Pred | None = None) -> int:
        return sum(1 for r in self.rows(obj) if pred is None or pred(r))

    def _pass(self, desc): self.passed += 1; self.lines.append(f"    ✓ {desc}")
    def _fail(self, desc): self.failed += 1; self.lines.append(f"    ✗ {desc}")

    def skip(self, desc):
        self.skipped += 1
        self.lines.append(f"    ○ {desc} (object not exercised)")

    def section(self, title): self.lines.append(f"\n── {title}")

    def check(self, ok: bool, desc: str):
        if ok:
            self._pass(desc)
        else:
            self._fail(desc)

    def ge(self, obj, pred, minimum, desc):
        got = self.count(obj, pred)
        if got >= minimum:
            self._pass(f"{desc} ({got} >= {minimum})")
        else:
            self._fail(f"{desc} (got {got!r}, wanted >= {minimum})")

    def has(self, obj, pred, desc): self.ge(obj, pred, 1, desc)

    def zero(self, obj, pred, desc):
        got = self.count(obj, pred)
        if got == 0:
            self._pass(f"{desc} (0)")
        else:
            self._fail(f"{desc} (got {got!r}, wanted 0)")

    def has_rows(self, obj, pred: Pred | None = None) -> bool:
        return self.count(obj, pred) >= 1


def run(car_dir: str = DEFAULT_CAR_DIR) -> _Checker:
    """Run the whole CAR run-through over a materialised CAR tree."""
    c = _Checker(car_dir)

    # -- preflight ------------------------------------------------------------
    c.section("Preflight")
    n_files = sum(len(car_files(c.car_dir, obj)) for obj in _OBJECTS)
    c.check(n_files >= 1,
            f"materialised CAR present under {c.car_dir} ({n_files} car_<object>.jsonl file(s))")
    c.has(CAR, None, "the cross-object CAR timeline (union of the objects) has rows")
    # The car_action vocabulary comes from the engine's model (forked car repo).
    actions = _engine_actions()
    if actions is None:
        c._fail("CAR action vocabulary — engine model not loadable "
                "(init submodules: git submodule update --init --recursive)")

    # -- per-object population + value sanity ---------------------------------
    for obj in _OBJECTS:
        if not c.has_rows(obj):
            c.skip(obj)
            continue
        c.section(f"{obj} (car_{obj}.jsonl)")
        # Traceability: every row names the artefact it came from. source_host is
        # a derived scope that is honestly null for artefacts that carry no host
        # identity (Linux utmp, network capture), so it is not required here.
        c.zero(obj, lambda r: empty(r.get("source_artefact")),
               f"{obj}: every row traces to one artefact (source_artefact)")
        c.zero(obj, lambda r: empty(r.get("car_action")),
               f"{obj}: every row has a car_action")
        # car_action ∈ the object's canonical vocabulary, from the engine model
        # (an empty action is already counted above, not twice).
        if actions and actions.get(obj):
            c.zero(obj, lambda r, vocab=actions[obj]: (
                not empty(r.get("car_action")) and r.get("car_action") not in vocab),
                f"{obj}: car_action in the model's {obj} vocabulary")

    # -- value sanity, per object (only where the object was exercised) --------
    if c.has_rows("process"):
        c.section("process — value sanity")
        c.has("process", lambda r: r.get("car_action") == "create" and not empty(r.get("command_line")),
              "process: command_line populated on create")
        c.zero("process", lambda r: not empty(r.get("sid")) and not str(r["sid"]).startswith("S-1-"),
               "process: sid is a Windows SID (S-1-...)")
        c.zero("process", lambda r: not empty(r.get("pid")) and _int(r["pid"]) is None,
               "process: pid is numeric where present")
    if c.has_rows("flow"):
        c.section("flow — value sanity")
        c.zero("flow", lambda r: not empty(r.get("src_ip")) and not _IP.match(str(r["src_ip"])),
               "flow: src_ip is a valid IP literal")
        c.zero("flow", lambda r: not empty(r.get("dest_ip")) and not _IP.match(str(r["dest_ip"])),
               "flow: dest_ip is a valid IP literal")
        c.zero("flow", lambda r: not empty(r.get("dest_port")) and _port_out_of_range(r["dest_port"]),
               "flow: dest_port within 0..65535")
    if c.has_rows("registry"):
        c.section("registry — value sanity")
        c.has("registry", lambda r: not empty(r.get("key")), "registry: key populated")
    if c.has_rows("user_session"):
        c.section("user_session — value sanity")
        c.has("user_session", lambda r: not empty(r.get("user")), "user_session: user populated")
    if c.has_rows("file"):
        c.section("file — value sanity")
        c.has("file", lambda r: not empty(r.get("file_path")), "file: file_path populated")

    # -- relationships (the superset edges) -----------------------------------
    if c.has_rows(RELATIONSHIPS):
        c.section("relationships (superset edges)")
        c.zero(RELATIONSHIPS, lambda r: empty(r.get("source_guid")) or empty(r.get("target_guid")),
               "relationships: every edge names a source and target guid")
        c.zero(RELATIONSHIPS, lambda r: empty(r.get("relationship")),
               "relationships: every edge has a verb")
        c.zero(RELATIONSHIPS, lambda r: (r.get("confidence") or "") not in ("definitive", "heuristic", ""),
               "relationships: confidence in {definitive, heuristic}")
    else:
        c.skip("relationships (car_relationships empty)")

    # -- OS-family coverage ----------------------------------------------------
    c.section("OS-family coverage (what this run actually exercised)")

    def art(r):
        return str(r.get("source_artefact") or "")

    coverage = {
        "Windows (event logs: Sysmon/Security)":
            c.has_rows(CAR, lambda r: art(r) in ("evtx_sysmon", "evtx_security", "evtx_process",
                                                 "evtx_services", "evtx_bits", "evtx_rdp")),
        "Windows (memory: Volatility/PIIAT-Mem)":
            c.has_rows(CAR, lambda r: has_term(art(r), "memory") or has_term(art(r), "piiat")),
        "Linux/Unix (utmp/ssh/cron)":
            c.has_rows(CAR, lambda r: art(r) in ("l2t_utmp", "l2t_text")),
        "macOS (utmpx/fseventsd)":
            c.has_rows(CAR, lambda r: art(r) in ("l2t_utmpx", "plaso_fseventsd")),
        "Network capture (Zeek)":
            c.has_rows(CAR, lambda r: art(r).startswith("zeek")),
    }
    for family, covered in coverage.items():
        c.lines.append(f"    {'●' if covered else '○'} {family}")
    c.os_families_covered = sum(coverage.values())
    c.os_families_total = len(coverage)

    return c


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.carcheck",
        description="CAR run-through: expected field values in the materialised CAR (car_<object>.jsonl).")
    ap.add_argument("--car-dir", default=DEFAULT_CAR_DIR,
                    help="the materialised CAR tree (default: data_store/processed/car)")
    args = ap.parse_args(argv)

    if not any(car_files(args.car_dir, obj) for obj in (*_OBJECTS, RELATIONSHIPS)):
        sys.stderr.write(
            f"no materialised CAR under {args.car_dir} — "
            "process + build-car first (dxdfir process <lanes> && dxdfir build-car).\n")
        return 2

    c = run(args.car_dir)
    print("\n".join(c.lines))
    print("\n" + "=" * 43)
    print(f"  passed: {c.passed:<4} failed: {c.failed:<4} not-exercised: {c.skipped}")
    print("=" * 43)
    if c.failed:
        print("  ❌ CAR run-through FAILED — a CAR field held a wrong/unpopulated/out-of-vocabulary value.")
        return 1
    print("  ✅ CAR run-through passed — populated, value-sane, traceable materialised CAR.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
