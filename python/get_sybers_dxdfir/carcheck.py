"""CAR correctness gate (``dxdfir verify-car``) — a thin front over the engine.

CAR is MATERIALISED by the external **Byakugan** engine: one
``car_<object>.jsonl`` per object (plus ``car_relationships.jsonl``) under
``data_store/processed/byakugan/<source>/``. Verifying that materialised CAR is
the ENGINE's job — it owns the CAR model and its car_action vocabulary — so this
lane does not house the checks. It runs the engine's own gate
(``byakugan.verify``) inside the hardened ``get-sybers/byakugan`` image over the
materialised tree (mounted read-only) and relays the report and exit code. The
object model never leaves the engine.

Runnable as ``dxdfir verify-car [--car-dir DIR]`` or
``python -m get_sybers_dxdfir.carcheck [--car-dir DIR]``. Exit codes are the
engine gate's: 0 pass, 1 a check failed, 2 no CAR present (or the engine image is
not built — provision it with ``dxdfir build-docker``).
"""
from __future__ import annotations

import os
import sys

from get_sybers_dxdfir import mitrecar

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_CAR_DIR = os.path.join(_REPO_ROOT, "data_store", "processed", "byakugan")


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.carcheck",
        description="CAR correctness gate over the materialised CAR — runs the engine's "
                    "byakugan.verify run-through inside the hardened get-sybers/byakugan image.")
    ap.add_argument("--car-dir", default=DEFAULT_CAR_DIR,
                    help="the materialised CAR tree (default: data_store/processed/byakugan)")
    args = ap.parse_args(argv)

    try:
        proc = mitrecar.run_verify(args.car_dir)
    except RuntimeError as exc:            # engine image absent / not hardened
        sys.stderr.write(f"{exc}\n{mitrecar.PROVISION_HINT}\n")
        return 2
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
