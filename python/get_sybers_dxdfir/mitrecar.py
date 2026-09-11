"""Drive the standalone **PIIAT-MitreCar** tool (the vendored
``third_party/piiat-mitrecar`` submodule) — DX_DFIR uses it in an automated
fashion via its CLI, exactly like the PIIAT-Mem lane: the tool stays a
standalone public project; this module only decides what to run and invokes
``python -m piiat_mitrecar``.

The tool turns each processed evidence SOURCE into its own MITRE CAR database
(one SQLite table per CAR object) plus per-object ``car_<object>.jsonl`` — the
materialised CAR every sink reads (epic #86): ``dxdfir verify-car`` gates it,
and the Elastic-native path projects it to ECS.

    python -m get_sybers_dxdfir.mitrecar --batch data_store/processed
    python -m get_sybers_dxdfir.mitrecar --in <file-or-dir> --out <dir> [--host H]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# The vendored PIIAT-MitreCar submodule — invoked as `python -m piiat_mitrecar`.
_PIIAT_MITRECAR_DIR = os.path.join(_REPO_ROOT, "third_party", "piiat-mitrecar")


def _env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = _PIIAT_MITRECAR_DIR + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env


# PIIAT-MitreCar reconstructs its object model LIVE from ITS OWN pinned
# submodules (car + attack-datasources), so the submodule must be initialised
# RECURSIVELY — a plain `--init` leaves the model sources missing.
_MODEL_SOURCES = (
    os.path.join(_PIIAT_MITRECAR_DIR, "third_party", "car", "data_model"),
    os.path.join(_PIIAT_MITRECAR_DIR, "third_party", "attack-datasources",
                 "docs", "attack_data_sources_objects.yaml"),
)
_INIT_HINT = ("git submodule update --init --recursive third_party/piiat-mitrecar")


def _model_sources_present() -> bool:
    car, ads = _MODEL_SOURCES
    return os.path.isdir(car) and bool(os.listdir(car)) and os.path.exists(ads)


def _ensure_ready() -> None:
    """Make the vendored engine runnable: the package present AND its nested
    model submodules checked out. Self-plumbs with a recursive init, then
    verifies — raising a precise, actionable error if it still can't."""
    if os.path.isdir(_PIIAT_MITRECAR_DIR) and _model_sources_present():
        return
    subprocess.run(["git", "submodule", "update", "--init", "--recursive",
                    "third_party/piiat-mitrecar"],
                   cwd=_REPO_ROOT, capture_output=True, text=True)
    if not os.path.isdir(_PIIAT_MITRECAR_DIR):
        raise RuntimeError(f"third_party/piiat-mitrecar is not initialised — run `{_INIT_HINT}`")
    if not _model_sources_present():
        raise RuntimeError(
            "PIIAT-MitreCar's model submodules (car, attack-datasources) are "
            f"missing — run `{_INIT_HINT}`")


def _run_module(module: str, tool_argv: list[str]) -> subprocess.CompletedProcess:
    _ensure_ready()
    return subprocess.run([sys.executable, "-m", module] + tool_argv,
                          env=_env(), capture_output=True, text=True, check=False)


def run(tool_argv: list[str]) -> subprocess.CompletedProcess:
    """One ``python -m piiat_mitrecar`` invocation with the given tool argv.
    stdout is the tool's JSON summary (returned, not swallowed)."""
    return _run_module("piiat_mitrecar", tool_argv)


def run_timeline(tool_argv: list[str]) -> subprocess.CompletedProcess:
    """Build the unified CAR timeline (``python -m piiat_mitrecar.timeline``) from
    a source's car.db + superset.db."""
    return _run_module("piiat_mitrecar.timeline", tool_argv)


def main(argv: list[str] | None = None) -> int:
    """A transparent pass-through: every flag is the tool's own (see the
    PIIAT-MitreCar README) — this lane only supplies the vendored location.

    The one reserved word is the leading ``timeline`` subcommand, which routes to
    ``piiat_mitrecar.timeline`` so a non-Python front-end can build the unified
    CAR timeline as ``python -m get_sybers_dxdfir.mitrecar timeline <car_dir> …``;
    every other invocation flows to the PIIAT-MitreCar build unchanged.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "timeline":
        proc = run_timeline(args[1:])
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        return proc.returncode
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.mitrecar", add_help=False,
        description="drive the vendored PIIAT-MitreCar CLI (all flags pass through)")
    _known, passthrough = ap.parse_known_args(args)
    proc = run(passthrough if passthrough else ["--help"])
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
