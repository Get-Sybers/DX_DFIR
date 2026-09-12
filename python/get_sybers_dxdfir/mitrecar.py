"""Drive the standalone **Byakugan** engine — DX_DFIR uses it in an automated
fashion via its CLI, exactly like the PIIAT-Mem lane: the engine stays a
standalone public project; this module only decides what to run and invokes
``python -m piiat_mitrecar`` (the package keeps upstream's import name).

The engine is an EXTERNAL recursive checkout, not vendored in this repo.
:func:`engine_root` is the canonical resolver: ``$BYAKUGAN_ROOT`` when set,
else the ``byakugan`` directory next to (a sibling of) the DX_DFIR checkout.
The pinned engine commit lives in ``byakugan.ref`` at the repo root, and the
resolved root is prepended to the child process's ``PYTHONPATH``.

The engine turns each processed evidence SOURCE into its own MITRE CAR database
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

# The ONE provisioning hint, shared by every dead-end message (carcheck imports it).
PROVISION_HINT = (
    "run scripts/setup-environment.sh, or manually: "
    "git clone --recurse-submodules https://github.com/Get-Sybers/byakugan <root> "
    "&& git -C <root> checkout <ref from byakugan.ref> "
    "&& git -C <root> submodule update --init --recursive")


def engine_root() -> str:
    """The canonical Byakugan engine root: ``$BYAKUGAN_ROOT`` when set (read at
    call time, so tests can monkeypatch the environment), else the ``byakugan``
    directory that is a sibling of the DX_DFIR checkout."""
    env_root = os.environ.get("BYAKUGAN_ROOT")
    if env_root:
        return env_root
    return os.path.join(os.path.dirname(_REPO_ROOT), "byakugan")


def _env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = engine_root() + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env


# Byakugan reconstructs its object model LIVE from ITS OWN nested submodules
# (car + attack-datasources, resolved next to the package), so the engine
# checkout must be RECURSIVE — a plain clone leaves the model sources missing.
def _model_sources(root: str) -> tuple[str, str]:
    return (os.path.join(root, "third_party", "car", "data_model"),
            os.path.join(root, "third_party", "attack-datasources",
                         "docs", "attack_data_sources_objects.yaml"))


def _model_sources_present(root: str | None = None) -> bool:
    car, ads = _model_sources(root if root is not None else engine_root())
    return os.path.isdir(car) and bool(os.listdir(car)) and os.path.exists(ads)


def _pinned_ref() -> str | None:
    """The engine commit pinned by ``byakugan.ref`` at the DX_DFIR repo root:
    the first non-comment, non-blank line. None when unreadable/absent."""
    try:
        with open(os.path.join(_REPO_ROOT, "byakugan.ref"), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except OSError:
        return None
    return None


def _warn_if_off_pin(root: str) -> None:
    """Best-effort version check: when byakugan.ref exists, the engine root is
    a git checkout, and git is available, warn (stderr, NEVER fatal — a
    deliberate branch test must stay possible) if the checkout's HEAD is not
    the pinned commit. Every failure of the check itself is a silent no-op."""
    try:
        pinned = _pinned_ref()
        if not pinned or not os.path.exists(os.path.join(root, ".git")):
            return
        proc = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=False)
        head = proc.stdout.strip()
        if proc.returncode == 0 and head and head != pinned:
            sys.stderr.write(
                f"WARNING: Byakugan checkout at {root} is at commit {head}, but "
                f"byakugan.ref pins {pinned} — results may differ from the tested "
                "engine version.\n")
    except Exception:  # noqa: BLE001 — best-effort only, never fatal
        pass


def _ensure_ready() -> None:
    """Verify the external engine is runnable: the resolved root present AND
    its nested model submodules checked out — raising a precise, actionable
    error if not. Also best-effort-warns when the checkout is off the pin."""
    root = engine_root()
    origin = ("$BYAKUGAN_ROOT" if os.environ.get("BYAKUGAN_ROOT")
              else "the default: the byakugan directory next to the DX_DFIR checkout")
    if not os.path.isdir(root):
        raise RuntimeError(
            f"Byakugan engine not found at {root} (resolved from {origin}) — "
            f"{PROVISION_HINT}")
    if not _model_sources_present(root):
        raise RuntimeError(
            f"the Byakugan engine at {root} (resolved from {origin}) is missing "
            "its model sources (nested submodules car + attack-datasources) — "
            f"{PROVISION_HINT}")
    _warn_if_off_pin(root)


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
    Byakugan README) — this lane only supplies the engine location.

    The one reserved word is the leading ``timeline`` subcommand, which routes to
    ``piiat_mitrecar.timeline`` so a non-Python front-end can build the unified
    CAR timeline as ``python -m get_sybers_dxdfir.mitrecar timeline <car_dir> …``;
    every other invocation flows to the Byakugan build unchanged.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "timeline":
        proc = run_timeline(args[1:])
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        return proc.returncode
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.mitrecar", add_help=False,
        description="drive the external Byakugan engine CLI (all flags pass through)")
    _known, passthrough = ap.parse_known_args(args)
    proc = run(passthrough if passthrough else ["--help"])
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
