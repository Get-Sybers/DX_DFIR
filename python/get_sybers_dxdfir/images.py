"""Tool-image inventory guard — refuse to run against anything but the known,
hardened get-sybers/* images, and flag anything added to that namespace that should
not be there.

Two checks:

- ``require(image)`` — run at the START of every processor (its role preflight):
  the exact image the lane is about to run must exist, carry the
  ``com.get-sybers.hardened`` label, and run as uid 2000. A substituted or
  un-hardened get-sybers/* image stops the run before any evidence is touched.
- ``audit()`` — the full inventory: every expected hardened image must be
  present and compliant, and **no other ``get-sybers/*`` image may exist on the host**
  except the curated non-tool ones (the molecule harness). An
  unexpected ``get-sybers/<x>`` image is something added that should not be — a
  supply-chain red flag — and the audit fails on it.

``docker image inspect`` is the trust anchor; the checks are pure over its JSON
so the logic is unit-testable without docker.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


#: The manifest's path under the repo root: the GoDFIR-toolz submodule's OWN
#: root images.yml, read at the gitlink pin. That repo supplies the inventory
#: (plug-and-play); this repo only consumes it, so no DX_DFIR-side image list
#: exists to drift.
_MANIFEST_RELPATH = Path("docker") / "GoDFIR-toolz" / "images.yml"


def _find_manifest() -> Path:
    """Locate the tool-image inventory — the GoDFIR-toolz submodule's
    images.yml. Honour DFIR_REPO_ROOT, else walk up from this file (the
    pipeline runs from the source tree, so the repo root is always an
    ancestor)."""
    root = os.environ.get("DFIR_REPO_ROOT")
    if root and (Path(root) / _MANIFEST_RELPATH).is_file():
        return Path(root) / _MANIFEST_RELPATH
    for parent in Path(__file__).resolve().parents:
        if (parent / _MANIFEST_RELPATH).is_file():
            return parent / _MANIFEST_RELPATH
    raise RuntimeError(
        f"{_MANIFEST_RELPATH} (the tool-image inventory the GoDFIR-toolz "
        "submodule supplies) not found — set DFIR_REPO_ROOT to the repository "
        "root and initialise the submodule (git submodule update --init)")


def _load_inventory() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(HARDENED_IMAGES, ALLOWED_NON_TOOL_REPOS) from the GoDFIR-toolz
    images.yml — the ONE source of truth shared with the Ansible dxdfir_images
    role (both read the submodule's manifest at the gitlink pin). Each `tool`
    image (the default) MUST be hardened (label + uid 2000); non_tool_repos
    are exempt but allow-listed so they don't trip the 'unexpected image'
    audit."""
    import yaml
    path = _find_manifest()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise RuntimeError(f"{path}: tool-image manifest must be a YAML mapping")
    ns = data.get("namespace", "get-sybers")
    images = data.get("images") or []
    if not isinstance(images, list):
        raise RuntimeError(f"{path}: 'images' must be a list of image entries")
    hardened = []
    for img in images:
        if not isinstance(img, dict) or not isinstance(img.get("name"), str) or not img["name"]:
            raise RuntimeError(f"{path}: every image entry needs a non-empty 'name' "
                               f"string (bad entry: {img!r})")
        if img.get("tool", True):
            hardened.append(f"{ns}/{img['name']}:latest")
    non_tool = tuple(data.get("non_tool_repos") or ())
    return tuple(hardened), non_tool


HARDENED_IMAGES, ALLOWED_NON_TOOL_REPOS = _load_inventory()

HARDENED_LABEL = "com.get-sybers.hardened"
REQUIRED_USER = "2000:2000"


def _inspect(image: str) -> dict | None:
    """The image's Config (User, Labels, ...) via ``docker image inspect``, or
    None if the image is absent. Not pure (shells out); kept thin."""
    proc = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{json .Config}}", image],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout.strip() or "null")
    except json.JSONDecodeError:
        return None


def check_config(config: dict | None) -> list[str]:
    """Hardening violations for one image's Config. Pure. Empty list = OK."""
    if config is None:
        return ["image not present"]
    problems = []
    if (config.get("User") or "") != REQUIRED_USER:
        problems.append(f"runs as {config.get('User') or 'root'}, not uid {REQUIRED_USER}")
    labels = config.get("Labels") or {}
    if labels.get(HARDENED_LABEL) != "true":
        problems.append(f"missing {HARDENED_LABEL}=true label")
    return problems


def _repo(image: str) -> str:
    """The repo (``registry[:port]/name``) of an image ref, with any ``:tag`` and
    any ``@sha256:...`` digest stripped. A digest-pinned override (a documented
    way to pin a tool image, e.g. ``get-sybers/goevtx@sha256:...``) must resolve
    to the same known repo as its ``:latest`` tag, or the supply-chain guard
    would reject it. The last ``:`` is a tag only when it comes after the last
    ``/`` — a ``:`` before that is a registry port, which is kept."""
    ref = image.split("@", 1)[0]          # drop an @sha256:... digest first
    colon = ref.rfind(":")
    if colon > ref.rfind("/"):            # a ':' after the last '/' is a tag
        ref = ref[:colon]
    return ref


def require(image: str) -> None:
    """Assert one image is a known hardened get-sybers/* tool image before the lane
    runs it. Raises RuntimeError with the reason otherwise. A non-dxdfir image
    (the documented operator-supplied .NET runtime) is out of scope and passes
    untouched."""
    if not image.startswith("get-sybers/"):
        return
    repo = _repo(image)
    tool_repos = {_repo(i) for i in HARDENED_IMAGES}
    if repo not in tool_repos:
        raise RuntimeError(
            f"refusing to run {image}: not a known DX_DFIR tool image "
            f"(expected one of {sorted(tool_repos)})")
    problems = check_config(_inspect(image))
    if problems:
        raise RuntimeError(
            f"refusing to run {image}: it is not hardened — {'; '.join(problems)}. "
            "Rebuild it with: dxdfir build-docker.")


def _list_dxdfir_images() -> list[str]:
    proc = subprocess.run(
        ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
        capture_output=True, text=True, check=False,
    )
    return [ln for ln in proc.stdout.splitlines()
            if ln.startswith("get-sybers/") and not ln.endswith(":<none>")]


def audit() -> dict:
    """Full inventory audit. Returns {ok, violations:[...]}:
      - every HARDENED_IMAGES entry present + compliant
      - no unexpected ``get-sybers/*`` image on the host (allow-list = the hardened
        tool images + ALLOWED_NON_TOOL_REPOS)."""
    violations = []
    for image in HARDENED_IMAGES:
        for problem in check_config(_inspect(image)):
            violations.append(f"{image}: {problem}")
    allowed = set(HARDENED_IMAGES)
    allowed_repos = {_repo(i) for i in HARDENED_IMAGES} | set(ALLOWED_NON_TOOL_REPOS)
    for present in _list_dxdfir_images():
        if present in allowed:
            continue
        if _repo(present) in allowed_repos:
            continue           # e.g. get-sybers/molecule:latest
        violations.append(
            f"{present}: unexpected get-sybers/* image — not a known DX_DFIR image "
            "(something was added to the namespace that should not be)")
    return {"ok": not violations, "violations": violations,
            "checked": list(HARDENED_IMAGES)}


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.images",
        description="Guard the hardened get-sybers/* tool-image inventory.")
    ap.add_argument("--require", metavar="IMAGE",
                    help="assert one image is a known hardened tool image (start-time gate)")
    ap.add_argument("--audit", action="store_true",
                    help="audit the whole get-sybers/* inventory for missing/unhardened/unexpected images")
    args = ap.parse_args(argv)
    if args.require:
        try:
            require(args.require)
        except RuntimeError as exc:
            sys.stderr.write(str(exc) + "\n")
            return 1
        sys.stdout.write(f"ok: {args.require} is a hardened DX_DFIR tool image\n")
        return 0
    result = audit()
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    if not result["ok"]:
        for v in result["violations"]:
            sys.stderr.write("VIOLATION: " + v + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
