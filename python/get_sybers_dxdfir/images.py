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
  except the curated non-tool ones (the SOF-ELK stack, the molecule harness). An
  unexpected ``get-sybers/<x>`` image is something added that should not be — a
  supply-chain red flag — and the audit fails on it.

``docker image inspect`` is the trust anchor; the checks are pure over its JSON
so the logic is unit-testable without docker.
"""
from __future__ import annotations

import json
import subprocess
import sys

# The tool images the pipeline runs. Each MUST be hardened (label + uid 2000).
HARDENED_IMAGES = (
    "get-sybers/yara:latest",
    "get-sybers/suricata:latest",
    "get-sybers/zeek:latest",
    "get-sybers/volatility:latest",
    "get-sybers/plaso:latest",
    "get-sybers/evtxecmd:latest",
    # The Eric Zimmerman tool family (dxdfir_zimmerman lane) — all built from the
    # one parameterized third_party/GoDFIR-toolz/eztool/Dockerfile (see dxdfir_images_set).
    "get-sybers/recmd:latest",
    "get-sybers/mftecmd:latest",
    "get-sybers/amcacheparser:latest",
    "get-sybers/appcompatcacheparser:latest",
    "get-sybers/lecmd:latest",
    "get-sybers/jlecmd:latest",
    "get-sybers/sbecmd:latest",
    "get-sybers/sqlecmd:latest",
    "get-sybers/gorb:latest",
    "get-sybers/wxtcmd:latest",
    # Linux-native Go substitutes for the Windows-bound EZ tools (FROM scratch;
    # built from the GoDFIR-toolz submodule's prefetch/ and srum/ contexts):
    # goprefetch replaces PECmd, goese replaces SrumECmd/SumECmd.
    "get-sybers/goprefetch:latest",
    "get-sybers/goese:latest",
)
# Other get-sybers/* images that legitimately exist but are not tool containers, so
# they are exempt from the hardened-tool contract (but still allow-listed, so
# they don't trip the "unexpected image" audit). Tags are matched by repo.
ALLOWED_NON_TOOL_REPOS = ("get-sybers/sof-elk", "get-sybers/molecule")

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
    return image.rsplit(":", 1)[0]


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
            "Rebuild it with playbooks/dxdfir-build-images.yml.")


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
            continue           # e.g. get-sybers/sof-elk:test, get-sybers/molecule:latest
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
