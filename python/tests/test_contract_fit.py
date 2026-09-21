"""Lane roles must fit the pinned GoDFIR-toolz tool contracts.

Every lane role drives its hardened container from a contract.yml in the
GoDFIR-toolz submodule: the env vars it sets and the container paths it mounts
exist only if the pinned submodule commit declares them. A role and the
submodule gitlink can only move together — these tests fail the build when a
role speaks a contract the pin does not carry (env keys the contract does not
declare, mount paths it does not define, or required mounts the role never
binds).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
ROLES = REPO / "ansible" / "collections" / "get_sybers.dxdfir" / "roles"
TOOLZ = REPO / "docker" / "GoDFIR-toolz"

# A contract reference in a role's defaults: .../GoDFIR-toolz/<tool>/contract.yml
# (also matched when the submodule path itself is behind a variable).
CONTRACT_REF = re.compile(r"([a-z0-9_-]+)/contract\.yml")
# An env key set on a run: quoted (Jinja dict literal) or bare (YAML mapping).
ENV_KEY = re.compile(r"['\"]?([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)['\"]?\s*:")
# A container mount path on a run: {host: ..., path: /x} or 'path': '/x'.
MOUNT_PATH = re.compile(r"['\"]?path['\"]?\s*:\s*['\"]?(/[a-z0-9_]+)['\"]?")
# A container path an env value names (an env-named mount, e.g. a filter file
# handed to the tool via its own env var) — allowed like the runtime preflight.
ENV_NAMED = re.compile(r"['\"]?[A-Z][A-Z0-9_]+['\"]?\s*:\s*\(?\s*['\"]?(/[a-z0-9_]+)")


def _contract(tool: str) -> dict:
    return yaml.safe_load((TOOLZ / tool / "contract.yml").read_text())


def _role_contracts(role: Path) -> set[str]:
    """Tool names whose contracts the role references (defaults + tasks)."""
    tools: set[str] = set()
    for part in ("defaults", "tasks"):
        for f in (role / part).glob("*.yml"):
            for m in CONTRACT_REF.finditer(f.read_text()):
                if (TOOLZ / m.group(1) / "contract.yml").is_file():
                    tools.add(m.group(1))
    return tools


def _role_text(role: Path) -> str:
    return "\n".join(f.read_text() for f in sorted((role / "tasks").glob("*.yml")))


def _lane_roles() -> list[tuple[Path, set[str]]]:
    out = []
    for role in sorted(ROLES.iterdir()):
        tools = _role_contracts(role)
        if tools:
            out.append((role, tools))
    return out


def test_lane_roles_reference_existing_contracts():
    roles = _lane_roles()
    assert roles, "no lane role references a GoDFIR-toolz contract"


def test_env_keys_are_declared_by_the_pinned_contracts():
    for role, tools in _lane_roles():
        declared = {k for t in tools for k in (_contract(t).get("env") or {})}
        prefixes = {k.split("_", 1)[0] for k in declared}
        used = {
            k
            for k in ENV_KEY.findall(_role_text(role))
            if k.split("_", 1)[0] in prefixes
        }
        undeclared = used - declared
        assert not undeclared, (
            f"{role.name} sets env {sorted(undeclared)} that no referenced "
            f"pinned contract ({sorted(tools)}) declares — the GoDFIR-toolz "
            f"submodule pin and the role have diverged"
        )


def test_mount_paths_are_declared_by_the_pinned_contracts():
    for role, tools in _lane_roles():
        declared = {
            m["path"]
            for t in tools
            for m in (_contract(t).get("mounts") or [])
            if isinstance(m, dict) and "path" in m
        }
        if not declared:
            continue
        text = _role_text(role)
        undeclared = set(MOUNT_PATH.findall(text)) - declared - set(ENV_NAMED.findall(text))
        assert not undeclared, (
            f"{role.name} mounts {sorted(undeclared)} that no referenced "
            f"pinned contract ({sorted(tools)}) defines — the GoDFIR-toolz "
            f"submodule pin and the role have diverged"
        )


def test_required_mounts_are_bound_by_the_role():
    for role, tools in _lane_roles():
        text = _role_text(role)
        for tool in sorted(tools):
            required = {
                m["path"]
                for m in (_contract(tool).get("mounts") or [])
                if isinstance(m, dict) and m.get("required")
            }
            unbound = {p for p in required if not re.search(rf"{p}(?![\w/])", text)}
            assert not unbound, (
                f"{role.name} never binds required mount(s) {sorted(unbound)} "
                f"of the pinned {tool} contract"
            )
