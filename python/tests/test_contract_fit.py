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
# Multi-segment paths are real (anamnesis mounts /opt/anamnesis/lib/Symbols).
MOUNT_PATH = re.compile(r"['\"]?path['\"]?\s*:\s*['\"]?(/[A-Za-z0-9_/.-]*[A-Za-z0-9_])['\"]?")
# A bare container path literal (inside a fact value, a Jinja expression, …).
PATH_LITERAL = re.compile(r"/[A-Za-z0-9_/.-]*[A-Za-z0-9_]")
# A container path an env value names (an env-named mount, e.g. a filter file
# handed to the tool via its own env var) — allowed like the runtime preflight,
# but only when the naming env KEY is itself declared by a referenced contract,
# so an undeclared mount cannot vouch for itself through its own env var.
ENV_NAMED = re.compile(r"['\"]?([A-Z][A-Z0-9_]+)['\"]?\s*:\s*\(?\s*['\"]?(/[A-Za-z0-9_/.-]*[A-Za-z0-9_])")


def _contract(tool: str) -> dict:
    return yaml.safe_load((TOOLZ / tool / "contract.yml").read_text())


def _role_contracts(role: Path) -> tuple[set[str], set[str]]:
    """Tool names whose contracts the role references (defaults + tasks),
    split into (present at the pin, missing at the pin)."""
    present: set[str] = set()
    missing: set[str] = set()
    for part in ("defaults", "tasks"):
        for f in (role / part).glob("*.yml"):
            for m in CONTRACT_REF.finditer(f.read_text()):
                if (TOOLZ / m.group(1) / "contract.yml").is_file():
                    present.add(m.group(1))
                else:
                    missing.add(m.group(1))
    return present, missing


def _role_text(role: Path) -> str:
    return "\n".join(f.read_text() for f in sorted((role / "tasks").glob("*.yml")))


def _lane_roles() -> list[tuple[Path, set[str]]]:
    out = []
    for role in sorted(ROLES.iterdir()):
        present, _ = _role_contracts(role)
        if present:
            out.append((role, present))
    return out


def test_lane_roles_reference_existing_contracts():
    assert (TOOLZ / "anamnesis" / "contract.yml").is_file(), (
        "the GoDFIR-toolz submodule is not checked out — run "
        "`git submodule update --init --recursive docker/GoDFIR-toolz`"
    )
    roles = _lane_roles()
    assert roles, "no lane role references a GoDFIR-toolz contract"


def test_referenced_contracts_exist_at_the_pin():
    for role in sorted(ROLES.iterdir()):
        _, missing = _role_contracts(role)
        assert not missing, (
            f"{role.name} references contract(s) {sorted(missing)} that the "
            f"pinned GoDFIR-toolz checkout does not carry — the submodule pin "
            f"and the role have diverged"
        )


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
        declared_env = {k for t in tools for k in (_contract(t).get("env") or {})}
        text = _role_text(role)
        env_named = {p for k, p in ENV_NAMED.findall(text) if k in declared_env}
        # One indirection hop: a declared env key whose value is a role fact
        # ('SIGNATURES_YARA_RULES': some_fact) vouches for the path literals
        # that fact is set from. The fact's value is its key's line plus any
        # folded/multi-line continuation — the following lines indented deeper
        # than the key (DOTALL would instead skate to unrelated paths further
        # down the file).
        for key, var in re.findall(
            r"['\"]?([A-Z][A-Z0-9_]+)['\"]?\s*:\s*([a-z_][a-z0-9_]*)\b", text
        ):
            if key not in declared_env:
                continue
            for m in re.finditer(
                rf"^([ \t]*)['\"]?{var}['\"]?\s*:([^\n]*(?:\n\1[ \t]+[^\n]*)*)",
                text,
                re.M,
            ):
                env_named.update(PATH_LITERAL.findall(m.group(2)))
        # A bind inside a declared mount is within contract (e.g. an operator
        # ruleset file mounted under the declared /rules directory).
        undeclared = {
            p
            for p in set(MOUNT_PATH.findall(text)) - env_named
            if not any(p == d or p.startswith(d + "/") for d in declared)
        }
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
