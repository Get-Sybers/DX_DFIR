"""DX_DFIR must not house what Byakugan owns.

Byakugan (the standalone ``get-sybers/byakugan`` engine) owns the MITRE CAR
object model, its extraction/relation reference documentation, and the CAR
correctness gate (``byakugan.verify``). DX_DFIR only *orchestrates* that engine
(it shells the hardened image) and links out to the Byakugan repo for the CAR
reference. That boundary was drawn when the CAR reference and gate logic moved
to Byakugan.

These tests fail if the boundary regresses — a Byakugan-owned doc tree reappears
under ``docs/``, DX_DFIR Python imports the engine package or reimplements its
CAR gate in-process instead of shelling the image, or the engine's DISK OUTPUT
inside this repo becomes commit-able: what Byakugan writes onto disk here
(the materialised CAR tree, the load bundles) is engine-owned and stays
ignored, never DX_DFIR content.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PACKAGE = REPO / "python" / "get_sybers_dxdfir"

# Byakugan-owned reference documentation. DX_DFIR references it in the Byakugan
# repo and must not house it again. (docs/architecture/car-pipeline.md is
# DX_DFIR's own CAR-lane architecture doc and is intentionally NOT listed.)
FORBIDDEN_PATHS = (
    "docs/CAR-CrossSource.md",
    "docs/CAR-Extraction-Rules.md",
    "docs/CAR-Pipeline.md",
    "docs/CAR-Relations.md",
    "docs/car-provenance",
    "docs/research/cross-source-linkage",
)

_ENGINE_IMPORT = re.compile(r"^\s*(?:import\s+byakugan\b|from\s+byakugan\b)", re.MULTILINE)
_REEMBEDDED_GATE = re.compile(r"\bdef\s+car_vocab\b|\bCAR_ACTION_VOCAB\b")


def test_no_byakugan_owned_doc_paths():
    present = [p for p in FORBIDDEN_PATHS if (REPO / p).exists()]
    assert not present, (
        "Byakugan-owned reference paths reappeared in DX_DFIR; they belong in the "
        f"Byakugan repo, not here: {present}"
    )


def test_dxdfir_does_not_import_or_reembed_the_engine():
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(REPO)
        if _ENGINE_IMPORT.search(text):
            offenders.append(f"{rel}: imports the byakugan engine package")
        if _REEMBEDDED_GATE.search(text):
            offenders.append(f"{rel}: re-embeds the CAR gate/vocabulary")
    assert not offenders, (
        "DX_DFIR re-embedded Byakugan-owned CAR logic (it should shell the "
        "get-sybers/byakugan image instead): " + "; ".join(offenders)
    )


# Byakugan WRITES into this repo only under these data_store roots (the lane
# roles' out-dir defaults): the materialised CAR tree — car_<object>.jsonl,
# car_relationships.jsonl, stix_bundle.json, verify.txt, timeline.jsonl — and
# the load bundles. Everything the engine writes is ENGINE-OWNED output:
# data_store/.gitignore's deny-by-default keeps every byte of it
# un-commit-able here, and these tests keep THAT enforced. A new lane that
# lands engine output must join this list and stay under data_store/processed/.
ENGINE_WRITE_ROOTS = (
    "data_store/processed/byakugan",
    "data_store/processed/byakugan-load",
)


def _git(*args: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=False)


def test_engine_written_output_is_never_commitable():
    probes = [f"{root}/case-x/{name}" for root in ENGINE_WRITE_ROOTS
              for name in ("car_flow.jsonl", "stix_bundle.json", "verify.txt",
                           "elastic/logs-car.process.bulk.ndjson",
                           "a-format-nobody-thought-of.new")]
    for probe in probes:
        assert _git("check-ignore", "-q", probe).returncode == 0, (
            f"{probe} is commit-able — engine-written output is Byakugan-owned and must "
            "stay ignored (data_store/.gitignore, deny-by-default)"
        )


def test_no_engine_output_is_tracked_beyond_the_skeleton():
    for root in ENGINE_WRITE_ROOTS:
        tracked = _git("ls-files", "--", root).stdout.splitlines()
        stray = [p for p in tracked if not p.endswith(".gitkeep")]
        assert not stray, (
            f"engine-owned output is committed under {root}: {stray} — "
            "what Byakugan writes, DX_DFIR never houses"
        )


def test_engine_out_dir_defaults_stay_under_the_ignored_store():
    # a refactor must not silently move an engine out-dir default into
    # commit-able tree space; the exchange lane joins this table when it lands
    defaults = {
        "dxdfir_byakugan_dir":
            "ansible/collections/get_sybers.dxdfir/roles/dxdfir_byakugan/defaults/main.yml",
        "dxdfir_car_load_dir":
            "ansible/collections/get_sybers.dxdfir/roles/dxdfir_car_load/defaults/main.yml",
        "dxdfir_car_load_out_dir":
            "ansible/collections/get_sybers.dxdfir/roles/dxdfir_car_load/defaults/main.yml",
    }
    for var, rel in defaults.items():
        text = (REPO / rel).read_text(encoding="utf-8")
        m = re.search(rf"^{var}: \"(.+)\"$", text, re.MULTILINE)
        assert m, f"{rel}: {var} default not found"
        assert "/data_store/processed/" in m.group(1), (
            f"{var} defaults outside data_store/processed/ ({m.group(1)}) — the engine "
            "would write commit-able files into the repo"
        )


def test_the_pinned_dockerfile_pins_the_byakugan_engine():
    # The reference to Byakugan must not be silently dropped or loosened: the
    # engine pin lives as the BYAKUGAN_REF ARG default in the byakugan
    # Dockerfile the GoDFIR-toolz submodule pin carries, and it is always a
    # reproducible full-sha commit.
    dockerfile = REPO / "docker" / "GoDFIR-toolz" / "byakugan" / "Dockerfile"
    assert dockerfile.is_file(), (
        "the GoDFIR-toolz submodule is not checked out — run "
        "`git submodule update --init --recursive docker/GoDFIR-toolz`"
    )
    text = dockerfile.read_text(encoding="utf-8")
    m = re.search(r"^ARG BYAKUGAN_REF=(\S+)$", text, re.MULTILINE)
    assert m, "the byakugan Dockerfile must default ARG BYAKUGAN_REF (the engine pin)"
    assert re.fullmatch(r"[0-9a-f]{40}", m.group(1)), (
        "BYAKUGAN_REF must default to a full 40-hex commit sha (never a branch "
        f"or tag, so the engine pin is reproducible), got {m.group(1)!r}"
    )
