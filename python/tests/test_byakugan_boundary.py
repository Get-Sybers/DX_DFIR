"""DX_DFIR must not house what Byakugan owns.

Byakugan (the standalone ``get-sybers/byakugan`` engine) owns the MITRE CAR
object model, its extraction/relation reference documentation, and the CAR
correctness gate (``byakugan.verify``). DX_DFIR only *orchestrates* that engine
(it shells the hardened image) and links out to the Byakugan repo for the CAR
reference. That boundary was drawn when the CAR reference and gate logic moved
to Byakugan.

These tests fail if the boundary regresses — a Byakugan-owned doc tree reappears
under ``docs/``, or DX_DFIR Python imports the engine package or reimplements its
CAR gate in-process instead of shelling the image.
"""

from __future__ import annotations

import re
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
