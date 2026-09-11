"""``python -m get_sybers_dxdfir.stix`` — run the STIX 2.1 / OpenCTI Typer sub-app.

The Go front-end shells this so the ``dxdfir stix`` verbs (export,
behaviour-sightings, pull, sightings) keep their exact behaviour and their
stdout=data / stderr=summary contract; nothing here alters the sub-app.
"""
from __future__ import annotations

from .cli import app

if __name__ == "__main__":
    app()
