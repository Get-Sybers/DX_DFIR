"""Emerging Threats Open ruleset provisioning for the Suricata lane.

The suricata lane needs rules to alert; the hardened dxdfir/suricata image ships
none. This module fetches the free **ET Open** ruleset and concatenates its
``*.rules`` into one ``<rules-dir>/suricata.rules`` — the file
:func:`suricata.run` looks for and mounts. The yara lane's ``--fetch`` provisions
DetectRaptor the same way (see :mod:`detectraptor`); this is its Suricata analogue.

**Why no content sha256 pin** (unlike DetectRaptor): ET Open is a *rolling* feed —
the tarball at a version URL is rebuilt daily, so a content hash would be stale
within a day. Instead we pin the ENGINE-VERSION URL (the stable addressing ET
publishes per Suricata release) and fetch it over HTTPS, then structurally
validate (it must be a gzip tar that yields ``*.rules`` text) — the same trust
model as the official ``suricata-update``. An air-gapped run drops its own
ruleset into the rules dir instead (``suricata.run`` finds any ``suricata.rules``
and never calls this); ``--fetch`` is online-only by contract.

Stdlib only (urllib, tarfile, io), like the rest of the signatures package.

    python -m get_sybers_dxdfir.signatures.suricata_rules --rules-dir <suricata-rules>
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tarfile
import urllib.request

# Pinned upstream addressing: ET Open, by Suricata engine version. ET publishes a
# rolling tarball per version; we pin the VERSION path (stable), not the content
# (it rolls daily — see the module docstring). To advance: bump _SURICATA_VER to
# match the dxdfir/suricata image's engine.
_SURICATA_VER = "7.0.3"
_ET_OPEN_URL = f"https://rules.emergingthreats.net/open/suricata-{_SURICATA_VER}/emerging.rules.tar.gz"
_RULES_FILE = "suricata.rules"


def extract_rules(tar_bytes: bytes) -> tuple[str, int]:
    """Concatenate every ``*.rules`` member of an ET Open ``.tar.gz`` into one
    ruleset text. Returns (text, file_count). Pure — the download is separate, so
    the merge is unit-testable without the network. Raises on a non-tar / a tar
    with no ``.rules`` (a truncated or wrong download must not write an empty
    ruleset that would silently disable alerting)."""
    chunks: list[str] = []
    n = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith(".rules"):
                continue
            fh = tar.extractfile(member)
            if fh is None:
                continue
            text = fh.read().decode("utf-8", errors="replace")
            chunks.append(f"# --- {os.path.basename(member.name)} ---\n{text.rstrip()}\n")
            n += 1
    if n == 0:
        raise ValueError("ET Open archive contained no .rules files "
                         "(truncated or unexpected download)")
    return "\n".join(chunks), n


def _download(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=180) as resp:  # noqa: S310 — pinned https URL
        return resp.read()


def fetch(rules_dir: str, *, url: str = _ET_OPEN_URL, force: bool = False) -> dict:
    """Provision ``<rules_dir>/suricata.rules`` from ET Open.

    Skips if the ruleset already exists (delete it or pass ``force=True`` to
    refresh). Downloads the pinned-version tarball, extracts+concatenates its
    ``.rules``, and writes them atomically. Returns a summary; raises on a bad
    download (so a failed fetch is loud, never a silently-empty ruleset)."""
    out = os.path.join(rules_dir, _RULES_FILE)
    if os.path.exists(out) and os.path.getsize(out) > 0 and not force:
        return {"tool": "et-open", "output": out, "skipped": True}
    text, n = extract_rules(_download(url))
    header = (
        "# Emerging Threats Open ruleset — fetched by get_sybers_dxdfir, do not edit.\n"
        f"# Source: {url}\n"
        f"# {n} rule files concatenated. ET Open is a rolling feed; re-fetch to update.\n"
        "# Licence: ET Open (BSD-style) — see THIRD_PARTY_NOTICES.md.\n\n"
    )
    os.makedirs(rules_dir, exist_ok=True)
    tmp = out + ".part"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(header + text)
    os.replace(tmp, out)
    rule_lines = sum(1 for ln in text.splitlines()
                     if ln.strip() and not ln.lstrip().startswith("#"))
    return {"tool": "et-open", "output": out, "skipped": False,
            "rule_files": n, "rules": rule_lines, "source": url}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.signatures.suricata_rules",
        description="Fetch the ET Open ruleset (pinned Suricata version) into "
                    "<rules-dir>/suricata.rules.")
    ap.add_argument("--rules-dir", required=True,
                    help="Suricata rules dir (normally data_store/dependencies/suricata-rules)")
    ap.add_argument("--url", default=_ET_OPEN_URL, help="override the ET Open tarball URL")
    ap.add_argument("--force", action="store_true", help="refresh an existing ruleset")
    args = ap.parse_args(argv)
    res = fetch(args.rules_dir, url=args.url, force=args.force)
    json.dump(res, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
