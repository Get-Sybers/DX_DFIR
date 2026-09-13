"""DetectRaptor YARA provisioning — fetch, verify, merge into one ruleset.

`mgreen27/DetectRaptor <https://github.com/mgreen27/DetectRaptor>`_ ships bulk
Velociraptor detection content. Most of it (VQL artifacts + the CSV lookups that
drive them) needs a Velociraptor server and has no consuming lane here; what THIS
pipeline can run is its ``yara/`` directory — curated YARA rulesets (webshells,
plus per-OS file and process sets, YARA-Forge-derived with per-rule provenance
metadata).

Upstream publishes each set for a *separate* Velociraptor artifact, so the sets
freely repeat rule identifiers (every pair of files collides). The YARA lane
compiles ONE index of everything under the rules dir, and yara errors on duplicate
identifiers — so this module downloads the pinned assets, verifies their sha256,
and merges them into a single deduplicated ``detectraptor/detectraptor.yar``
(imports hoisted, first occurrence of each rule identifier wins, per-rule ``meta``
provenance kept intact). Nothing third-party is vendored in the repository: the
merged file lands under ``data_store/dependencies/yara-rules/`` (deny-by-default
gitignored) and is re-fetchable from the pin.

CAUTION: the sets are largely YARA-Forge extracts, so the merged file repeats rule
names from the YARA-Forge packages. Do not put both in one rules dir (e.g. a
downloaded YARA-Forge release) — the lane's single index would fail to compile.

Stdlib only (urllib, gzip, hashlib), like the rest of the signatures package.

    python -m get_sybers_dxdfir.signatures.detectraptor --rules-dir <yara-rules>

or implicitly: the yara lane's ``--fetch`` calls :func:`fetch` when the merged
file is absent.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import re
import sys
import urllib.request

# Pinned upstream state: repo commit + sha256 of each downloaded object (the .gz
# bytes for gzipped assets). A mismatch means upstream moved or the download was
# tampered with — same discipline as dev-scripts/samples-manifest.tsv. To advance
# the pin: bump _PIN, re-run with --print-hashes, paste the new digests.
_REPO = "mgreen27/DetectRaptor"
_PIN = "4c3cdddcfff334edeeda8875d5839be43978ea8b"  # master @ 2026-08-23
_RAW = f"https://raw.githubusercontent.com/{_REPO}/{_PIN}/yara/"

# name -> (upstream file, sha256 of the download, gzipped?). Merge precedence is
# this order: first occurrence of a duplicate rule identifier wins.
ASSETS: dict[str, tuple[str, str, bool]] = {
    "webshells": (
        "webshells.yar",
        "3a44da109b7033c059aca99b1b8c04ebb8886cf03daacb9fefc435d44f28361a", False),
    "windows_file": (
        "full_windows_file.yar.gz",
        "0b10ae6bd90258bcf1819f56544ffc61de8ec7cca7a3915b825c261053b333c7", True),
    "linux_file": (
        "full_linux_file.yar.gz",
        "d7a764a599fc2b5092d6145d4c2c099fa663242d6a482eba931569bb57c34256", True),
    "macos_file": (
        "full_macos_file.yar.gz",
        "242ac57b50f3ea76e4fad44a6c09fcea1dbdadacd548b6285929daa7b95edb4b", True),
    "windows_process": (
        "full_windows_process.yar",
        "6bd4d1344c810441726450c4b9a1a75c644dc488fe7e8c6dd03a37c0bb567dd4", False),
    "linux_process": (
        "full_linux_process.yar",
        "87415b8adf088a34d6a12a9dc63b6ebfce1e0a123420ec3ba76b656dc947318c", False),
    "macos_process": (
        "full_macos_process.yar",
        "1891f46edecb4a6ac51748be4be1f426499540bf591a15953ce2905331a0869a", False),
}

# NOT fetched: yara/yara-rules-full.yar (20 MB) — it IS the YARA-Forge "full"
# package (available directly from YARA-Forge releases); fetching it here would
# only duplicate (and collide with) the targeted sets above.

_MERGED_NAME = "detectraptor.yar"
_RULE_START = re.compile(r"(?m)^(?:private\s+)?rule\s+([A-Za-z0-9_]+)")
_IMPORT = re.compile(r'(?m)^import\s+"([^"]+)"\s*$')

# Module features the lane's yara build (get-sybers/yara, Debian libyara) does not
# have; a rule using one fails the WHOLE single-index compile, so drop it at
# merge time and count it. telfhash needs a tlsh-enabled build.
_INCOMPATIBLE = ("telfhash",)


def merge_rules(named_texts: list[tuple[str, str]],
                incompatible: tuple[str, ...] = _INCOMPATIBLE) -> tuple[str, dict]:
    """Merge YARA sources into one compilable text. Pure.

    Hoists ``import`` statements (deduplicated) to the top and keeps the FIRST
    occurrence of each rule identifier — upstream repeats identifiers across sets
    because each set targets its own Velociraptor artifact, but one yara compile
    must see each name once. Rules using a feature in ``incompatible`` are dropped
    (one bad rule fails the whole compile). Returns
    (text, {source: {"kept": n, "dropped": n, "incompatible": n}}).
    """
    imports: list[str] = []
    seen_imports: set[str] = set()
    seen_rules: set[str] = set()
    chunks: list[str] = []
    stats: dict = {}
    for source, text in named_texts:
        for mod in _IMPORT.findall(text):
            if mod not in seen_imports:
                seen_imports.add(mod)
                imports.append(f'import "{mod}"')
        kept = dropped = skipped = 0
        starts = list(_RULE_START.finditer(text))
        for i, m in enumerate(starts):
            end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
            name = m.group(1)
            if name in seen_rules:
                dropped += 1
                continue
            body = text[m.start():end]
            if any(feat in body for feat in incompatible):
                skipped += 1
                continue
            seen_rules.add(name)
            kept += 1
            chunks.append(f"// source: {source}\n" + body.rstrip() + "\n")
        stats[source] = {"kept": kept, "dropped": dropped, "incompatible": skipped}
    body = "\n".join(chunks)
    return ("\n".join(imports) + ("\n\n" if imports else "") + body, stats)


def _download(url: str, want_sha256: str, gzipped: bool) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 — pinned https URL
        blob = resp.read()
    got = hashlib.sha256(blob).hexdigest()
    if got != want_sha256:
        raise ValueError(f"sha256 mismatch for {url}: expected {want_sha256}, got {got}")
    return gzip.decompress(blob) if gzipped else blob


def print_hashes(pin: str) -> None:
    """Print the sha256 of every asset at ``pin`` — the pin-advance workflow:
    bump ``_PIN``, run ``--print-hashes``, paste the digests into ``ASSETS``."""
    raw = f"https://raw.githubusercontent.com/{_REPO}/{pin}/yara/"
    for name, (fname, _sha, _gz) in ASSETS.items():
        with urllib.request.urlopen(raw + fname, timeout=120) as resp:  # noqa: S310
            digest = hashlib.sha256(resp.read()).hexdigest()
        print(f"{name}: {digest}  # {fname} @ {pin}")


def fetch(rules_dir: str, *, assets: list[str] | None = None, force: bool = False) -> dict:
    """Provision the merged DetectRaptor ruleset under ``rules_dir``.

    Downloads each pinned asset (in-memory, nothing staged on disk), verifies its
    sha256, merges, and writes ``<rules_dir>/detectraptor/detectraptor.yar``.
    Skips everything if the merged file already exists (delete it or pass
    ``force=True`` to refresh). Returns a summary dict; raises on hash mismatch.
    """
    names = list(assets) if assets else list(ASSETS)
    unknown = [n for n in names if n not in ASSETS]
    if unknown:
        raise ValueError(f"unknown asset(s): {', '.join(unknown)} (have: {', '.join(ASSETS)})")
    out = os.path.join(rules_dir, "detectraptor", _MERGED_NAME)
    if os.path.exists(out) and not force:
        return {"tool": "detectraptor", "output": out, "skipped": True}

    named_texts = []
    for name in names:
        fname, sha, gz = ASSETS[name]
        blob = _download(_RAW + fname, sha, gz)
        named_texts.append((fname, blob.decode("utf-8", errors="replace")))
    merged, stats = merge_rules(named_texts)

    header = (
        "// DetectRaptor YARA rules — fetched and merged by get_sybers_dxdfir, do not edit.\n"
        f"// Upstream: https://github.com/{_REPO} @ {_PIN}\n"
        f"// Assets:   {', '.join(ASSETS[n][0] for n in names)}\n"
        "// Duplicate rule identifiers across upstream sets are dropped (first wins);\n"
        "// per-rule meta (author, source_url, license_url) is upstream's, unmodified.\n"
        "// Provenance/licensing: THIRD_PARTY_NOTICES.md (DetectRaptor section).\n\n"
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".part"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(header + merged)
    os.replace(tmp, out)
    rules = sum(s["kept"] for s in stats.values())
    return {"tool": "detectraptor", "output": out, "skipped": False,
            "rules": rules, "sources": stats}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.signatures.detectraptor",
        description="Fetch DetectRaptor YARA content (pinned + sha256-verified) and "
                    "merge it into <rules-dir>/detectraptor/detectraptor.yar",
    )
    ap.add_argument("--rules-dir",
                    help="YARA rules dir (normally data_store/dependencies/yara-rules); "
                         "required unless --print-hashes")
    ap.add_argument("--assets", action="append", choices=list(ASSETS),
                    help="asset to include (repeatable); default all")
    ap.add_argument("--force", action="store_true", help="refresh an existing merged file")
    ap.add_argument("--print-hashes", metavar="PIN", nargs="?", const=_PIN, default=None,
                    help="print each asset's sha256 at PIN (default: the current pin) "
                         "and exit — the pin-advance workflow")
    args = ap.parse_args(argv)
    if args.print_hashes:
        print_hashes(args.print_hashes)
        return 0
    if not args.rules_dir:
        ap.error("--rules-dir is required (unless --print-hashes)")
    res = fetch(args.rules_dir, assets=args.assets, force=args.force)
    import json
    json.dump(res, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
