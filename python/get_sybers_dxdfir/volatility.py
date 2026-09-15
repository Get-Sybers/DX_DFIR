"""Volatility 3 processor — memory images -> per-plugin JSON Lines.

Drive the standalone **PIIAT-Mem** tool (the vendored ``third_party/piiat-mem``
submodule) over each memory image, one CLI invocation per image, and collect the
raw per-plugin JSON Lines it writes for the CAR lane. PIIAT-Mem owns the
Volatility runner, the ``jsonl_dfir`` renderer, the custom plugins and the
hardened container; this module is only its *automation*: it discovers images,
decides (per plugin) what still needs running, invokes ``python -m piiat_mem``,
and emits the machine-readable summary Ansible gates on. We consume PIIAT-Mem
through its public CLI — never by importing its internals.

The tool writes ``<dest>/plugins/<plugin>.jsonl`` (one flat JSON object per
TreeGrid node); we pass ``--no-timeline`` because the pipeline builds its own
timeline downstream — the CAR lane (``dxdfir build-car``) normalises these
per-plugin files, and the file name carries the plugin.

⚠️ SYMBOLS. Windows plugins resolve the kernel against ISF symbol tables Volatility
fetches from the symbol servers on first use — that needs outbound network. On an
isolated host, pre-seed ``symbols_dir`` (VOLATILITY_SYMBOLS) or the Windows plugins
error; format-agnostic plugins (banners.Banners) work without symbols.

Idempotent: a plugin whose ``.jsonl`` output exists and whose first line parses as
JSON is not re-requested (only the still-missing plugins are passed to ``--plugins``;
an image with none missing is skipped entirely). Empty/failed plugin outputs are
removed (not treated as done). Emits a JSON summary on stdout for an honest
``changed_when`` (``processed > 0`` — processed counts plugin OUTPUTS).

    python -m get_sybers_dxdfir.volatility --memory-dir RAW/memory --out-dir PROCESSED/volatility \
        --symbols-dir DEPENDENCIES/volatility3-symbols
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

_IMAGE = "get-sybers/volatility:latest"

# The vendored PIIAT-Mem submodule — invoked as `python -m piiat_mem`. Its path is
# put on the child's PYTHONPATH (not this process's import graph): we use the tool,
# we don't import it.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PIIAT_MEM_DIR = os.path.join(_REPO_ROOT, "third_party", "piiat-mem")

# The CAR plugin set, by PIIAT-Mem's PUBLIC plugin names (the tool's CLI interface,
# like `windows.pslist`). banners.Banners runs first — format-agnostic, it sanity-
# checks the image without symbols. `--plugins` selects exactly this set.
#   -> Car* comments show the downstream CAR artefact each maps to.
DEFAULT_PLUGINS = [
    "banners.Banners",
    "windows.info",
    "windows.piiat.processes",        # -> CarProcess (psscan; token Sid/User/LogonId)
    "windows.pslist",
    "windows.pstree",
    "windows.piiat.modules",          # -> CarModule (OwnerOffset: definitive link)
    "windows.modules",                # -> CarDriver
    "windows.piiat.network",          # -> CarFlow / socket (OwnerOffset)
    "windows.netstat",                # -> CarFlow (second view)
    "windows.piiat.sessions",         # -> CarUserSession (token LUID logons)
    "windows.filescan",               # -> CarFile (ownerless scan)
    "windows.piiat.files",            # -> CarFile (handle-enumerated, WITH owners)
    "windows.svcscan",                # -> CarService
    "windows.piiat.threads",          # -> CarThread (OwnerOffset + stacks)
    "windows.piiat.registry",         # -> CarRegistry
    "windows.piiat.access",           # -> CarProcess access events (handle-observed)
    "windows.mftscan.MFTScan",        # -> CarFile (NTFS times from resident $MFT)
    "windows.malfind",
]

_MEMORY_EXTS = (
    ".raw", ".mem", ".dmp", ".lime", ".vmem",
    ".bin", ".dump", ".vmsn", ".crash",
)


def is_memory_image(name: str) -> bool:
    """Match by common memory-dump extensions plus the M57 corpus '*dramimage'."""
    low = name.lower()
    return low.endswith(_MEMORY_EXTS) or low.endswith("dramimage")


def discover(memory_dir: str) -> list[str]:
    """Every memory image under memory_dir (recursed), sorted, absolute."""
    found = []
    for root, _dirs, files in os.walk(memory_dir):
        for name in files:
            if is_memory_image(name):
                found.append(os.path.join(root, name))
    return sorted(found)


def clean_name(rel: str) -> str:
    """Output-folder name from a path relative to the memory dir (dirs+space folded),
    so two corpora sharing a basename keep distinct output."""
    return rel.replace("/", "_").replace(" ", "_")


def _valid_jsonl(path: str) -> bool:
    """Non-empty and first line parses as JSON — the shell's done/valid guard."""
    try:
        if os.path.getsize(path) <= 0:
            return False
        with open(path, encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
    except OSError:
        return False
    if not first.strip():
        return False
    try:
        json.loads(first)
        return True
    except json.JSONDecodeError:
        return False


def _out_path(dest: str, plugin: str) -> str:
    """Where PIIAT-Mem writes a plugin's JSONL: <dest>/plugins/<plugin>.jsonl."""
    return os.path.join(dest, "plugins", f"{plugin}.jsonl")


def _tail(path: str, n: int) -> str:
    """Last ``n`` lines of a text file, or "" if unreadable — for diagnostics."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return ""
    return "".join(lines[-n:]).rstrip()


def _plugin_done(dest: str, plugin: str) -> bool:
    """A plugin is done if valid output sits at the tool's path OR the legacy flat
    ``<dest>/<plugin>.jsonl`` an earlier version of this lane wrote — so upgrading
    doesn't re-run every corpus's (expensive) container sweep."""
    return _valid_jsonl(_out_path(dest, plugin)) or _valid_jsonl(os.path.join(dest, f"{plugin}.jsonl"))


def _run_piiat_mem(img, dest, plugins, symbols_dir, image, native, symbols_online) -> None:
    """One `python -m piiat_mem` invocation for `plugins` over `img` into `dest`.
    The tool's stdout+stderr (its progress) are STREAMED to ``<dest>/piiat_mem.log``
    rather than captured in memory — a big or verbose run then stays bounded and
    debuggable, and our own stdout stays a clean summary. We do NOT gate on the
    exit code — rc=1 just means every plugin produced nothing (the retryable
    Windows-without-symbols case); success is judged per file by `_valid_jsonl`."""
    py = native or sys.executable
    argv = [py, "-m", "piiat_mem",
            "-f", img, "-o", dest,
            "--plugins", ",".join(plugins),   # bare commas: the CLI splits on "," with no strip
            "--symbols", symbols_dir,          # always pass ours — else the tool uses a throwaway temp dir
            "--image", image,
            "--no-timeline"]                   # raw per-plugin JSONL only; we timeline downstream
    if symbols_online:
        argv.append("--symbols-online")
    if native:
        argv.append("--native")
    env = dict(os.environ)
    env["PYTHONPATH"] = _PIIAT_MEM_DIR + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    with open(os.path.join(dest, "piiat_mem.log"), "wb") as log:
        subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, env=env, check=False)


def process(memory_dir, out_dir, symbols_dir, image=_IMAGE, plugins=None,
            native=None, force=False, symbols_online=False) -> dict:
    """Run the plugin set over every image under memory_dir by driving the PIIAT-Mem
    CLI. Idempotent per plugin. ``native`` is a native-python path (falsy -> the
    hardened container). ``symbols_online`` allows the container network for ISF
    symbol fetch (the ONE legitimate network need); default is fully offline.
    """
    memory_dir = os.path.realpath(memory_dir)
    out_dir = os.path.realpath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(symbols_dir, exist_ok=True)
    try:
        # the container's uid-2000 volatility caches fetched symbols here
        os.chmod(symbols_dir, 0o777)
    except OSError:
        pass
    plugins = plugins or DEFAULT_PLUGINS
    symbols_dir = os.path.realpath(symbols_dir)
    # Fail fast when running in-container: if the hardened image is absent or
    # unhardened, PIIAT-Mem's `docker run` would fail silently into its log and
    # every plugin would land as "empty" with no visible cause upstream.
    if not native:
        from . import images as _images
        try:
            _images.require(image)
        except RuntimeError as exc:
            return {
                "tool": "volatility", "memory_dir": memory_dir, "out_dir": out_dir,
                "images": 0, "plugins": len(plugins), "processed": 0, "skipped": 0,
                "failed": 0, "results": [], "error": str(exc),
            }
    images_found = discover(memory_dir)

    processed, skipped, failed, results = 0, 0, 0, []
    for img in images_found:
        rel = os.path.relpath(img, memory_dir)
        dest = os.path.join(out_dir, clean_name(rel))
        os.makedirs(dest, exist_ok=True)
        per_image = {"image": rel, "produced": [], "empty": []}

        todo = []
        for plugin in plugins:
            if not force and _plugin_done(dest, plugin):
                skipped += 1
            else:
                todo.append(plugin)

        if todo:  # never invoke with an empty --plugins (the CLI would run its DEFAULT set)
            _run_piiat_mem(img, dest, todo, symbols_dir, image, native, symbols_online)
            for plugin in todo:
                out_path = _out_path(dest, plugin)
                if _valid_jsonl(out_path):
                    processed += 1
                    per_image["produced"].append(plugin)
                else:
                    if os.path.exists(out_path):
                        os.remove(out_path)
                    failed += 1
                    per_image["empty"].append(plugin)
        results.append(per_image)

    summary = {
        "tool": "volatility",
        "memory_dir": memory_dir,
        "out_dir": out_dir,
        "images": len(images_found),
        "plugins": len(plugins),
        "processed": processed,
        "skipped": skipped,
        "failed": failed,
        "results": results,
    }
    # When nothing produced output for any image, the real cause is buried in
    # PIIAT-Mem's per-image log (its docker-run stdout/stderr goes there). Surface
    # the tail so Ansible/CLI callers see WHY, not just that everything was empty.
    if images_found and processed == 0 and failed > 0:
        tails = []
        for per_image in results:
            log_path = os.path.join(out_dir, clean_name(per_image["image"]), "piiat_mem.log")
            tail = _tail(log_path, 20)
            if tail:
                tails.append(f"--- {per_image['image']} (last lines of piiat_mem.log) ---\n{tail}")
        if tails:
            summary["diagnostics"] = "\n".join(tails)
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.volatility",
        description="memory images -> Volatility 3 per-plugin JSON Lines (via the PIIAT-Mem CLI)",
    )
    ap.add_argument("--memory-dir", required=True, help="directory tree of memory images")
    ap.add_argument("--out-dir", required=True, help="output dir; one folder per image")
    ap.add_argument("--symbols-dir", required=True, help="Volatility symbol cache (VOLATILITY_SYMBOLS)")
    ap.add_argument("--image", default=_IMAGE, help="Volatility 3 container image")
    ap.add_argument("--vol-native", default=None,
                    help="UNCONFINED escape hatch: a native python (with volatility3) that "
                         "parses the memory image directly ON THE HOST — no container, no "
                         "cap-drop/read-only/network-none, and the hardened-image guard is "
                         "skipped. Requires --accept-unconfined.")
    ap.add_argument("--accept-unconfined", action="store_true",
                    help="acknowledge that --vol-native runs the tool unconfined on the host")
    ap.add_argument("--plugins", default=None, help="comma-separated plugin override (default: the CAR set)")
    ap.add_argument("--force", action="store_true", help="rerun plugins that already have valid output")
    ap.add_argument("--symbols-online", action="store_true",
                    help="allow the container network access for ISF symbol fetch — the "
                         "one legitimate network need; default is fully offline "
                         "(pre-seed --symbols-dir instead)")
    args = ap.parse_args(argv)

    # --vol-native bypasses the hardened container (the tool parses attacker memory
    # on the host, unconfined). Gate it behind an explicit acknowledgement so it can
    # never be reached by accident (e.g. a stray extra-var); the container is the
    # only supported path otherwise.
    if args.vol_native and not args.accept_unconfined:
        sys.stderr.write(
            "refusing --vol-native: it runs Volatility 3 UNCONFINED on the host "
            "(no cap-drop/read-only/network-none, skips the hardened-image guard). "
            "Re-run without it to use the hardened container, or pass "
            "--accept-unconfined to override.\n")
        return 2
    if args.vol_native:
        sys.stderr.write(
            "WARNING: --vol-native — parsing memory images UNCONFINED on the host, "
            "outside the hardened container.\n")

    plugins = [p.strip() for p in args.plugins.split(",") if p.strip()] if args.plugins else None
    summary = process(
        args.memory_dir, args.out_dir, args.symbols_dir,
        image=args.image, plugins=plugins, native=args.vol_native, force=args.force,
        symbols_online=args.symbols_online,
    )
    # Diagnostics (image-guard error or piiat_mem.log tails) go to stderr so a
    # non-zero rc surfaces the REAL cause — Ansible currently reports stderr="".
    if summary.get("error"):
        sys.stderr.write(summary["error"] + "\n")
    if summary.get("diagnostics"):
        sys.stderr.write(summary["diagnostics"] + "\n")
    json.dump(summary, sys.stdout)
    sys.stdout.write("\n")
    # Fail only when the run produced nothing AND nothing was already done: inputs
    # that can never produce output (e.g. a Volatility plugin unsupported by this
    # image) are retried on every run, and must not flip an otherwise-complete,
    # idempotent re-run (processed=0, everything else skipped) into a failure.
    if summary.get("error"):
        return 1
    return 1 if summary["failed"] and not summary["processed"] and not summary["skipped"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
