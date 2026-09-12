"""``dxdfir stix`` — the exchange verbs (stdlib argparse; the Go front-end passes
argv through to ``python -m get_sybers_dxdfir.stix`` verbatim).

    dxdfir stix export --hits detections.jsonl [--bundle piiat.json] --out bundle.json [--push]
    dxdfir stix pull --out cti.ndjson [--since 2026-01-01T00:00:00Z]        # OpenCTI -> cti-* copy
    dxdfir stix sightings --alerts alerts.json --out sightings.json [--push]  # matches -> OpenCTI

Exit codes: 0 done (and pushed, if asked); 1 the bundle failed validation or a
push or pull was refused; 2 bad input / missing configuration.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import export as _export
from .config import load_config
from .cti import run_pull, run_sightings
from .objects import TLP_LEVELS
from .opencti import DEFAULT_PAGE_SIZE

PROG = "python -m get_sybers_dxdfir.stix"


def _err(message: str) -> None:
    sys.stderr.write(message + "\n")


def _cmd_export(args: argparse.Namespace) -> None:
    """Export detections as STIX 2.1 sightings + indicators (`indicates` -> MITRE's own
    ATT&CK attack-pattern ids), merge PIIAT bundles through, write the bundle, optionally push it.
    """
    if not args.hits and not args.bundle:
        _err("nothing to export: give --hits and/or --bundle")
        raise SystemExit(2)
    try:
        cfg = load_config(str(args.config) if args.config else None, case_id=args.case, tlp=args.tlp,
                          out=str(args.out) if args.out else None,
                          rules_dir=str(args.rules_dir) if args.rules_dir else None,
                          push=True if args.push else None)
    except (OSError, ValueError) as e:
        _err(f"bad config: {e}")
        raise SystemExit(2) from None
    if cfg.push and not (cfg.opencti_url and cfg.opencti_token):
        _err("--push needs the OpenCTI endpoint AND token: set $DXDFIR_OPENCTI_URL and "
             "$DXDFIR_OPENCTI_TOKEN (or opencti.url / opencti.token in --config).")
        raise SystemExit(2)
    try:
        summary, bundle_doc = _export.run_export(
            cfg, [str(p) for p in args.hits or []], [str(p) for p in args.bundle or []])
    except (OSError, ValueError) as e:
        _err(f"export failed: {e}")
        raise SystemExit(2) from None

    indent = None if args.compact else 2
    to_stdout = not cfg.out and summary["ok"]
    if to_stdout:                       # the bundle IS the output; the summary goes to stderr
        sys.stdout.write(json.dumps(bundle_doc, indent=indent, ensure_ascii=False, default=str) + "\n")
        sys.stderr.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    else:
        sys.stdout.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    if not summary["ok"]:
        for problem in summary["validation"]["errors"]:
            _err(f"   • {problem}")
        if summary.get("push") and not summary["push"]["ok"]:
            _err(f"   • {summary['push']['message']}")
        raise SystemExit(1)


def _cmd_behaviour_sightings(args: argparse.Namespace) -> None:
    """Join the detection lanes to the CAR entities they touch and emit each as a
    STIX 2.1 Sighting of the ATT&CK attack-pattern over the matched CAR row's
    spindle-identified observed-data — the behaviour timeline as the primary axis.
    """
    from . import behaviour as _behaviour
    from .objects import DEFAULT_PRODUCER
    if not args.detections.is_dir():
        _err(f"--detections is not a directory: {args.detections}")
        raise SystemExit(2)
    try:
        summary, bundle_doc = _behaviour.run_behaviour(
            car_paths=[str(p) for p in args.car], detections_dir=str(args.detections), case_id=args.case,
            out=str(args.out) if args.out else None, producer=args.producer or DEFAULT_PRODUCER,
            tlp=args.tlp, attack_index=str(args.attack_index) if args.attack_index else None)
    except (OSError, ValueError) as e:
        _err(f"behaviour-sightings failed: {e}")
        raise SystemExit(2) from None

    indent = None if args.compact else 2
    to_stdout = not args.out and summary["ok"]
    if to_stdout:
        sys.stdout.write(json.dumps(bundle_doc, indent=indent, ensure_ascii=False, default=str) + "\n")
        sys.stderr.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    else:
        sys.stdout.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    if not summary["ok"]:
        for problem in summary["validation"]["errors"]:
            _err(f"   • {problem}")
        raise SystemExit(1)


def _cmd_pull(args: argparse.Namespace) -> None:
    """Pull OpenCTI's STIX 2.1 indicators and write the cti-* copy that Elastic's
    indicator-match rule reads (atomics under threat.indicator.*), as _bulk lines keyed
    on the STIX id. Endpoint/token from $DXDFIR_OPENCTI_URL / $DXDFIR_OPENCTI_TOKEN or the
    config file — never flags.
    """
    try:
        cfg = load_config(str(args.config) if args.config else None, cti_index=args.index)
    except (OSError, ValueError) as e:
        _err(f"bad config: {e}")
        raise SystemExit(2) from None
    if not args.from_bundle and not (cfg.opencti_url and cfg.opencti_token):
        _err("pull needs the OpenCTI endpoint AND token: set $DXDFIR_OPENCTI_URL and "
             "$DXDFIR_OPENCTI_TOKEN (or opencti.url / opencti.token in --config) — or give "
             "--from-bundle to normalise an already-pulled bundle offline.")
        raise SystemExit(2)
    try:
        summary, lines = run_pull(
            cfg, out=str(args.out) if args.out else None,
            bundle_out=str(args.bundle_out) if args.bundle_out else None,
            from_bundle=str(args.from_bundle) if args.from_bundle else None, since=args.since,
            page_size=args.page_size, max_pages=args.max_pages)
    except (OSError, ValueError) as e:
        _err(f"pull failed: {e}")
        raise SystemExit(2) from None

    indent = None if args.compact else 2
    if not args.out and summary["ok"]:  # the bulk lines ARE the output; the summary goes to stderr
        sys.stdout.write("".join(line + "\n" for line in lines))
        sys.stderr.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    else:
        sys.stdout.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    if not summary["ok"]:
        for problem in summary["validation"]["errors"]:
            _err(f"   • {problem}")
        if summary.get("pull") and not summary["pull"].get("ok", True):
            _err(f"   • {summary['pull']['message']}")
        raise SystemExit(1)


def _cmd_sightings(args: argparse.Namespace) -> None:
    """Turn indicator-match alerts into STIX 2.1 sightings of the OpenCTI indicators they
    matched (sighting_of_ref = the platform's own indicator id), write the bundle,
    optionally push it back.
    """
    if not args.alerts:
        _err("nothing to sight: give --alerts")
        raise SystemExit(2)
    try:
        cfg = load_config(str(args.config) if args.config else None, case_id=args.case, tlp=args.tlp,
                          out=str(args.out) if args.out else None, push=True if args.push else None)
    except (OSError, ValueError) as e:
        _err(f"bad config: {e}")
        raise SystemExit(2) from None
    if cfg.push and not (cfg.opencti_url and cfg.opencti_token):
        _err("--push needs the OpenCTI endpoint AND token: set $DXDFIR_OPENCTI_URL and "
             "$DXDFIR_OPENCTI_TOKEN (or opencti.url / opencti.token in --config).")
        raise SystemExit(2)
    try:
        summary, bundle_doc = run_sightings(cfg, [str(p) for p in args.alerts])
    except (OSError, ValueError) as e:
        _err(f"sightings failed: {e}")
        raise SystemExit(2) from None

    indent = None if args.compact else 2
    to_stdout = not cfg.out and summary["ok"]
    if to_stdout:                       # the bundle IS the output; the summary goes to stderr
        sys.stdout.write(json.dumps(bundle_doc, indent=indent, ensure_ascii=False, default=str) + "\n")
        sys.stderr.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    else:
        sys.stdout.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    if not summary["ok"]:
        for problem in summary["validation"]["errors"]:
            _err(f"   • {problem}")
        if summary.get("push") and not summary["push"]["ok"]:
            _err(f"   • {summary['push']['message']}")
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="STIX 2.1 exchange — detections as sightings/indicators, PIIAT bundles "
                    "passed through, optional OpenCTI push.")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser(
        "export",
        help="Export detections as STIX 2.1 sightings + indicators, merge PIIAT bundles "
             "through, write the bundle, optionally push it.",
        description=_cmd_export.__doc__)
    p.add_argument("--hits", action="append", type=Path, metavar="<path>",
                   help="Detection hits: `dxdfir detect --jsonl-out` JSONL, an Elasticsearch "
                        "_search response, or alert / car-detections documents (repeatable).")
    p.add_argument("--bundle", action="append", type=Path, metavar="<path>",
                   help="STIX 2.1 bundle(s) to pass through unchanged, e.g. PIIAT's projection (repeatable).")
    p.add_argument("--out", type=Path, metavar="<path>",
                   help="Write the bundle here (default: config `out`, else stdout).")
    p.add_argument("--config", type=Path, metavar="<path>", help="JSON/YAML config file (see stix/README.md).")
    p.add_argument("--case", metavar="<str>", help="Case id scoping the observation ids (default: the hits' run id).")
    p.add_argument("--tlp", metavar="<str>",
                   help="TLP marking on exported objects: " + "|".join(TLP_LEVELS) + "|none.")
    p.add_argument("--rules-dir", type=Path, metavar="<path>",
                   help="Rules-as-code directory (default: the package's own detect/rules): an indicator's pattern is "
                        "the rule's query, its pattern_type the language; a hit whose rule has no body is "
                        "skipped and counted.")
    p.add_argument("--push", action="store_true",
                   help="Also push to OpenCTI (endpoint/token from $DXDFIR_OPENCTI_URL / $DXDFIR_OPENCTI_TOKEN "
                        "or the config file — never flags).")
    p.add_argument("--compact", action="store_true", help="Single-line JSON output instead of indented.")
    p.set_defaults(func=_cmd_export)

    p = sub.add_parser(
        "behaviour-sightings",
        help="Join the detection lanes to the CAR entities they touch and emit each as a "
             "STIX 2.1 Sighting over the matched CAR row's observed-data.",
        description=_cmd_behaviour_sightings.__doc__)
    p.add_argument("--car", action="append", type=Path, required=True, metavar="<path>",
                   help="A source's car.db, or a tree to walk for every car.db (repeatable). The "
                        "finished CAR stores the detections are joined to. [required]")
    p.add_argument("--detections", type=Path, required=True, metavar="<path>",
                   help="The detection-lane output dir (its suricata/ hayabusa/ yara/ subdirs), "
                        "e.g. data_store/processed/signatures. [required]")
    p.add_argument("--out", type=Path, metavar="<path>", help="Write the bundle here (default: stdout).")
    p.add_argument("--case", required=True, metavar="<str>",
                   help="Case id scoping the observation/sighting ids. [required]")
    p.add_argument("--tlp", metavar="<str>",
                   help="TLP marking on exported objects: " + "|".join(TLP_LEVELS) + "|none.")
    p.add_argument("--producer", metavar="<str>", help="Producer identity name (default: DX_DFIR).")
    p.add_argument("--attack-index", type=Path, metavar="<path>",
                   help="ATT&CK index / STIX bundle (default: the committed index).")
    p.add_argument("--compact", action="store_true", help="Single-line JSON output instead of indented.")
    p.set_defaults(func=_cmd_behaviour_sightings)

    p = sub.add_parser(
        "pull",
        help="Pull OpenCTI's STIX 2.1 indicators and write the cti-* copy that Elastic's "
             "indicator-match rule reads, as _bulk lines keyed on the STIX id.",
        description=_cmd_pull.__doc__)
    p.add_argument("--out", type=Path, metavar="<path>",
                   help="Write the cti-* copy as Elasticsearch _bulk lines (NDJSON) here (default: stdout).")
    p.add_argument("--bundle-out", type=Path, metavar="<path>",
                   help="Also keep the pulled STIX 2.1 indicator bundle here (re-normalise it later with --from-bundle).")
    p.add_argument("--from-bundle", type=Path, metavar="<path>",
                   help="Normalise an already-pulled STIX bundle instead of contacting OpenCTI (no endpoint/token needed).")
    p.add_argument("--index", metavar="<str>",
                   help="The cti-* index the bulk lines target (default: config cti.index / $DXDFIR_CTI_INDEX, else cti-opencti).")
    p.add_argument("--since", metavar="<str>",
                   help="Incremental: only indicators modified after this timestamp (e.g. 2026-01-01T00:00:00Z).")
    p.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE, metavar="<int>",
                   help=f"Indicators per GraphQL page. [default: {DEFAULT_PAGE_SIZE}]")
    p.add_argument("--max-pages", type=int, metavar="<int>", help="Stop after this many pages (safety valve).")
    p.add_argument("--config", type=Path, metavar="<path>", help="JSON/YAML config file (see stix/README.md).")
    p.add_argument("--compact", action="store_true", help="Single-line JSON summary instead of indented.")
    p.set_defaults(func=_cmd_pull)

    p = sub.add_parser(
        "sightings",
        help="Turn indicator-match alerts into STIX 2.1 sightings of the OpenCTI indicators "
             "they matched, write the bundle, optionally push it back.",
        description=_cmd_sightings.__doc__)
    p.add_argument("--alerts", action="append", type=Path, metavar="<path>",
                   help="Indicator-match alerts: an Elasticsearch _search response over .alerts-security.alerts-*, "
                        "a JSON array, one document, or JSON Lines (repeatable).")
    p.add_argument("--out", type=Path, metavar="<path>",
                   help="Write the sightings bundle here (default: config `out`, else stdout).")
    p.add_argument("--config", type=Path, metavar="<path>", help="JSON/YAML config file (see stix/README.md).")
    p.add_argument("--case", metavar="<str>",
                   help="Case id scoping the sighting ids (default: the alerts' rule execution id).")
    p.add_argument("--tlp", metavar="<str>",
                   help="TLP marking on exported objects: " + "|".join(TLP_LEVELS) + "|none.")
    p.add_argument("--push", action="store_true",
                   help="Also push to OpenCTI (endpoint/token from $DXDFIR_OPENCTI_URL / $DXDFIR_OPENCTI_TOKEN "
                        "or the config file — never flags).")
    p.add_argument("--compact", action="store_true", help="Single-line JSON output instead of indented.")
    p.set_defaults(func=_cmd_sightings)
    return parser


def main(argv: list[str] | None = None) -> None:
    """Parse argv (default: ``sys.argv[1:]``) and run the chosen verb.

    Raises SystemExit on any non-zero outcome; usage errors are argparse's
    exit 2, ``--help`` exits 0. With no arguments at all the help is printed
    (stdout) and the exit code is 2 — exactly what the retired Typer app did.
    """
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    if getattr(args, "func", None) is None:     # bare `dxdfir stix`: help, then exit 2
        parser.print_help()
        raise SystemExit(2)
    args.func(args)


if __name__ == "__main__":
    main()
