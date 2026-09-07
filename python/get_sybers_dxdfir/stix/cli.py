"""``dxdfir stix`` — the exchange verbs (Typer sub-app registered by ``cli.py``).

    dxdfir stix export --hits detections.jsonl [--bundle piiat.json] --out bundle.json [--push]
    dxdfir stix pull --out cti.ndjson [--since 2026-01-01T00:00:00Z]        # OpenCTI -> cti-* copy
    dxdfir stix sightings --alerts alerts.json --out sightings.json [--push]  # matches -> OpenCTI

Exit codes: 0 done (and pushed, if asked); 1 the bundle failed validation or a
push or pull was refused; 2 bad input / missing configuration.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

from . import export as _export
from .config import load_config
from .cti import run_pull, run_sightings
from .objects import TLP_LEVELS
from .opencti import DEFAULT_PAGE_SIZE

app = typer.Typer(
    help="STIX 2.1 exchange — detections as sightings/indicators, PIIAT bundles passed through, optional OpenCTI push.",
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.command()
def export(
    hits: list[Path] = typer.Option(
        None, "--hits", help="Detection hits: `dxdfir detect --jsonl-out` JSONL, an Elasticsearch "
                             "_search response, or alert / car-detections documents (repeatable)."),
    bundle: list[Path] = typer.Option(
        None, "--bundle", help="STIX 2.1 bundle(s) to pass through unchanged, e.g. PIIAT's projection (repeatable)."),
    out: Path = typer.Option(None, "--out", help="Write the bundle here (default: config `out`, else stdout)."),
    config: Path = typer.Option(None, "--config", help="JSON/YAML config file (see stix/README.md)."),
    case: str = typer.Option(None, "--case", help="Case id scoping the observation ids (default: the hits' run id)."),
    tlp: str = typer.Option(None, "--tlp", help="TLP marking on exported objects: " + "|".join(TLP_LEVELS) + "|none."),
    rules_dir: Path = typer.Option(
        None, "--rules-dir",
        help="Rules-as-code directory (default: the package's own detect/rules): an indicator's pattern is "
             "the rule's query, its pattern_type the language; a hit whose rule has no body is skipped and counted."),
    push: bool = typer.Option(
        False, "--push",
        help="Also push to OpenCTI (endpoint/token from $DXDFIR_OPENCTI_URL / $DXDFIR_OPENCTI_TOKEN "
             "or the config file — never flags)."),
    compact: bool = typer.Option(False, "--compact", help="Single-line JSON output instead of indented."),
) -> None:
    """Export detections as STIX 2.1 sightings + indicators (`indicates` -> MITRE's own
    ATT&CK attack-pattern ids), merge PIIAT bundles through, write the bundle, optionally push it.
    """
    if not hits and not bundle:
        typer.secho("nothing to export: give --hits and/or --bundle", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    try:
        cfg = load_config(str(config) if config else None, case_id=case, tlp=tlp,
                          out=str(out) if out else None, rules_dir=str(rules_dir) if rules_dir else None,
                          push=True if push else None)
    except (OSError, ValueError) as e:
        typer.secho(f"bad config: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    if cfg.push and not (cfg.opencti_url and cfg.opencti_token):
        typer.secho("--push needs the OpenCTI endpoint AND token: set $DXDFIR_OPENCTI_URL and "
                    "$DXDFIR_OPENCTI_TOKEN (or opencti.url / opencti.token in --config).",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    try:
        summary, bundle_doc = _export.run_export(
            cfg, [str(p) for p in hits or []], [str(p) for p in bundle or []])
    except (OSError, ValueError) as e:
        typer.secho(f"export failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None

    indent = None if compact else 2
    to_stdout = not cfg.out and summary["ok"]
    if to_stdout:                       # the bundle IS the output; the summary goes to stderr
        sys.stdout.write(json.dumps(bundle_doc, indent=indent, ensure_ascii=False, default=str) + "\n")
        sys.stderr.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    else:
        sys.stdout.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    if not summary["ok"]:
        for problem in summary["validation"]["errors"]:
            typer.secho(f"   • {problem}", fg=typer.colors.RED, err=True)
        if summary.get("push") and not summary["push"]["ok"]:
            typer.secho(f"   • {summary['push']['message']}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


@app.command(name="behaviour-sightings")
def behaviour_sightings(
    car: list[Path] = typer.Option(
        ..., "--car", help="A source's car.db, or a tree to walk for every car.db (repeatable). The "
                           "finished CAR stores the detections are joined to."),
    detections: Path = typer.Option(
        ..., "--detections", help="The detection-lane output dir (its suricata/ hayabusa/ yara/ subdirs), "
                                  "e.g. data_store/processed/signatures."),
    out: Path = typer.Option(None, "--out", help="Write the bundle here (default: stdout)."),
    case: str = typer.Option(..., "--case", help="Case id scoping the observation/sighting ids."),
    tlp: str = typer.Option(None, "--tlp", help="TLP marking on exported objects: " + "|".join(TLP_LEVELS) + "|none."),
    producer: str = typer.Option(None, "--producer", help="Producer identity name (default: DX_DFIR)."),
    attack_index: Path = typer.Option(
        None, "--attack-index", help="ATT&CK index / STIX bundle (default: the committed index)."),
    compact: bool = typer.Option(False, "--compact", help="Single-line JSON output instead of indented."),
) -> None:
    """Join the detection lanes to the CAR entities they touch and emit each as a
    STIX 2.1 Sighting of the ATT&CK attack-pattern over the matched CAR row's
    spindle-identified observed-data — the behaviour timeline as the primary axis.
    """
    from . import behaviour as _behaviour
    from .objects import DEFAULT_PRODUCER
    if not detections.is_dir():
        typer.secho(f"--detections is not a directory: {detections}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    try:
        summary, bundle_doc = _behaviour.run_behaviour(
            car_paths=[str(p) for p in car], detections_dir=str(detections), case_id=case,
            out=str(out) if out else None, producer=producer or DEFAULT_PRODUCER,
            tlp=tlp, attack_index=str(attack_index) if attack_index else None)
    except (OSError, ValueError) as e:
        typer.secho(f"behaviour-sightings failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None

    indent = None if compact else 2
    to_stdout = not out and summary["ok"]
    if to_stdout:
        sys.stdout.write(json.dumps(bundle_doc, indent=indent, ensure_ascii=False, default=str) + "\n")
        sys.stderr.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    else:
        sys.stdout.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    if not summary["ok"]:
        for problem in summary["validation"]["errors"]:
            typer.secho(f"   • {problem}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


@app.command()
def pull(
    out: Path = typer.Option(
        None, "--out", help="Write the cti-* copy as Elasticsearch _bulk lines (NDJSON) here (default: stdout)."),
    bundle_out: Path = typer.Option(
        None, "--bundle-out",
        help="Also keep the pulled STIX 2.1 indicator bundle here (re-normalise it later with --from-bundle)."),
    from_bundle: Path = typer.Option(
        None, "--from-bundle",
        help="Normalise an already-pulled STIX bundle instead of contacting OpenCTI (no endpoint/token needed)."),
    index: str = typer.Option(
        None, "--index",
        help="The cti-* index the bulk lines target (default: config cti.index / $DXDFIR_CTI_INDEX, else cti-opencti)."),
    since: str = typer.Option(
        None, "--since", help="Incremental: only indicators modified after this timestamp (e.g. 2026-01-01T00:00:00Z)."),
    page_size: int = typer.Option(DEFAULT_PAGE_SIZE, "--page-size", help="Indicators per GraphQL page."),
    max_pages: int = typer.Option(None, "--max-pages", help="Stop after this many pages (safety valve)."),
    config: Path = typer.Option(None, "--config", help="JSON/YAML config file (see stix/README.md)."),
    compact: bool = typer.Option(False, "--compact", help="Single-line JSON summary instead of indented."),
) -> None:
    """Pull OpenCTI's STIX 2.1 indicators and write the cti-* copy that Elastic's
    indicator-match rule reads (atomics under threat.indicator.*), as _bulk lines keyed
    on the STIX id. Endpoint/token from $DXDFIR_OPENCTI_URL / $DXDFIR_OPENCTI_TOKEN or the
    config file — never flags.
    """
    try:
        cfg = load_config(str(config) if config else None, cti_index=index)
    except (OSError, ValueError) as e:
        typer.secho(f"bad config: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    if not from_bundle and not (cfg.opencti_url and cfg.opencti_token):
        typer.secho("pull needs the OpenCTI endpoint AND token: set $DXDFIR_OPENCTI_URL and "
                    "$DXDFIR_OPENCTI_TOKEN (or opencti.url / opencti.token in --config) — or give "
                    "--from-bundle to normalise an already-pulled bundle offline.",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    try:
        summary, lines = run_pull(
            cfg, out=str(out) if out else None, bundle_out=str(bundle_out) if bundle_out else None,
            from_bundle=str(from_bundle) if from_bundle else None, since=since,
            page_size=page_size, max_pages=max_pages)
    except (OSError, ValueError) as e:
        typer.secho(f"pull failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None

    indent = None if compact else 2
    if not out and summary["ok"]:       # the bulk lines ARE the output; the summary goes to stderr
        sys.stdout.write("".join(line + "\n" for line in lines))
        sys.stderr.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    else:
        sys.stdout.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    if not summary["ok"]:
        for problem in summary["validation"]["errors"]:
            typer.secho(f"   • {problem}", fg=typer.colors.RED, err=True)
        if summary.get("pull") and not summary["pull"].get("ok", True):
            typer.secho(f"   • {summary['pull']['message']}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


@app.command()
def sightings(
    alerts: list[Path] = typer.Option(
        None, "--alerts",
        help="Indicator-match alerts: an Elasticsearch _search response over .alerts-security.alerts-*, "
             "a JSON array, one document, or JSON Lines (repeatable)."),
    out: Path = typer.Option(None, "--out", help="Write the sightings bundle here (default: config `out`, else stdout)."),
    config: Path = typer.Option(None, "--config", help="JSON/YAML config file (see stix/README.md)."),
    case: str = typer.Option(None, "--case", help="Case id scoping the sighting ids (default: the alerts' rule execution id)."),
    tlp: str = typer.Option(None, "--tlp", help="TLP marking on exported objects: " + "|".join(TLP_LEVELS) + "|none."),
    push: bool = typer.Option(
        False, "--push",
        help="Also push to OpenCTI (endpoint/token from $DXDFIR_OPENCTI_URL / $DXDFIR_OPENCTI_TOKEN "
             "or the config file — never flags)."),
    compact: bool = typer.Option(False, "--compact", help="Single-line JSON output instead of indented."),
) -> None:
    """Turn indicator-match alerts into STIX 2.1 sightings of the OpenCTI indicators they
    matched (sighting_of_ref = the platform's own indicator id), write the bundle,
    optionally push it back.
    """
    if not alerts:
        typer.secho("nothing to sight: give --alerts", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    try:
        cfg = load_config(str(config) if config else None, case_id=case, tlp=tlp,
                          out=str(out) if out else None, push=True if push else None)
    except (OSError, ValueError) as e:
        typer.secho(f"bad config: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    if cfg.push and not (cfg.opencti_url and cfg.opencti_token):
        typer.secho("--push needs the OpenCTI endpoint AND token: set $DXDFIR_OPENCTI_URL and "
                    "$DXDFIR_OPENCTI_TOKEN (or opencti.url / opencti.token in --config).",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    try:
        summary, bundle_doc = run_sightings(cfg, [str(p) for p in alerts])
    except (OSError, ValueError) as e:
        typer.secho(f"sightings failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None

    indent = None if compact else 2
    to_stdout = not cfg.out and summary["ok"]
    if to_stdout:                       # the bundle IS the output; the summary goes to stderr
        sys.stdout.write(json.dumps(bundle_doc, indent=indent, ensure_ascii=False, default=str) + "\n")
        sys.stderr.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    else:
        sys.stdout.write(json.dumps(summary, indent=indent, ensure_ascii=False, default=str) + "\n")
    if not summary["ok"]:
        for problem in summary["validation"]["errors"]:
            typer.secho(f"   • {problem}", fg=typer.colors.RED, err=True)
        if summary.get("push") and not summary["push"]["ok"]:
            typer.secho(f"   • {summary['push']['message']}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
