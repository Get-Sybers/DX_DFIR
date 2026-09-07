"""CLI for the signatures processors: python -m get_sybers_dxdfir.signatures ..."""
from __future__ import annotations

import argparse
import json
import sys

from . import LANES, process


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.signatures",
        description="YARA / Suricata / Hayabusa detection lanes -> JSONL",
    )
    ap.add_argument("--output-dir", required=True, help="base output dir (one <lane>/ per lane)")
    ap.add_argument("--repo-root", required=True, help="repo root (lane input/dep defaults hang off it)")
    ap.add_argument("--only", action="append", choices=list(LANES),
                    help="run only this lane (repeatable); default all")
    ap.add_argument("--fetch", action="store_true",
                    help="provision rules when online: the yara lane fetches the pinned "
                         "DetectRaptor ruleset when it has no rules yet (see "
                         "signatures/detectraptor.py); the other lanes still record a "
                         "note when their deps are missing")
    ap.add_argument("--force", action="store_true", help="regenerate outputs that already exist")
    # Hayabusa disk-image staging (shared with the evtx processor's stage).
    ap.add_argument("--stage-dir", help="where disk-image EVTX extractions land for the "
                    "hayabusa lane (default: the evtx processor's stage, "
                    "data_store/processed/windows_logs/_extracted_evtx — already-staged "
                    "images are reused, not re-extracted).")
    ap.add_argument("--vss", action="store_true",
                    help="also extract from Volume Shadow Copies when staging disk images")
    # YARA source selection (the shell lane's YARA_SOURCES).
    ap.add_argument("--yara-sources",
                    help="comma list of yara sources to run: files,disk,memory "
                         "(default all three). disk needs /dev/fuse + ewfmount/ntfs-3g "
                         "on the host; memory needs the Volatility 3 image + symbols.")
    # Suricata tuning (HOME_NET is Suricata's primary tuning variable: rule direction
    # keys off $HOME_NET/$EXTERNAL_NET).
    ap.add_argument("--home-net", help="Suricata HOME_NET, e.g. '[10.0.0.0/8,192.168.0.0/16]'. "
                    "Applies to every pcap; EXTERNAL_NET defaults to its complement.")
    ap.add_argument("--external-net", help="Suricata EXTERNAL_NET (default: !$HOME_NET).")
    ap.add_argument("--auto-home-net", action="store_true",
                    help="accepted for compatibility; per-pcap HOME_NET auto-detection is "
                         "now the default whenever neither --home-net nor a tuning-file "
                         "entry covers a pcap (see --tuning-file).")
    ap.add_argument("--suricata-set", action="append", metavar="KEY=VALUE",
                    help="raw Suricata --set tuning entry, repeatable (e.g. "
                         "vars.port-groups.HTTP_PORTS=8080).")
    ap.add_argument("--tuning-file",
                    help="per-pcap Suricata tuning file (INI template; default "
                         "data_store/dependencies/suricata-tuning.conf). Written as an "
                         "editable template on first run; while template-only or "
                         "invalid, the automatable vars are auto-detected per pcap and "
                         "recorded into it. Tuning resets per pcap.")
    ap.add_argument("--pcap-dir",
                    help="the directory of captures the suricata lane replays "
                         "(default data_store/raw/pcaps). A collection scopes this to "
                         "its sorted pcaps/ subdir (dxdfir_signatures_pcap_dir); without "
                         "it a sorted collection's captures never reach suricata.")
    args = ap.parse_args(argv)

    lanes = tuple(args.only) if args.only else LANES
    config = {"suricata": {
        "home_net": args.home_net,
        "external_net": args.external_net,
        "auto_home_net": args.auto_home_net,
        "extra_sets": args.suricata_set or [],
        "tuning_file": args.tuning_file,
        "pcap_dir": args.pcap_dir,
    }, "hayabusa": {
        "stage_dir": args.stage_dir,
        "vss": args.vss,
    }}
    if args.yara_sources:
        srcs = tuple(s.strip() for s in args.yara_sources.split(",") if s.strip())
        bad = [s for s in srcs if s not in ("files", "disk", "memory")]
        if bad:
            ap.error(f"--yara-sources: unknown source(s) {','.join(bad)} "
                     "(choose from files,disk,memory)")
        config["yara"] = {"sources": srcs}
    summary = process(
        args.output_dir, lanes, repo_root=args.repo_root,
        fetch=args.fetch, force=args.force, config=config,
    )
    json.dump(summary, sys.stdout)
    sys.stdout.write("\n")
    # Fail only when the run produced nothing AND nothing was already done: inputs
    # that can never produce output (e.g. a Volatility plugin unsupported by this
    # image) are retried on every run, and must not flip an otherwise-complete,
    # idempotent re-run (processed=0, everything else skipped) into a failure.
    return 1 if summary["failed"] and not summary["processed"] and not summary["skipped"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
