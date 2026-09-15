#!/usr/bin/python3
"""Byakugan container ENTRYPOINT — ONE binary, three operations, selected by the
first argument (the DX_DFIR mitrecar lane / the dxdfir_byakugan ansible role supplies
it), mirroring the lane's own dispatch:

    byakugan timeline <car_dir> [flags]   -> the unified, time-ordered CAR timeline
                                             (byakugan.timeline)
    byakugan car-vocab                    -> {object: [car_actions]} JSON, the
                                             canonical car_action vocabulary the
                                             verify-car gate checks values against
    byakugan <build flags...>             -> materialise CAR from processed
                                             evidence (byakugan.pipeline, the
                                             default: --in/--out or --batch)

This is `dxdfir`'s ENTIRE interaction surface with the external Byakugan engine:
the engine is cloned at the pinned sources.yml and baked into this image at
build time, so nothing about it leaks into the DX_DFIR checkout. The engine
reconstructs its object model live from its own nested submodules and resolves
that model RELATIVE TO ITS PACKAGE, so it runs from the baked source tree
(PYTHONPATH=/opt/byakugan); its Go parse binary is BYAKUGAN_PARSE_BIN — both are
baked as image ENV, so this binary needs no arguments of its own.

`car-vocab` is why verify-car no longer imports the engine on the analyst host:
the object model stays entirely inside this container, and the host gate reads
the vocabulary as JSON over stdout.
"""
import json
import sys


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "timeline":
        from byakugan.timeline import main as timeline_main
        return timeline_main(argv[1:])
    if argv and argv[0] == "car-vocab":
        from byakugan import carmodel
        model = carmodel.load()
        json.dump({obj: sorted(model[obj].get("actions", [])) for obj in model},
                  sys.stdout)
        sys.stdout.write("\n")
        return 0
    from byakugan.pipeline import main as build_main
    return build_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
