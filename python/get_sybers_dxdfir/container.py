"""Shared docker-run construction for the minimal hardened get-sybers/* tool images.

Posture (chosen for strongest resistance to container escape AND a
supply-chain-compromised tool): the images are stripped to the tool itself —
no runtime ansible, no package managers, no pip, no sudo/su, no setuid, uid 0
renamed and locked, tool runs as uid 2000, and NO shell/python beyond what the
tool irreducibly needs (yara's per-file scan loop needs sh; Volatility and
Plaso are python). The tool is the image's ENTRYPOINT.

Every invocation is confined at the runtime — which is what actually contains
both threats, since an attacker with code execution (the premise of a
compromised tool) does not need an on-image shell:

  --cap-drop ALL                 no capabilities (all pcap work is offline)
  --security-opt no-new-privileges
                                 execve can never regain privileges
  --read-only                    immutable root filesystem; the tool may write
                                 only to explicit mounts and tmpfs
  --tmpfs /tmp                   the one always-writable scratch area
  --pids-limit                   caps fork-bomb / parallel-exploit blast radius
  --network none                 no network by default — a compromised tool
                                 cannot exfiltrate or fetch a second stage.
                                 The single exception is Volatility ISF symbol
                                 fetch (``network=True``), an explicit opt-in.

The confinement flags stay pure list builders; run() additionally reads the
group owning each read-only (evidence) mount and --group-add's it, so a
locked-down evidence tree is readable by the image's non-root uid off defaults —
no per-run --user/--group knobs threaded through processing.
"""
from __future__ import annotations

import os

# Base confinement applied to every tool container.
HARDENING_FLAGS = [
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "512",
    "--read-only",
]
# tmpfs mounted read-write on every run (the tool's only rootfs-adjacent scratch).
_BASE_TMPFS = ["--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=1g"]


def run_flags(network: bool = False, tmpfs: tuple = ()) -> list[str]:
    """The confinement flags for one ``docker run``. ``network=True`` keeps the
    default bridge (Volatility symbol fetch); everything else runs with no
    network. ``tmpfs`` adds per-tool writable tmpfs mounts (paths a tool touches
    on the read-only rootfs, e.g. suricata's /var/run)."""
    flags = list(HARDENING_FLAGS) + list(_BASE_TMPFS)
    for spec in tmpfs:
        flags += ["--tmpfs", spec]
    if not network:
        flags += ["--network", "none"]
    return flags


def _mount_group_ids(mounts) -> list[str]:
    """Supplementary gids the container needs to READ its read-only mounts.

    Evidence is bind-mounted read-only and owned by whatever group staged it
    (data_store is root:docker 750 on a locked-down host). The tool runs as the
    image's baked non-root uid, which is not in that group, so it cannot traverse
    the evidence unless granted it. Return the distinct gid of each read-only
    mount's host source for --group-add, so reading evidence works off the mount
    with nothing to configure per run. Read-write (output) mounts are skipped —
    the caller makes those world-writable — as are the root group and any source
    that can't be stat'd (keeps placeholder-path unit tests and absent mounts
    harmless).
    """
    gids: list[str] = []
    for spec in mounts:
        parts = spec.split(":")
        if len(parts) < 3 or parts[-1] != "ro":
            continue
        try:
            gid = str(os.stat(parts[0]).st_gid)
        except OSError:
            continue
        if gid not in gids and gid != "0":
            gids.append(gid)
    return gids


def run(image, after_image=(), *, mounts=(), network=False, tmpfs=(),
        workdir=None, entrypoint=None) -> list[str]:
    """``docker run`` argv for a minimal hardened get-sybers/* image.

    ``after_image`` is appended verbatim after the image name: for a tool-as-
    ENTRYPOINT image these are just the tool's arguments; for an image with no
    ENTRYPOINT (plaso, which has three entry tools) it is the full ``[tool,
    args...]``. ``entrypoint`` overrides the image's baked ENTRYPOINT (e.g. run a
    different baked binary than the image's default). ``workdir`` sets the tool's
    cwd (tools that write housekeeping files to cwd need it pointed at a writable
    mount or /tmp, since the root filesystem is immutable). The tool writes to the
    mounted output dir (read-write) and reads mounted evidence (read-only).
    """
    argv = ["docker", "run", "--rm", *run_flags(network, tmpfs)]
    # Grant the container the group that owns each read-only (evidence) mount, so
    # the image's baked non-root uid can read locked-down evidence (data_store is
    # root:docker 750 on a hardened host) without running as root. Automatic, off
    # the mounts — no per-run --user/--group knobs threaded through processing.
    for gid in _mount_group_ids(mounts):
        argv += ["--group-add", gid]
    if entrypoint:
        argv += ["--entrypoint", entrypoint]
    if workdir:
        argv += ["-w", workdir]
    for mount in mounts:
        argv += ["-v", mount]
    argv += [image, *after_image]
    return argv
