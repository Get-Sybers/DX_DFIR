# dxdfir_zimmerman

Process **forensic disk images** and **VMware VM exports** with Eric Zimmerman's
**EZ-Tools** (RECmd, JLECmd, LECmd, AmcacheParser, AppCompatCacheParser, SBECmd,
RBCmd, MFTECmd) plus a plaso-driven SRUM parse, into per-host artefact output for
the Elastic-native or SOF-ELK pipeline. The role is structure only — it asserts inputs, runs
a preflight (docker, input dir, the `get_sybers_dxdfir.zimmerman` module, every
tool image it drives), then invokes the processor as a **single action** (the
extraction + nine container runs happen inside Python). One output dir per host.

## How it works

For each disk image, the processor (`get_sybers_dxdfir/zimmerman.py`):

1. Extracts the zimmerman artefact set from the image with Plaso's
   `image_export.py`, using a **YAML collection filter** (not
   `--artifact_filters` — the set has no named forensic-artifact-definitions
   entry): registry hives (SYSTEM/SOFTWARE/SAM/SECURITY + per-user
   NTUSER.DAT/UsrClass.dat) **with their .LOG1/.LOG2 transaction logs**, Amcache,
   jump lists/`.lnk` (Explorer "Recent"), Recycle Bin `$I` records, the Windows
   Timeline database, the SRUM database, and a resident `$MFT`.
2. Runs the hardened EZ-Tools containers over what was pulled out: RECmd
   (registry batch), JLECmd/LECmd (jump lists/lnk), AmcacheParser,
   AppCompatCacheParser, SBECmd (ShellBags), RBCmd (Recycle Bin), MFTECmd (when
   a `$MFT` was extracted). The two Windows-bound EZ tools run through their
   Linux-native Go substitutes: **SRUM** via `get-sybers/goese` (`goese` —
   SrumECmd is .NET and P/Invokes Windows' ESE engine) and **Prefetch** via
   `get-sybers/goprefetch` (`goprefetch` — PECmd refuses off-Windows), each run
   only when its artefact (`SRUDB.dat` / any `.pf`) was extracted.

Directory-recursive tools (RECmd, JLECmd, LECmd, SBECmd, RBCmd) are pointed at
the **whole per-image extraction root**, not a hand-picked sub-directory: that
tree holds only the filtered artefact set (never the rest of the filesystem), so
scanning it whole is both correct and needs no per-user directory lookup for a
multi-user image. AmcacheParser / AppCompatCacheParser / MFTECmd need one
specific file (`Amcache.hve` / `SYSTEM` / `$MFT`) and are only run when that file
was actually extracted.

Prefetch is **deliberately not** extracted or parsed a second time here: PECmd
is Windows-only and the main log2timeline lane already parses `.pf` files inline
as part of the normal disk-image timeline.

## Output isolation

Follows the CAR pipeline's rule (`docs/CAR-Pipeline.md` §2 — "one source, one
database"): each image gets its own `<out_dir>/<host>/` (host = the image's
filename stem), holding the raw extraction (`_extracted/`), one sub-dir per
EZ-Tool, and a combined `zimmerman.log`.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_zimmerman_pipeline` | `elastic` | `elastic` or `sofelk` — selects the output destination (the **playbook** decides this). |
| `dxdfir_zimmerman_input_dir` | `<repo>/data_store/raw/disk_images` | Disk-image tree (E01/raw/img/dd/vmdk/vhd/vhdx/aff), recursed. |
| `dxdfir_zimmerman_vm_dir` | `<repo>/data_store/raw/VM_files` | VMware VM export folders (one per VM); optional. |
| `dxdfir_zimmerman_elastic_out_dir` | `<repo>/data_store/processed/zimmerman` | Elastic-path output. |
| `dxdfir_zimmerman_sofelk_out_dir` | `<repo>/data_store/processed/sofelk/zimmerman` | SOF-ELK-path output. |
| `dxdfir_zimmerman_plaso_image` | `get-sybers/plaso:latest` | Used for both artefact extraction and the SRUM two-step. |
| `dxdfir_zimmerman_vss` | `false` | Also extract from Volume Shadow Copies. |
| `dxdfir_zimmerman_python_path` | `<repo>/python` | PYTHONPATH to `get_sybers_dxdfir` (in-repo runs). |
| `dxdfir_zimmerman_force` | `false` | Reprocess hosts that already have output. |

## Idempotence

Coarse-grained, at the **host** level: a host output dir that already holds any
non-empty file is skipped whole, unless `dxdfir_zimmerman_force`. A partial prior
run (interrupted mid-way) is reprocessed entirely rather than resumed
step-by-step — simpler and safer than guessing which EZ-Tool half-completed.
The skip lives in the Python processor, never in a task `when:`.

## What is deliberately NOT run: WxTCmd

`wxtcmd_argv()` exists as a pure, unit-tested argv builder, but
`process_image()` does **not** invoke it. WxTCmd's SQLite interop needs a
**writable** unpack path (its own working directory), which the hardened
read-only-rootfs base image does not provide by default; the fix is an extra
writable tmpfs at `/opt/eztool` (uid/gid 2000 to match the container's non-root
user) — see the epic #86 Phase-D comment and `wxtcmd_argv()`'s docstring.
Verifying this against a real `ActivitiesCache.db` is deferred to issue #88
rather than risk breaking the rest of the lane chasing one tool.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-zimmerman.yml -e dxdfir_zimmerman_pipeline=elastic
```

## Testing
Python unit tests (`python/tests/test_zimmerman.py`) cover the pure logic: the
YAML filter's shape and artefact coverage (including prefetch), every container
argv builder's exact flags/mounts, discovery, host-level idempotent skip,
per-artefact gating (amcache/appcompatcache/mftecmd/srum/prefetch only run when
their file was extracted), and one-host-one-dir naming —
all with docker mocked out. The **Molecule** scenario needs a small parseable
image (large/binary — not shipped):
```bash
molecule test -- -e molecule_sample_image=/path/tiny.raw
```

## Not yet run against a real image
This lane's build + unit tests are complete, but a full end-to-end run against a
real disk image is deliberately deferred to issue #88 (see the epic). Treat the
container argv as *proven-by-recipe* (each was independently confirmed against
the built `get-sybers/plaso` and EZ-Tools images this session — see the module
docstrings) rather than validated end-to-end.
