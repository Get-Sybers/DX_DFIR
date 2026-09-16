# dxdfir_godfir_toolz

Process **forensic disk images** and **VMware VM exports** with the artefact set
the **GoDFIR-toolz** parse (gore, gojle, gole, goamcache,
goappcompat, gosbe, gorb, gomft) plus SRUM and Prefetch, into
per-host artefact output. Every tool
now runs as a Linux-native, static-Go `FROM scratch` substitute
(Get-Sybers/GoDFIR-toolz: `gore`/`gojle`/`gole`/`goamcache`/`goappcompat`/`gosbe`/
`gorb`/`gomft`), not .NET — including SRUM (`goese`) and Prefetch (`goprefetch`),
which Plaso only **extracts** the bytes for; the parsing is all Go. The role is structure only — it asserts inputs, runs
a preflight (docker, input dir, the `get_sybers_dxdfir.godfir_toolz` module, every
tool image it drives), then invokes the processor as a **single action** (the
extraction + nine container runs happen inside Python). One output dir per host.

## How it works

For each disk image, the processor (`get_sybers_dxdfir/godfir_toolz.py`):

1. Extracts the godfir-toolz artefact set from the image with Plaso's
   `image_export.py`, using a **YAML collection filter** (not
   `--artifact_filters` — the set has no named forensic-artifact-definitions
   entry): registry hives (SYSTEM/SOFTWARE/SAM/SECURITY + per-user
   NTUSER.DAT/UsrClass.dat) **with their .LOG1/.LOG2 transaction logs**, Amcache,
   jump lists/`.lnk` (Explorer "Recent"), Recycle Bin `$I` records, the Windows
   Timeline database, the SRUM database, and a resident `$MFT`.
2. Runs the hardened Go containers over what was pulled out: `gore`
   (registry batch), `gojle`/`gole` (jump lists / `.lnk`), `goamcache`,
   `goappcompat`, `gosbe` (ShellBags), `gorb` (Recycle Bin),
   `gomft` (when a `$MFT` was extracted). The registry-family tools
   (`gore`/`gosbe`/`goamcache`/`goappcompat`) replay each hive's `.LOG1/.LOG2`
   dirty-hive transaction logs into a writable `/work` tmpfs to match .NET
   fidelity. The two tools that were never Linux-viable under .NET at all run as
   Go parsers too: **SRUM** via `get-sybers/goese` (the ESE database needs
   no Windows engine here) and **Prefetch** via `get-sybers/goprefetch` (nothing prior
   refuses off-Windows), each run only when its artefact (`SRUDB.dat` / any
   `.pf`) was extracted.

Directory-recursive tools (`gore`, `gojle`, `gole`, `gosbe`, `gorb`) are pointed at
the **whole per-image extraction root**, not a hand-picked sub-directory: that
tree holds only the filtered artefact set (never the rest of the filesystem), so
scanning it whole is both correct and needs no per-user directory lookup for a
multi-user image. goamcache / goappcompat / gomft need one
specific file (`Amcache.hve` / `SYSTEM` / `$MFT`) and are only run when that file
was actually extracted.

Prefetch is **deliberately not** extracted or parsed a second time here: goprefetch
is Windows-only and the main log2timeline lane already parses `.pf` files inline
as part of the normal disk-image timeline.

## Output isolation

Follows the CAR pipeline's rule (`docs/CAR-Pipeline.md` §2 — "one source, one
database"): each image gets its own `<out_dir>/<host>/` (host = the image's
filename stem), holding the raw extraction (`_extracted/`), one sub-dir per
tool, and a combined `godfir-toolz.log`.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_godfir_toolz_input_dir` | `<repo>/data_store/raw/disk_images` | Disk-image tree (E01/raw/img/dd/vmdk/vhd/vhdx/aff), recursed. |
| `dxdfir_godfir_toolz_vm_dir` | `<repo>/data_store/raw/VM_files` | VMware VM export folders (one per VM); optional. |
| `dxdfir_godfir_toolz_out_dir` | `<repo>/data_store/processed/godfir-toolz` | Output base (override to redirect). |
| `dxdfir_godfir_toolz_plaso_image` | `get-sybers/plaso:latest` | Used for both artefact extraction and the SRUM two-step. |
| `dxdfir_godfir_toolz_vss` | `false` | Also extract from Volume Shadow Copies. |
| `dxdfir_godfir_toolz_python_path` | `<repo>/python` | PYTHONPATH to `get_sybers_dxdfir` (in-repo runs). |
| `dxdfir_godfir_toolz_force` | `false` | Reprocess hosts that already have output. |

## Idempotence

Coarse-grained, at the **host** level: a host output dir that already holds any
non-empty file is skipped whole, unless `dxdfir_godfir_toolz_force`. A partial prior
run (interrupted mid-way) is reprocessed entirely rather than resumed
step-by-step — simpler and safer than guessing which tool half-completed.
The skip lives in the Python processor, never in a task `when:`.

## What is deliberately NOT run: gowxt

`wxtcmd_argv()` exists as a pure, unit-tested argv builder, but
`process_image()` does **not** invoke it yet. `gowxt`'s SQLite interop needs a
**writable** unpack path (it copies `ActivitiesCache.db` before opening it),
which the hardened read-only rootfs does not provide; `gowxt` takes a
`--work-dir` on a writable `/work` tmpfs (uid/gid 2000), the same replay/unpack
pattern `gore`/`gosbe`/`goamcache`/`goappcompat` use — so the read-only-rootfs
blocker is solved. The step stays deferred only until a real `ActivitiesCache.db`
confirms the end-to-end shape (issue #88 — none of the lab images carried a
Windows Timeline database to validate against).

## Example
```bash
ansible-playbook playbooks/dxdfir-process-godfir-toolz.yml
```

## Testing
Python unit tests (`python/tests/test_godfir_toolz.py`) cover the pure logic: the
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
the built `get-sybers/plaso` and GoDFIR-toolz images this session — see the module
docstrings) rather than validated end-to-end.
