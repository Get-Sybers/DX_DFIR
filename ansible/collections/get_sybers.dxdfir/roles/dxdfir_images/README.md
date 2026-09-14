# dxdfir_images

Build **every runtime tool container from source, hardened** — and verify it.
No third-party tool image is pulled at runtime. The images come from two
in-tree sources:

- **DX_DFIR's own `docker/<name>/Dockerfile`**: yara, suricata, zeek, plaso
  (volatility from the [PIIAT-Mem](https://github.com/Get-Sybers/PIIAT-Mem)
  submodule's context).
- **The [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz)
  submodule** (`third_party/GoDFIR-toolz/`): the whole **Eric Zimmerman tool
  family**, now almost entirely **static-Go `FROM scratch` substitutes** (no
  shell, no python, just the binary) — `goevtx` (EvtxECmd), `gomft` (MFTECmd),
  `goamcache`/`goappcompat` (Amcache/AppCompatCache), `gore`/`gosbe`
  (RECmd/SBECmd, with dirty-hive `.LOG` replay), `gole`/`gojle` (LECmd/JLECmd),
  `gorb` (RBCmd), `gowxt` (WxTCmd), plus the two tools that were never
  Linux-viable under .NET at all — `goprefetch` (PECmd — XP→Win11 `.pf`,
  MAM-compressed included) and `goese` (SrumECmd/SumECmd — SRUDB.dat / SUM
  `Current.mdb`). Each builds from its OWN subdir in the submodule. The one
  remaining .NET tool, **sqlecmd** (SQLECmd), still builds from the ONE
  parameterized `eztool/Dockerfile` (tool selected via
  `dxdfir_images_build_overrides` args).

Every image runs as uid 2000 (the single `dxdfir_runtime_uid` knob) and is
verified against the hardening contract by this role.

## Hardening: minimal, attack-surface-reduction posture

Chosen for the strongest resistance to container escape AND to a
supply-chain-compromised tool: each image is **stripped to the tool itself** and
every run is confined hard. ansible does the hardening *at build time* and is
then **removed from the final image** — it never ships at runtime. The hardening
playbook has ONE canonical home,
[`third_party/GoDFIR-toolz/hardening/harden.yml`](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/hardening/harden.yml):
the submodule's images use it directly, and this role's preflight syncs it into
`docker/hardening/harden.yml` (git-ignored, generated) so DX_DFIR's own images
can `COPY` it from their build context.

- the tool is the image **ENTRYPOINT**; no ansible, no run-role, no
  orchestration in the runtime image
- **uid 0 renamed `ansible`** and locked; **sudo/su/pkexec** and the
  account-manipulation suite removed; every setuid/setgid bit stripped
- **no package manager, no pip** (nothing installable at runtime)
- **no shell and no python** except where the tool needs them: `get-sybers/yara`
  keeps `sh` (its scan loop is a shell script), `get-sybers/volatility` and
  `get-sybers/plaso` keep python (the tools are python); `get-sybers/zeek`,
  `get-sybers/suricata`, and the GoDFIR Go tools carry neither
- the tool runs as **uid 2000**

The role verifies this twice per image: the static image config (USER, hardened
label) and a shell-free `docker export | tar -t` scan proving the removed
binaries — and, for the tool-only images, the shell and python — are absent.

Runtime confinement is what actually contains both threats (an attacker with
code execution does not need an on-image shell): every processor `docker run`
carries `--cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs
/tmp --pids-limit 512 --network none` (Volatility symbol fetch is the one
`--symbols-online` opt-in).

## What is removed vs. what remains (and why)

Verify any image with a shell-free filesystem scan:
`cid=$(docker create get-sybers/<tool>:latest); docker export "$cid" | tar -t | grep -E 'apt-get|dpkg|sudo|/pip|/sh$|python3'; docker rm -f "$cid"`.

**Removed** (every image): package managers (`apt`/`apt-get`/`dpkg`), `pip`,
`sudo`/`su`/`pkexec`, the account-manipulation suite, every setuid/setgid bit,
and **ansible itself** (build-time only). The uid-0 account is renamed `ansible`
and locked; the tool runs as uid 2000.

**Kept only where the tool needs it**: `get-sybers/yara` keeps `sh` (its per-file
scan loop is a shell script — the image ENTRYPOINT); `get-sybers/volatility` and
`get-sybers/plaso` keep `python3` (the tools *are* python). `get-sybers/zeek`,
`get-sybers/suricata` and the GoDFIR Go tools (goevtx/gomft/…) carry **no shell and no python** at all.

Why not strip the shell from *every* image on instinct? Removing it does not
stop an attacker who already has code execution — the premise of a compromised
tool — because they issue syscalls directly; and a compromised *allowed* tool
is executed regardless of any in-container policing. So the design minimises
what is present (fewer packages = smaller supply-chain surface) and confines
what runs at the boundary (`--cap-drop ALL --security-opt no-new-privileges
--read-only --network none`), rather than shipping an orchestrator to guard a
large image from inside. An escape or exfiltration then needs a defect in the
tool plus the kernel/runtime, against dropped capabilities and no network —
not a convenient interpreter.

## What is not built here

The analysis backend is not a tool image: the Elastic stack under
`docker/elastic/` (Elasticsearch, Kibana, Fleet Server, Filebeat — the official
Elastic images, version-pinned) is brought up with docker compose, published on
`127.0.0.1` only, with security on. No other third-party image is pulled at
runtime (the stock .NET runtime image is used only by the evtx lane's
operator-supplied mode).

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_images_namespace` | `get-sybers` | Image namespace — every image is tagged `<namespace>/<name>:latest`. |
| `dxdfir_images_context` | `<repo>/docker` | DX_DFIR's own build context (yara/suricata/zeek/plaso; holds `<name>/Dockerfile` + the synced `hardening/harden.yml`). |
| `dxdfir_images_eztools_context` | `<repo>/third_party/GoDFIR-toolz` | The GoDFIR-toolz submodule root — evtxecmd, the EZ family, and the two Go substitutes build from here. |
| `dxdfir_runtime_uid` / `dxdfir_runtime_gid` | `2000` | Single run-as uid/gid, passed to every build as `DFIR_UID`/`DFIR_GID` and asserted in the contract. |
| `dxdfir_images_set` | all eighteen | Images to build. |
| `dxdfir_images_force` | `false` | Rebuild existing images (layer cache applies). |

## Usage
```bash
ansible-playbook playbooks/dxdfir-build-images.yml
# one image:
ansible-playbook playbooks/dxdfir-build-images.yml -e '{"dxdfir_images_set":["yara"]}'
```
