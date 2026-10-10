# 01_Containers

[goDFIR-Toolz](https://github.com/Get-Sybers/GoDFIR-toolz) images are built from the docker files located. goDFIR-toolz also hosts the pre-built container images via the GitHub registry.

| Image | Tool | Source |
|---|---|---|
| [get-sybers/zeek](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/zeek/README.md) | PCAP → Zeek JSON | Zeek LTS from the project's OBS Debian repo (`docker/GoDFIR-toolz/zeek/`) |
| [get-sybers/signatures](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/signatures/README.md) | detections: YARA + Suricata (offline replay) + Hayabusa | Debian packages + the pinned Hayabusa release (`docker/GoDFIR-toolz/signatures/`) |
| [get-sybers/byakugan](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/byakugan/README.md) | [Byakugan](https://github.com/Get-Sybers/Byakugan) CAR/STIX behaviour engine | `BYAKUGAN_REF` pin (`docker/GoDFIR-toolz/byakugan/`) |
| [get-sybers/anamnesis](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/anamnesis/README.md) | [Anamnesis](https://github.com/Get-Sybers/Anamnesis) memory (anamnesis / MemProcFS) | `docker/GoDFIR-toolz/anamnesis/` (clone-at-build) |
| [get-sybers/plaso](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/plaso/README.md) | [Plaso](https://github.com/log2timeline/plaso) timelining + `image_export` (dfVFS) | GIFT stable PPA (`docker/GoDFIR-toolz/plaso/`) |
| [get-sybers/gowindowlicker](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/gowindowlicker/README.md) | [gowindowlicker](https://github.com/Get-Sybers/gowindowlicker) the Windows artefact matrix: every parser (goevtx, gomft, gore, goprefetch, …) a sub-tool of one binary | static Go, FROM scratch (`docker/GoDFIR-toolz/gowindowlicker/`) |
| [get-sybers/godaemonhunter](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/godaemonhunter/README.md) | [godaemonhunter](https://github.com/Get-Sybers/godaemonhunter) the Linux & MacOS daemon-parser matrix (`hunt`: Layer-1 knowledge store → enriched daemon parsers) | static Go, FROM scratch (repo-root context) |
| [get-sybers/gomount](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/gomount/README.md) | [gomount](https://github.com/Get-Sybers/gomount) the disk-image reader (E01/Ex01, raw, VMDK, VHDX, VHD, QCOW2, VDI, DMG, sparseimage; a sparsebundle directory is readable by gomount itself but is not a lane item; NTFS, the Linux filesystems, APFS, HFS+, LVM2): drives the signatures disk scan, the hayabusa export (`materialise`), and baked into the two host-lane images so their parsers run on the image | static Go (`docker/GoDFIR-toolz/gomount/`) |

## Ansible
The `dxdfir_images` role builds each one and **verifies the minimal-posture
contract** per build: the static image config plus a shell-free
`docker export` scan proving the removed binaries (and, for the tool-only
images, the shell and python) are absent.

A start-time **inventory guard** then refuses to process against anything but a
known hardened image: each processor preflight asserts the image it will run is
a hardened `get-sybers/*` image, and `dx verify images` audits the whole `get-sybers/*`
namespace for missing, un-hardened, or **unexpected** images (something added
that shouldn't be).

## The hardening posture (minimal / attack-surface reduction)

Chosen for the strongest resistance to container escape AND to a
supply-chain-compromised tool: strip each image to the tool itself, and confine
every run hard. ansible does the hardening *at build time*
(`docker/GoDFIR-toolz/hardening/harden.yml`) and is then **removed from the final image**:
it never ships at runtime.

- the tool is the image **ENTRYPOINT**; there is no ansible, no run-role, no
  orchestration layer in the runtime image
- the **uid-0 account is `ansible`, not `root`**, password-locked, nologin: no
  `root` login name exists; **sudo/su/pkexec** and the account-manipulation
  suite are removed; every setuid/setgid bit is stripped
- **no package manager, no pip**: nothing installable at runtime
- **no shell and no python** except where the tool irreducibly needs them:
  `get-sybers/signatures` keeps `sh` (its per-file scan loop *is* a shell script);
  `get-sybers/anamnesis` and `get-sybers/plaso` keep python (the tools *are* python).
  `get-sybers/zeek` and the GoDFIR Go tools carry neither.
- the tool runs as the fixed unprivileged user (`USER 2000:2000`)

Runtime confinement is what actually contains both threats (an attacker with
code execution does not need an on-image shell), applied on every `docker run`
the processors issue: `--cap-drop ALL --security-opt no-new-privileges
--read-only --tmpfs /tmp --pids-limit 512 --network none`. Evidence is mounted
read-only, output read-write, the root filesystem is immutable. Every evidence
lane runs with the network off: the anamnesis PDB symbols are baked into the
image at build time, so byakugan's explicit Elastic push (`BYAKUGAN_LOAD_ES_URL`)
is the one `network: optional` contract.

Why not keep a shell out of a "belt and braces" instinct? Removing the shell
does not stop an attacker who already has code execution (the premise of a
compromised tool): they issue syscalls directly, and adding an in-container
orchestrator to police it only enlarges the supply-chain and execution surface.
So the design minimises what is present and confines what runs, rather than
policing a large image from inside.

## Offline / air-gapped hosts

1. run [scripts/save-docker-images.sh](save-docker-images.sh) to save the required docker images as tar balls. they will be saved `dx_dfir/data_store/docker_images`

2. `setup-environment.sh` in the air gapped environment will check for these images when run.