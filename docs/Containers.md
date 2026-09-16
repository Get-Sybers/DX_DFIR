# 01_Containers

Every tool container the pipeline runs is **built in-repo, hardened** — no
third-party tool image is pulled at runtime. This page lists the images, how
they are built, and the posture they enforce.

---

## Build the hardened tool images

```sh
ansible-playbook ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-build-images.yml
```

| Image | Tool | Source |
|---|---|---|
| `get-sybers/zeek` | PCAP → Zeek JSON | Zeek LTS from the project's OBS Debian repo (`docker/GoDFIR-toolz/zeek/`) |
| `get-sybers/signatures` | detections — YARA + Suricata (offline replay) + Hayabusa | Debian packages + the pinned Hayabusa release (`docker/GoDFIR-toolz/signatures/`) |
| `get-sybers/byakugan` | CAR/STIX behaviour engine | clone-at-build at the `sources.yml` pin (`docker/GoDFIR-toolz/byakugan/`) |
| `get-sybers/piiat-mem` | memory (Volatility 3) + `vadyarascan` | `docker/GoDFIR-toolz/piiat-mem/` (clone-at-build) |
| `get-sybers/plaso` | Plaso timelining + `image_export` (dfVFS) | GIFT stable PPA (`docker/GoDFIR-toolz/plaso/`) |
| `get-sybers/goevtx` | Windows Event Logs (.evtx) | static Go on go-evtx, FROM scratch (`docker/GoDFIR-toolz/goevtx/`) |

The `dxdfir_images` role builds each one and **verifies the minimal-posture
contract** per build — the static image config plus a shell-free
`docker export` scan proving the removed binaries (and, for the tool-only
images, the shell and python) are absent.

A start-time **inventory guard** then refuses to process against anything but a
known hardened image: each processor preflight asserts the image it will run is
a hardened `get-sybers/*` image, and `dxdfir verify-images` audits the whole `get-sybers/*`
namespace for missing, un-hardened, or **unexpected** images (something added
that shouldn't be).

## The hardening posture (minimal / attack-surface reduction)

Chosen for the strongest resistance to container escape AND to a
supply-chain-compromised tool: strip each image to the tool itself, and confine
every run hard. ansible does the hardening *at build time*
(`docker/GoDFIR-toolz/hardening/harden.yml`) and is then **removed from the final image** —
it never ships at runtime.

- the tool is the image **ENTRYPOINT**; there is no ansible, no run-role, no
  orchestration layer in the runtime image
- the **uid-0 account is renamed `ansible`**, password-locked, nologin — no
  `root` login name exists; **sudo/su/pkexec** and the account-manipulation
  suite are removed; every setuid/setgid bit is stripped
- **no package manager, no pip** — nothing installable at runtime
- **no shell and no python** except where the tool irreducibly needs them:
  `get-sybers/signatures` keeps `sh` (its per-file scan loop *is* a shell script);
  `get-sybers/piiat-mem` and `get-sybers/plaso` keep python (the tools *are* python).
  `get-sybers/zeek` and the GoDFIR Go tools carry neither.
- the tool runs as the fixed unprivileged user (`USER 2000:2000`)

Runtime confinement is what actually contains both threats (an attacker with
code execution does not need an on-image shell), applied on every `docker run`
the processors issue: `--cap-drop ALL --security-opt no-new-privileges
--read-only --tmpfs /tmp --pids-limit 512 --network none`. Evidence is mounted
read-only, output read-write, the root filesystem is immutable. The single
network exception is Volatility ISF symbol fetch
(`dxdfir_volatility_symbols_online` / `--symbols-online`).

Why not keep a shell out of a "belt and braces" instinct? Removing the shell
does not stop an attacker who already has code execution (the premise of a
compromised tool) — they issue syscalls directly — and adding an in-container
orchestrator to police it only enlarges the supply-chain and execution surface.
So the design minimises what is present and confines what runs, rather than
policing a large image from inside.

## Pulled images

No tool image is pulled — every `get-sybers/*` image is built from source. The
one pulled set is the analysis backend: the Elastic stack (`docker/elastic/`)
is the official `docker.elastic.co/*` images, version-pinned
(`ELASTIC_VERSION`), brought up with docker compose on `127.0.0.1` with
security on — see its README. `scripts/save-docker-images.sh` includes them in
the offline tarball set, so the stack deploys air-gapped with zero pulls.

## Offline / air-gapped hosts

Two levels:

**Images only** — `save-docker-images.sh` saves the built `get-sybers/*` images
plus the pulled Elastic-stack images into `data_store/docker_images/`:

```bash
scripts/save-docker-images.sh --build     # online: build the get-sybers/* images, then save all
scripts/save-docker-images.sh --verify    # offline: load every tarball, then assert the hardened inventory
```

**Complete portable bundle** — `package-offline.sh` produces ONE artifact with
everything an air-gapped host needs — the images, the `dxdfir` CLI + all Python
deps as wheels, the pinned ansible collections, a clean archive of the repo, and
a `MANIFEST.sha256` over all of it:

```bash
# online host:
scripts/package-offline.sh --build            # -> dist/dxdfir-offline-<ver>-<arch>.tar.gz

# air-gapped host (no network needed):
tar -xzf dxdfir-offline-<ver>-<arch>.tar.gz
cd dxdfir-offline-<ver>-<arch> && ./setup-offline.sh
```

`setup-offline.sh` verifies every checksum before doing anything, loads the
images, installs the CLI from the bundled wheels (`pip --no-index`), installs
the collections offline, and finishes by running `dxdfir verify-images` so the
loaded inventory is confirmed to be the expected hardened set. Nothing reaches
the network.

**Not containers:** **Hayabusa** ships as a self-contained Rust binary (no
official image) — operator-supplied: download the pinned release into
`data_store/dependencies/hayabusa/`. Disk-image file access uses host tools
(`ewf-tools`, `sleuthkit`, `ntfs-3g`) installed by `setup-environment.sh`.

## Upstream documentation

- [Zeek](https://zeek.org/) · [Suricata](https://suricata.io/) · [YARA](https://virustotal.github.io/yara/)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3) · [Plaso / GIFT PPA](https://launchpad.net/~gift)
- [go-evtx (Velociraptor)](https://github.com/Velocidex/evtx) · [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) · [Hayabusa (Yamato Security)](https://github.com/Yamato-Security/hayabusa)
- [Elastic Stack](https://www.elastic.co/docs) — the analysis backend (`docker/elastic/`)

The obligations the tools and the backend place on the operator are recorded in
[THIRD_PARTY_NOTICES.md](/.github/THIRD_PARTY_NOTICES.md).
