# syntax=docker/dockerfile:1
#
# get-sybers/byakugan — the external Byakugan MITRE CAR engine in ONE hardened
# image. Byakugan used to run as `python -m byakugan` DIRECTLY ON THE ANALYST
# HOST off a sibling git checkout (a host-execution gap a container-safety audit
# flagged, and a cross-repo checkout DX_DFIR had to provision + keep on-pin);
# it now runs confined here, and the engine is cloned + built INTO the image at
# the commit pinned by byakugan.ref, so the only thing the DX_DFIR checkout holds
# is how it INVOKES this image (get_sybers_dxdfir.mitrecar).
#
# The engine's `byakugan` console binary IS the ENTRYPOINT (byakugan-entry.py):
# one binary, dispatched on its first argument to the engine's three operations
# (build / timeline / car-vocab) — see that file. It is a python engine, so
# python3 stays (like get-sybers/plaso and get-sybers/volatility); everything
# else is stripped by the shared build-time hardener.
#
#   docker build -t get-sybers/byakugan:latest \
#     --build-arg BYAKUGAN_REF=$(grep -vE '^\s*(#|$)' byakugan.ref | head -1) \
#     -f docker/byakugan/Dockerfile docker
ARG BASE=debian:trixie-slim
ARG GO_BASE=golang:1.24-bookworm
ARG BYAKUGAN_REPO=https://github.com/Get-Sybers/byakugan
ARG BYAKUGAN_REF=main

# --- stage 1: build the Go parse engine -------------------------------------
# byakugan-parse is stdlib-only Go (go/go.mod has no external requires), so
# CGO_ENABLED=0 gives a fully static binary that runs regardless of the runtime
# stage's glibc, and GOTOOLCHAIN=local keeps the build offline (no toolchain
# download). The engine is cloned RECURSIVELY: it reconstructs its object model
# live from the pinned nested submodules (third_party/car + attack-datasources),
# so a plain clone would leave the model sources missing.
FROM ${GO_BASE} AS engine
ARG BYAKUGAN_REPO
ARG BYAKUGAN_REF
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-trimpath
RUN set -eux; \
    git clone "${BYAKUGAN_REPO}" /src; \
    git -C /src checkout "${BYAKUGAN_REF}"; \
    git -C /src submodule update --init --recursive; \
    (cd /src/go && go build -o bin/byakugan-parse ./cmd/byakugan-parse); \
    test -x /src/go/bin/byakugan-parse; \
    # drop every .git dir (repo + submodules) — the model YAML/JSON and the built
    # binary are all that ship; the history does not.
    find /src -name .git -prune -exec rm -rf {} +

# --- stage 2: python runtime + in-image hardening ---------------------------
FROM ${BASE} AS hardened
ARG DFIR_UID=2000
ARG DFIR_GID=2000
ARG BYAKUGAN_REF
# python3 + pyyaml (the engine's ONLY runtime dependency, from apt so there is no
# pip); ansible-core is the build-time hardener, removed below.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends python3 python3-yaml ansible-core; \
    rm -rf /var/lib/apt/lists/*
# The engine SOURCE TREE (package + its pinned model submodules + the static Go
# parse binary): the engine resolves its model dir relative to the package, so
# it must run from this tree via PYTHONPATH, never from site-packages.
COPY --from=engine /src /opt/byakugan
COPY byakugan/byakugan-entry.py /usr/local/bin/byakugan
COPY hardening/harden.yml /tmp/hardening/harden.yml
RUN set -eux; \
    chmod 0755 /usr/local/bin/byakugan; \
    ansible-playbook -c local -i localhost, /tmp/hardening/harden.yml \
      -e harden_uid=${DFIR_UID} -e harden_gid=${DFIR_GID}; \
    # remove the build-time hardener + the shell; KEEP python3 + python3-yaml +
    # the baked engine tree (python is the tool, like plaso/volatility).
    rm -rf /usr/bin/ansible* /usr/lib/python3/dist-packages/ansible* \
           /etc/ansible /root/.ansible /tmp/hardening \
           /usr/bin/bash /bin/bash /usr/bin/bashbug /usr/bin/perl*

FROM scratch
COPY --from=hardened / /
ARG DFIR_UID=2000
ARG DFIR_GID=2000
ARG BYAKUGAN_REF
# PYTHONPATH: run the engine from its baked source tree. BYAKUGAN_PARSE_BIN: the
# static Go parse binary (the engine reads this env first). HOME=/tmp: the only
# writable path on the read-only rootfs.
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/tmp \
    PYTHONPATH=/opt/byakugan \
    PYTHONDONTWRITEBYTECODE=1 \
    BYAKUGAN_PARSE_BIN=/opt/byakugan/go/bin/byakugan-parse
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["byakugan"]
LABEL org.opencontainers.image.title="get-sybers/byakugan" \
      org.opencontainers.image.description="Minimal hardened MITRE CAR engine (Byakugan) for DX_DFIR: engine cloned + built into the image at the byakugan.ref pin, uid0 renamed+locked, no ansible/apt/pip/sudo/setuid/shell, runs as a fixed non-root uid (default 2000). python kept (the engine is python). One entrypoint binary dispatched to build/timeline/car-vocab." \
      com.get-sybers.hardened="true" \
      com.get-sybers.byakugan.ref="${BYAKUGAN_REF}"
