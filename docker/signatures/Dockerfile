# syntax=docker/dockerfile:1
#
# get-sybers/signatures — ONE hardened image for the whole detection lane:
# YARA + Suricata + Hayabusa. It consolidates the former get-sybers/yara and
# get-sybers/suricata images AND pulls Hayabusa off the host — Hayabusa used to
# run as an operator-supplied native binary directly on the analyst host (a
# host-execution gap a container-safety audit flagged); it now runs confined here.
#
# There is NO ENTRYPOINT: this is a multi-tool image (like get-sybers/plaso),
# invoked as `container.run(IMAGE, [<tool>, <args>...])` — the caller names the
# tool (the YARA scan loop, `suricata`, or the baked `hayabusa`). A shell REMAINS
# only for the YARA per-file scan loop (/opt/dxdfir/scan-list.sh), exactly as in
# the former get-sybers/yara image.
#
#   docker build -t get-sybers/signatures:latest -f docker/signatures/Dockerfile docker
ARG BASE=debian:trixie-slim
ARG HAYABUSA_VERSION=4.1.0

FROM ${BASE} AS hardened
ARG DFIR_UID=2000
ARG DFIR_GID=2000
ARG HAYABUSA_VERSION
ARG TARGETARCH
# Pinned Hayabusa (Yamato-Security, GPL-3.0) — downloaded + sha256-verified at
# BUILD time, like the apt tools; nothing is committed to the repo. One archive
# per arch (the checksums are the release's own published assets).
ARG HB_SHA_amd64=ed2c4595f95b8e765d37f392212587304ce89ed7cfb6682b425a96d126ed67eb
ARG HB_SHA_arm64=9a112ed5ead6850c0f7f1b2a18b2c9c71c6eddc469cc2e1a31f5ed1170afa628
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        yara suricata ansible-core ca-certificates curl unzip; \
    case "${TARGETARCH:-amd64}" in \
      amd64) hbarch=x64;     hbsha="${HB_SHA_amd64}" ;; \
      arm64) hbarch=aarch64; hbsha="${HB_SHA_arm64}" ;; \
      *) echo "unsupported TARGETARCH '${TARGETARCH}'" >&2; exit 1 ;; \
    esac; \
    zip="hayabusa-${HAYABUSA_VERSION}-lin-${hbarch}-gnu.zip"; \
    curl -fsSL "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/${zip}" -o /tmp/hb.zip; \
    printf '%s  /tmp/hb.zip\n' "${hbsha}" | sha256sum -c -; \
    mkdir -p /opt/dxdfir/hayabusa; \
    unzip -q /tmp/hb.zip -d /opt/dxdfir/hayabusa; \
    mv "/opt/dxdfir/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-${hbarch}-gnu" /opt/dxdfir/hayabusa/hayabusa; \
    chmod 0755 /opt/dxdfir/hayabusa/hayabusa; \
    rm -rf /opt/dxdfir/hayabusa/rules/.git /tmp/hb.zip
COPY signatures/scan-list.sh /opt/dxdfir/scan-list.sh
COPY hardening/harden.yml /tmp/hardening/harden.yml
RUN set -eux; \
    chmod 0755 /opt/dxdfir/scan-list.sh; \
    ansible-playbook -c local -i localhost, /tmp/hardening/harden.yml \
      -e harden_uid=${DFIR_UID} -e harden_gid=${DFIR_GID} \
      -e '{"harden_extra_remove": ["/usr/bin/suricata-update", "/usr/bin/suricatasc", "/usr/bin/suricatactl", "/var/lib/suricata/update"]}'; \
    # remove the build-time hardener + everything the tools do not need at runtime,
    # keeping sh/dash for the YARA scan loop (glibc/libgcc stay — Hayabusa's gnu
    # build needs them; the tools are C/Rust, so python goes).
    rm -rf /usr/bin/ansible* /usr/lib/python3/dist-packages/ansible* \
           /etc/ansible /root/.ansible /tmp/hardening \
           /usr/bin/python3* /usr/lib/python3* /usr/bin/bash /bin/bash /usr/bin/perl* \
           /usr/bin/curl /usr/bin/unzip

FROM scratch
COPY --from=hardened / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/tmp
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
LABEL org.opencontainers.image.title="get-sybers/signatures" \
      org.opencontainers.image.description="Minimal hardened detection lane (YARA + Suricata + Hayabusa) for DX_DFIR: uid0 renamed+locked, no ansible/apt/pip/sudo/setuid, no python, runs as a fixed non-root uid (default 2000); sh kept only for the YARA per-file scan loop. Multi-tool image (no ENTRYPOINT)." \
      com.get-sybers.hardened="true"
