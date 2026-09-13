# syntax=docker/dockerfile:1
#
# get-sybers/yara — minimal hardened YARA. The image is stripped to yara + its
# per-file scan loop; ansible (the build-time hardener) and python are removed
# from the final image. A shell REMAINS only because the scan loop needs it —
# it is the tool's own invocation, not a general-purpose interpreter — and it
# is the pinned ENTRYPOINT (docker/yara/scan-list.sh, reads /list.txt).
#
#   docker build -t get-sybers/yara:latest -f docker/yara/Dockerfile docker
ARG BASE=debian:trixie-slim

FROM ${BASE} AS hardened
ARG DFIR_UID=2000
ARG DFIR_GID=2000
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends yara ansible-core
COPY yara/scan-list.sh /opt/dxdfir/scan-list.sh
COPY hardening/harden.yml /tmp/hardening/harden.yml
RUN set -eux; \
    chmod 0755 /opt/dxdfir/scan-list.sh; \
    ansible-playbook -c local -i localhost, /tmp/hardening/harden.yml -e harden_uid=${DFIR_UID} -e harden_gid=${DFIR_GID}; \
    # remove the build-time hardener and everything the tool doesn't need,
    # keeping only sh/dash for the scan loop
    rm -rf /usr/bin/ansible* /usr/lib/python3/dist-packages/ansible* \
           /etc/ansible /root/.ansible /tmp/hardening \
           /usr/bin/python3* /usr/lib/python3* /usr/bin/bash /bin/bash /usr/bin/perl*

FROM scratch
COPY --from=hardened / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/tmp
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/opt/dxdfir/scan-list.sh"]
LABEL org.opencontainers.image.title="get-sybers/yara" \
      org.opencontainers.image.description="Minimal hardened YARA for the DX_DFIR signatures lane: uid0 renamed+locked, no ansible/apt/pip/sudo/setuid, no python, runs as a fixed non-root uid (default 2000); sh kept only for the tool's own scan loop." \
      com.get-sybers.hardened="true"
