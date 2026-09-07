# syntax=docker/dockerfile:1
#
# dxdfir/plaso — minimal hardened Plaso (pinned PyPI, libyal built from source).
# Plaso IS python and has three entry tools (log2timeline.py, psort.py,
# image_export.py) plus the psort wrapper, so python and a shell remain and
# there is no single ENTRYPOINT — the caller passes the full tool argv. ansible
# (the build-time hardener) is removed.
#
#   docker build -t dxdfir/plaso:latest -f docker/plaso/Dockerfile docker
ARG BASE=python:3.12-slim
ARG PLASO_VERSION=20260720

# ---- wheel-build stage: compile the libyal stack from source ----------------
FROM ${BASE} AS wheels
ARG PLASO_VERSION
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends build-essential pkg-config \
        zlib1g-dev libssl-dev libfuse3-dev; \
    pip wheel --no-cache-dir --wheel-dir /wheels "plaso==${PLASO_VERSION}"

FROM ${BASE} AS hardened
ARG DFIR_UID=2000
ARG DFIR_GID=2000
ARG PLASO_VERSION
COPY --from=wheels /wheels /wheels
RUN set -eux; \
    pip install --no-cache-dir --no-index --find-links /wheels "plaso==${PLASO_VERSION}"; \
    pip install --no-cache-dir ansible-core; \
    rm -rf /wheels; \
    ln -s /usr/local/bin/log2timeline /usr/local/bin/log2timeline.py; \
    ln -s /usr/local/bin/psort /usr/local/bin/psort.py; \
    ln -s /usr/local/bin/image_export /usr/local/bin/image_export.py; \
    printf 'plaso %s (pypi, libyal built from source)\n' "${PLASO_VERSION}" > /etc/dxdfir-plaso-version
# The image runs as a non-root uid (2000); the wrapper is the only python entry
# point psort is invoked through, so it MUST be world-READABLE or
# `python3 /opt/dxdfir/psort_wrapper.py` fails with Errno 13 for uid 2000. Pin the
# mode with a `chmod` in the RUN below (NOT `COPY --chmod`, which needs BuildKit —
# the ansible docker builder uses the legacy builder) rather than inheriting the
# build-context file's perms (which vary by checkout/umask and have shipped as
# 0640, breaking every psort render).
COPY plaso/psort_wrapper.py /opt/dxdfir/psort_wrapper.py
COPY hardening/harden.yml /tmp/hardening/harden.yml
RUN set -eux; \
    chmod 0644 /opt/dxdfir/psort_wrapper.py; \
    ansible-playbook -c local -i localhost, /tmp/hardening/harden.yml -e harden_uid=${DFIR_UID} -e harden_gid=${DFIR_GID}; \
    rm -rf /usr/local/bin/ansible* /usr/local/lib/python3*/site-packages/ansible* \
           /etc/ansible /root/.ansible /tmp/hardening

FROM scratch
COPY --from=hardened / /
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/tmp LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
LABEL org.opencontainers.image.title="dxdfir/plaso" \
      org.opencontainers.image.description="Minimal hardened Plaso (pinned PyPI, libyal from source) for the DX_DFIR plaso/evtx-extraction lanes: uid0 renamed+locked, no ansible/apt/pip/sudo/setuid, runs as a fixed non-root uid (default 2000) (python+sh irreducible; three entry tools, no single ENTRYPOINT)." \
      com.get-sybers.hardened="true"
