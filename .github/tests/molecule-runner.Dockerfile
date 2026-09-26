# syntax=docker/dockerfile:1
# get-sybers/molecule — the containerised molecule runner (a non-tool image:
# GoDFIR-toolz images.yml `non_tool_repos`). Static docker CLI only — the
# daemon is always the host's, reached via the mounted socket.
FROM python:3.12-slim
ADD https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz /tmp/docker.tgz
RUN tar -xzf /tmp/docker.tgz -C /tmp && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker /tmp/docker.tgz
# requests + docker SDK: community.docker's modules import them
RUN pip install --no-cache-dir molecule ansible-core requests docker
