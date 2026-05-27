# syntax=docker/dockerfile:1.7
#
# Cepheus container image — published as ghcr.io/su1ph3r/cepheus.
#
# Why python-slim instead of a Nuitka binary base:
#   * Multi-arch builds (linux/amd64 + linux/arm64) are trivial with pip;
#     a Nuitka binary base would need separate per-arch builds.
#   * pip install of the wheel is the same code path users get locally,
#     so behavioural drift between container and pip install is zero.
#   * Image is ~210 MB after slim base + cepheus + docker-cli — small
#     enough for CI use, no benefit from going smaller.
#
# Why we bundle the docker CLI:
#   * `cepheus ci <image>` shells out to `docker run --rm ...` to spin
#     up an ephemeral enumeration container. Users would otherwise need
#     to bind-mount the host docker binary AND the socket.
#   * `cepheus enumerate --container-id X` shells out to `docker exec`
#     against a running container the user already has — needs the
#     docker socket bind-mounted (see docs/INSTALL.md for the exact
#     `docker run` flags).
#   * docker-cli alone (no daemon) is ~50 MB; the daemon is not needed
#     inside the container because we always talk to the HOST daemon
#     via the bind-mounted socket.

FROM python:3.12-slim AS base

# Pin debian frontend to avoid tty prompts during install. Install the
# docker CLI (client only — no daemon) and tini for clean signal handling.
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        tini \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && apt-get purge -y --auto-remove curl gnupg \
    && rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/docker.list

# Install cepheus from a wheel built in the surrounding workflow.
# Use BuildKit's COPY with --from=context for the wheel so the image
# stays platform-agnostic (the wheel is py3-none-any).
#
# PEP 427 normalises non-alphanumeric characters in the project name
# to underscores in the wheel filename, so cepheus-engine produces
# ``cepheus_engine-X.Y.Z-py3-none-any.whl``. The glob below tolerates
# both the legacy ``cepheus-X.Y.Z-...`` filename (pre-0.6.1 releases)
# and the post-rename ``cepheus_engine-X.Y.Z-...`` filename so an old
# wheel built outside CI doesn't fail to copy in.
COPY dist/cepheus*-py3-none-any.whl /tmp/

# Resolve the wheel path via `ls` first — `pip install /tmp/*.whl[html]`
# fails because bash interprets `[html]` as a glob character class and
# never expands the `*`. Resolving the path explicitly into a shell
# variable lets the `[html]` extras spec attach to the resolved path
# rather than being part of the glob pattern.
RUN whl=$(ls /tmp/cepheus*-py3-none-any.whl | head -n1) \
    && pip install --no-cache-dir "${whl}[html]" \
    && rm -f /tmp/cepheus*.whl

# Drop privileges by default. The container runs as a non-root user;
# the docker socket bind-mount handles its own permission negotiation
# via the docker group on the host (operators can override with --user).
RUN groupadd --system --gid 1000 cepheus \
    && useradd  --system --uid 1000 --gid 1000 --home /home/cepheus --create-home cepheus
USER cepheus
WORKDIR /home/cepheus

# tini ensures SIGTERM forwarding to the cepheus process so `docker stop`
# triggers clean shutdown instead of waiting for the 10s SIGKILL timeout.
ENTRYPOINT ["/usr/bin/tini", "--", "cepheus"]
CMD ["--help"]

# OCI labels for registry discoverability — GHCR renders these on the
# package landing page.
LABEL org.opencontainers.image.title="Cepheus" \
      org.opencontainers.image.description="Container Escape Scenario Modeler — enumerate posture, model escape paths, verify primitives." \
      org.opencontainers.image.source="https://github.com/Su1ph3r/Cepheus" \
      org.opencontainers.image.documentation="https://github.com/Su1ph3r/Cepheus/blob/main/docs/INSTALL.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Su1ph3r"
