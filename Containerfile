# syntax=docker/dockerfile:1
#
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
#
# Portable sandbox image for the `encryption-helper` command-line interface.
#
# The purpose of this image is to let an operator run key generation,
# encryption, signing and inventory scanning without installing Python, the
# `cryptography` wheel, or this package onto the host. The host contributes a
# single bind-mounted working directory and nothing else.
#
# Build (either engine; the file is named Containerfile so that Podman picks it
# up by default, and a `Dockerfile` symlink is provided so that `docker build .`
# also works):
#
#   podman build -t encryption-helper:0.0.2 .
#   docker build -f Containerfile -t encryption-helper:0.0.2 .
#
# Run via the supplied wrapper, which applies the hardening flags documented in
# docs/SANDBOX.md:
#
#   ./scripts/sandbox.sh keygen --algorithm ed25519 --no-passphrase --name svc
#
# This image deliberately has no HEALTHCHECK. The entry point is a one-shot
# command-line tool that exits when its work is done, not a long-running
# service, so there is no steady state for a probe to observe.

# ---------------------------------------------------------------------------
# Base image
# ---------------------------------------------------------------------------
#
# TODO: pin by digest before this image is promoted to a controlled registry.
# A tag is mutable, so a tag-only reference cannot support reproducible builds
# or a meaningful provenance attestation. A maintainer with network access
# obtains the digest with one of:
#
#   docker buildx imagetools inspect python:3.12-slim \
#     --format '{{.Manifest.Digest}}'
#   docker pull python:3.12-slim && docker image inspect \
#     --format '{{index .RepoDigests 0}}' python:3.12-slim
#   skopeo inspect docker://docker.io/library/python:3.12-slim \
#     | jq -r .Digest
#
# The result is then substituted into BOTH stages below, as
# `python:3.12-slim@sha256:<digest>`, and into the
# `org.opencontainers.image.base.name` label.
#
# 3.12 is chosen rather than the newest interpreter because it sits inside the
# `requires-python = ">=3.10"` floor declared in pyproject.toml and is the
# version the published test matrix exercises most heavily.

# ---------------------------------------------------------------------------
# Stage 1: build the wheel
# ---------------------------------------------------------------------------
#
# The package is built here and installed in the next stage from the resulting
# artefact alone. The separation keeps the source tree, the PEP 517 build
# backend (poetry-core) and pip's build scratch space out of the shipped
# filesystem, so the image that reaches a reviewer contains the distribution
# that would be published to an index and nothing that produced it.
FROM python:3.12-slim AS build

# Byte-code in the build stage would be discarded anyway, and pip's cache and
# version self-check add network calls and layer size without affecting the
# artefact.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /src

# Copied explicitly rather than with `COPY . .` so that the build inputs are
# auditable from this file alone, and so that an unrelated change in the
# repository does not invalidate the layer cache. Each entry is required by the
# project metadata: pyproject.toml declares the build, README.md is the
# `readme`, LICENSE and NOTICE are the declared `license-files`, and
# encryption_helper/ is the package itself. MANIFEST.in is not needed, because
# it governs the source distribution rather than the wheel.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY encryption_helper ./encryption_helper

# `pip wheel` is used in preference to `python -m build` because it resolves
# and materialises the full dependency closure -- the project wheel plus
# `cryptography` and its own requirements -- into one directory. The next stage
# can then install with `--no-index`, which means the runtime stage performs no
# dependency resolution and cannot silently acquire a package that was not
# present at build time.
RUN python -m pip wheel --wheel-dir /wheels /src

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Version is an argument so that a release pipeline can stamp the label without
# editing this file. The default must track the `version` field in
# pyproject.toml.
ARG VERSION=0.0.2

LABEL org.opencontainers.image.title="encryption-helper" \
      org.opencontainers.image.description="Command-line sandbox for generating, protecting and using asymmetric key pairs" \
      org.opencontainers.image.source="https://github.com/hsbc/encryption-helper-python" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12-slim"

# PYTHONDONTWRITEBYTECODE prevents the interpreter attempting to write .pyc
# files, which would fail noisily under the read-only root filesystem the
# container is expected to run with. PYTHONUNBUFFERED makes diagnostics on
# stderr appear in the correct order relative to stdout when output is piped or
# captured by a log collector rather than attached to a terminal.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

# A dedicated account, not `nobody` and not root.
#
# This tool enforces owner-only (0600) permissions on every private key it
# writes, and that control is vacuous if the process is uid 0: root bypasses
# the permission bits it has just set, and any bind-mounted key material would
# be written into the host directory as root-owned.
#
# The uid and gid are fixed at 10001 so that host-side file ownership is
# predictable and so that the value sits well above the range Debian allocates
# to system accounts, which avoids a collision with a future base-image
# package. `--no-log-init` avoids allocating a sparse lastlog record sized by
# the uid.
RUN groupadd --system --gid 10001 ehelper \
 && useradd --system --uid 10001 --gid 10001 --no-log-init \
      --home-dir /home/ehelper --create-home \
      --shell /usr/sbin/nologin ehelper

# The wheels built in stage 1, installed with no index and no network.
# `--no-deps` is not used: the dependency closure is already present in /wheels,
# so resolution is satisfied locally and a missing requirement fails the build
# rather than being fetched. The directory is removed in the same layer so the
# artefacts do not persist in the final filesystem.
COPY --from=build /wheels /tmp/wheels
RUN python -m pip install --no-index --find-links=/tmp/wheels encryption-helper \
 && rm -rf /tmp/wheels

# No `apt-get upgrade` is performed. Mutating the package set at build time
# would make the image's contents depend on the moment it was built, which
# defeats pinning the base by digest. Patching is handled by rebuilding against
# a newer base digest, which is an auditable change to this file.

# /work is the sole intended interface with the host and is expected to be
# replaced by a bind mount at run time. It is created owned by the unprivileged
# account so that the image is also usable without a mount -- for example when
# reading from stdin and writing to stdout -- and group-writable so that a
# caller who overrides the uid with `--user` but keeps the gid can still write.
RUN install --directory --owner 10001 --group 10001 --mode 0770 /work
WORKDIR /work

# Numeric form rather than the account name. A numeric USER can be verified as
# non-root by an orchestrator without resolving /etc/passwd, which is what
# Kubernetes `runAsNonRoot` and comparable admission policies require.
USER 10001:10001

# No CMD. The entry point is the console script installed by the wheel, so
# arguments given to `docker run` or `podman run` are the tool's own arguments:
#
#   podman run --rm encryption-helper:0.0.2 keygen --help
#
# With no CMD, a bare `run` with no arguments reports a usage error listing the
# available commands. A default CMD would instead cause it to perform
# cryptographic work, which is the wrong default for a tool that writes key
# material.
ENTRYPOINT ["encryption-helper"]
