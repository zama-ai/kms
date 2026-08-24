# syntax=docker/dockerfile:1

################################################################
### Multistage build to reduce image size
## First stage sets up basic Rust build environment
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms/rust-golden-image:latest AS builder

# Cargo profile to build with. Override at build time with
# `--build-arg LTO_RELEASE=<profile>` to use a different profile,
# e.g. `release-lto-off` for faster CI link times.
ARG LTO_RELEASE=release-lto-thin
ARG SCCACHE_BUCKET
ARG SCCACHE_REGION=eu-west-3
ARG SCCACHE_S3_PREFIX
# Only enable the sccache S3 cache when a bucket is provided (CI passes one via
# the SCCACHE_BUCKET build-arg). Local builds (e.g. docker compose) leave it
# unset, so RUSTC_WRAPPER stays empty and the build compiles without the remote
# cache instead of failing to authenticate to S3.
ENV RUSTC_WRAPPER=${SCCACHE_BUCKET:+sccache}
ENV SCCACHE_IDLE_TIMEOUT=0
ENV SCCACHE_BUCKET=${SCCACHE_BUCKET}
ENV SCCACHE_REGION=${SCCACHE_REGION}
ENV SCCACHE_S3_KEY_PREFIX=${SCCACHE_S3_PREFIX}
ENV AWS_REGION=${SCCACHE_REGION}

WORKDIR /app/kms-core-client

# Workspace source (everything needed to resolve and build the workspace).
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY backward-compatibility ./backward-compatibility
COPY bc2wrap ./bc2wrap
COPY core ./core
COPY core-client ./core-client
COPY observability ./observability
COPY tools ./tools

# Single cargo build for all three binaries. Compared to three separate
# `cargo install` invocations, this:
#   - walks the workspace dep graph once instead of three times,
#   - runs each build script once instead of three times,
#   - lets cargo parallelize all link steps across binaries,
#   - shares a single sccache hit set with no race conditions.
#
# `-F threshold-execution/testing` is intentionally applied workspace-wide:
# all three binaries build in one pass, so `kms-custodian` and
# `kms-health-check` also link `threshold-execution` with `testing` enabled.
RUN --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
    --mount=type=secret,id=sccache_aws_access_key_id \
    --mount=type=secret,id=sccache_aws_secret_access_key \
    set -eu && \
    # The sccache S3 cache and its AWS credentials are only used in CI, where
    # SCCACHE_BUCKET is set. Local builds provide neither the bucket nor the
    # secrets, so skip the credential setup and remote cache there.
    if [ -n "${SCCACHE_BUCKET}" ]; then \
      export AWS_ACCESS_KEY_ID="$(cat /run/secrets/sccache_aws_access_key_id)"; \
      export AWS_SECRET_ACCESS_KEY="$(cat /run/secrets/sccache_aws_secret_access_key)"; \
    fi && \
    cargo build --locked --profile=${LTO_RELEASE} \
      -p kms              --bin kms-custodian \
      -p kms-core-client  --bin kms-core-client \
      -p kms-health-check --bin kms-health-check \
      -F threshold-execution/testing && \
    mkdir -p /app/kms-core-client/bin && \
    cp /app/kms-core-client/target/${LTO_RELEASE}/kms-custodian \
       /app/kms-core-client/target/${LTO_RELEASE}/kms-core-client \
       /app/kms-core-client/target/${LTO_RELEASE}/kms-health-check \
       /app/kms-core-client/bin/ && \
    if [ -n "${SCCACHE_BUCKET}" ]; then sccache --show-stats; fi


################################################################
# Runtime Stage
FROM --platform=$BUILDPLATFORM cgr.dev/zama.ai/glibc-dynamic:16-dev AS prod

# Install only required runtime dependencies
USER root
RUN apk add --no-cache \
        openssl \
        wget \
        libgcc \
        libstdc++

WORKDIR /app/kms-core-client

# Copy binaries (all three landed in /app/kms-core-client/bin via the
# single `cp` at the end of the build stage).
COPY --from=builder /app/kms-core-client/bin/ /app/kms-core-client/bin/

# Change user to limit root access
RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms

RUN chown -R kms:kms /app/kms-core-client
USER kms

ENV PATH="/app/kms-core-client/bin:$PATH"

################################################################
# Development Stage
FROM prod AS dev
