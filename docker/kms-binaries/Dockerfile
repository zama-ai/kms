# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms/rust-golden-image:latest AS builder

# Cargo profile to build with.
# But you can provide --build-arg LTO_RELEASE="--profile release-lto-off" locally to build locally.
ARG LTO_RELEASE=release-lto-thin
ARG SCCACHE_BUCKET
ARG SCCACHE_REGION=eu-west-3
ARG SCCACHE_S3_PREFIX
ENV RUSTC_WRAPPER=sccache
ENV SCCACHE_IDLE_TIMEOUT=0
ENV SCCACHE_BUCKET=${SCCACHE_BUCKET}
ENV SCCACHE_REGION=${SCCACHE_REGION}
ENV SCCACHE_S3_KEY_PREFIX=${SCCACHE_S3_PREFIX}
ENV AWS_REGION=${SCCACHE_REGION}

WORKDIR /app/kms-binaries

# Copy only what is needed to build the shared runtime binaries.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY backward-compatibility ./backward-compatibility
COPY bc2wrap ./bc2wrap
COPY core ./core
COPY core-client ./core-client
COPY observability ./observability
COPY tools ./tools

RUN mkdir -p /out/core-service/bin /out/core-client/bin

# `cargo fetch` only downloads dependencies; it does not compile. The global
# `RUSTC_WRAPPER=sccache` is still consulted for cargo's `rustc -vV` probe,
# which would make sccache start up and hit S3 (and thus need AWS creds). Unset
# the wrapper for this step so the fetch stays credential-free.
RUN --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
    RUSTC_WRAPPER= cargo fetch --locked

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
    export AWS_ACCESS_KEY_ID="$(cat /run/secrets/sccache_aws_access_key_id)" && \
    export AWS_SECRET_ACCESS_KEY="$(cat /run/secrets/sccache_aws_secret_access_key)" && \
    cargo build --locked --profile=${LTO_RELEASE} \
        -p kms --bin kms-server --bin kms-gen-tls-certs --bin kms-init --bin kms-custodian --bin kms-gen-keys \
        -p kms-core-client --bin kms-core-client \
        -p kms-health-check --bin kms-health-check \
        -F kms/insecure \
    -F threshold-execution/testing && \
    sccache --show-stats && \
    cp /app/kms-binaries/target/${LTO_RELEASE}/kms-server \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-gen-tls-certs \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-init \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-gen-keys \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-custodian \
       /out/core-service/bin/ && \
    cp /app/kms-binaries/target/${LTO_RELEASE}/kms-core-client \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-health-check \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-custodian \
       /out/core-client/bin/

FROM scratch AS prod

COPY --from=builder /out /out

FROM prod AS dev
