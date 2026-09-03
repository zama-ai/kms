# syntax=docker/dockerfile:1

ARG RUST_GOLDEN_IMAGE=ghcr.io/zama-ai/kms/rust-golden-image:latest

FROM --platform=$BUILDPLATFORM ${RUST_GOLDEN_IMAGE} AS builder

# Cargo profile to build with.
# Use --build-arg LTO_RELEASE=release-lto-off for faster local linking.
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

WORKDIR /app/kms-binaries

# Workspace source (everything needed to resolve and build the workspace).
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
# Single parameterized cargo build for all binaries. Compared to separate
# `cargo install` invocations, this:
#   - walks the workspace dep graph once instead of three times,
#   - runs each build script once instead of three times,
#   - lets cargo parallelize all link steps across binaries,
#   - shares a single sccache hit set with no race conditions.
ARG KMS_FLAVOR=secure
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,id=kms-binaries-target-${TARGETARCH}-${KMS_FLAVOR},target=/app/kms-binaries/target,sharing=locked \
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
    case "${KMS_FLAVOR}" in \
      secure) set -- ;; \
      insecure) set -- --features insecure ;; \
      *) echo "Unsupported KMS_FLAVOR: ${KMS_FLAVOR}" >&2; exit 1 ;; \
    esac && \
    cargo build --locked --profile="${LTO_RELEASE}" \
        -p kms --bin kms-server --bin kms-gen-tls-certs --bin kms-init --bin kms-custodian --bin kms-gen-keys \
        -p kms-core-client --bin kms-core-client \
        -p kms-health-check --bin kms-health-check \
        "$@" && \
    actual_flavor=secure && \
    if /app/kms-binaries/target/${LTO_RELEASE}/kms-core-client --help 2>&1 | grep -q insecure-key-gen; then \
      actual_flavor=insecure; \
    fi && \
    if [ "${actual_flavor}" != "${KMS_FLAVOR}" ]; then \
      echo "Built ${actual_flavor} client for requested ${KMS_FLAVOR} flavor" >&2; exit 1; \
    fi && \
    cp /app/kms-binaries/target/${LTO_RELEASE}/kms-server \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-gen-tls-certs \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-init \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-gen-keys \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-custodian \
       /out/core-service/bin/ && \
    cp /app/kms-binaries/target/${LTO_RELEASE}/kms-core-client \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-health-check \
       /app/kms-binaries/target/${LTO_RELEASE}/kms-custodian \
       /out/core-client/bin/ && \
    printf '%s\n' "${KMS_FLAVOR}" > /out/kms-build-flavor && \
    if [ -n "${SCCACHE_BUCKET}" ]; then sccache --show-stats; fi

# Export the selected flavor's binaries for the package-only Dockerfiles.
FROM scratch AS binaries

COPY --from=builder /out /out

# The production CI template always builds a target named `prod`.
FROM binaries AS prod
