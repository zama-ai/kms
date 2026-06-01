# syntax=docker/dockerfile:1

################################################################
# Shared base stage: golden image + sccache config + workspace source.
# Every parallel build stage descends from this so the source COPYs
# are done once and reused.
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms/rust-golden-image:latest AS src

ARG SCCACHE_BUCKET
ARG SCCACHE_REGION=eu-west-3
ARG SCCACHE_S3_PREFIX
ENV RUSTC_WRAPPER=sccache
ENV SCCACHE_IDLE_TIMEOUT=0
ENV SCCACHE_BUCKET=${SCCACHE_BUCKET}
ENV SCCACHE_REGION=${SCCACHE_REGION}
ENV SCCACHE_S3_KEY_PREFIX=${SCCACHE_S3_PREFIX}
ENV AWS_REGION=${SCCACHE_REGION}

WORKDIR /app/kms-core-client

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY backward-compatibility ./backward-compatibility
COPY bc2wrap ./bc2wrap
COPY core ./core
COPY core-client ./core-client
COPY observability ./observability
COPY tools ./tools

################################################################
# Three independent build stages. BuildKit runs them concurrently
# on the same runner. Each stage has its own cargo registry cache
# (separate `id=` per stage) because cargo's registry source unpack
# is NOT safe across parallel processes — see rust-lang/cargo#8728.
# The cost is small: a one-time per-stage download (~50-100MB) from
# crates.io, in-region, fully parallelized.
# Each stage installs its binaries into /out/bin/.
FROM src AS build-custodian
RUN --mount=type=cache,id=kms-cargo-registry-custodian,target=/root/.cargo/registry,sharing=locked \
    --mount=type=secret,id=sccache_aws_access_key_id \
    --mount=type=secret,id=sccache_aws_secret_access_key \
    set -eu && \
    export AWS_ACCESS_KEY_ID="$(cat /run/secrets/sccache_aws_access_key_id)" && \
    export AWS_SECRET_ACCESS_KEY="$(cat /run/secrets/sccache_aws_secret_access_key)" && \
    cargo install --locked --path core/service --root /out --bin kms-custodian

FROM src AS build-core-client
RUN --mount=type=cache,id=kms-cargo-registry-core-client,target=/root/.cargo/registry,sharing=locked \
    --mount=type=secret,id=sccache_aws_access_key_id \
    --mount=type=secret,id=sccache_aws_secret_access_key \
    set -eu && \
    export AWS_ACCESS_KEY_ID="$(cat /run/secrets/sccache_aws_access_key_id)" && \
    export AWS_SECRET_ACCESS_KEY="$(cat /run/secrets/sccache_aws_secret_access_key)" && \
    cargo install --locked --path core-client --root /out --bins -F threshold-execution/testing

FROM src AS build-health-check
RUN --mount=type=cache,id=kms-cargo-registry-health-check,target=/root/.cargo/registry,sharing=locked \
    --mount=type=secret,id=sccache_aws_access_key_id \
    --mount=type=secret,id=sccache_aws_secret_access_key \
    set -eu && \
    export AWS_ACCESS_KEY_ID="$(cat /run/secrets/sccache_aws_access_key_id)" && \
    export AWS_SECRET_ACCESS_KEY="$(cat /run/secrets/sccache_aws_secret_access_key)" && \
    cargo install --locked --path tools/kms-health-check --root /out --bins && \
    sccache --show-stats

################################################################
# Runtime Stage
FROM --platform=$BUILDPLATFORM cgr.dev/zama.ai/glibc-dynamic:15.2.0-dev AS prod

USER root
RUN apk add --no-cache \
        openssl \
        wget \
        libgcc \
        libstdc++

WORKDIR /app/kms-core-client
RUN mkdir -p /app/kms-core-client/bin

# Collect binaries from the three parallel build stages.
COPY --from=build-custodian    /out/bin/ /app/kms-core-client/bin/
COPY --from=build-core-client  /out/bin/ /app/kms-core-client/bin/
COPY --from=build-health-check /out/bin/ /app/kms-core-client/bin/

RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms && \
    chown -R kms:kms /app/kms-core-client
USER kms

ENV PATH="/app/kms-core-client/bin:$PATH"

################################################################
# Development Stage
FROM prod AS dev
