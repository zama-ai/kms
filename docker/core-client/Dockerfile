# syntax=docker/dockerfile:1

################################################################
### Multistage build to reduce image size
## First stage sets up basic Rust build environment
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms/rust-golden-image:v0.12.1-dev AS builder

ARG APP_CACHE_DIR=kms-core-client

WORKDIR /app/kms-core-client

# Copy entire project for workspace support
COPY . .

# Build using cargo install with caching
RUN --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/${APP_CACHE_DIR}/target,sharing=locked \
    mkdir -p /app/kms-core-client/bin && \
    cargo install --locked --path core/service --root tools/service --bin kms-custodian && \
    cargo install --locked --path core-client --root core-client --bins && \
    cargo install --locked --path tools/kms-health-check --root tools/kms-health-check --bins


################################################################
# Runtime Stage
FROM --platform=$BUILDPLATFORM cgr.dev/zama.ai/glibc-dynamic:15.2.0-dev@sha256:911027da13121ac5f6a4480bcb3540b9f43330dddf60ceb1658bb02c504be38f AS prod

# Install only required runtime dependencies
USER root
RUN apk add --no-cache \
        openssl \
        wget \
        libgcc \
        libstdc++

WORKDIR /app/kms-core-client

# Copy binaries
COPY --from=builder /app/kms-core-client/core-client/bin/ /app/kms-core-client/bin/
COPY --from=builder /app/kms-core-client/tools/kms-health-check/bin/ /app/kms-core-client/bin/
COPY --from=builder /app/kms-core-client/tools/service/bin/ /app/kms-core-client/bin/

# Change user to limit root access
RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms

RUN chown -R kms:kms /app/kms-core-client
USER kms

ENV PATH="/app/kms-core-client/bin:$PATH"

################################################################
# Development Stage
FROM prod AS dev
