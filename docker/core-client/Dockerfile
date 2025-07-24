# syntax=docker/dockerfile:1

################################################################
### Multistage build to reduce image size
## First stage sets up basic Rust build environment
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms/rust-golden-image:latest AS builder

WORKDIR /app/kms-core-client

# Copy entire project for workspace support
COPY . .

# Build using cargo install with caching
RUN --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    mkdir -p /app/kms-core-client/bin && \
    cargo install --path core-client --root core-client --bins


################################################################
# Runtime Stage
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/glibc-dynamic:latest-dev AS prod

# Install only required runtime dependencies
USER root
RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    --mount=type=cache,target=/var/lib/apk,sharing=locked \
    apk add --no-cache \
        openssl \
        wget \
        libgcc \
        libstdc++ \
    && rm -rf /var/lib/apk/lists/*

WORKDIR /app/kms-core-client

# Copy binaries
COPY --from=builder /app/kms-core-client/core-client/bin/ /app/kms-core-client/bin/

# Change user to limit root access
RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms

RUN chown -R kms:kms /app/kms-core-client
USER kms

ENV PATH="/app/kms-core-client/bin:$PATH"

################################################################
# Development Stage
FROM prod AS dev
