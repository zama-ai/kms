# syntax=docker/dockerfile:1.4

# Build Stage
FROM rust:1.84-slim-bookworm AS builder

# Install build dependencies with cache mount
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        make \
        protobuf-compiler \
        gcc \
        libssl-dev \
        libprotobuf-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/kms-core-client

# Copy entire project for workspace support
COPY . .

# Build using cargo install with caching
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/kms-core-client/target,sharing=locked \
    mkdir -p /app/kms-core-client/bin && \
    cargo install --path core-client --root core-client --bins



# Runtime Stage
FROM debian:stable-slim

# Install only required runtime dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/kms-core-client

# Copy binaries
COPY --from=builder /app/kms-core-client/core-client/bin/ /app/kms-core-client/bin/

ENV PATH="/app/kms-core-client/bin:$PATH"
