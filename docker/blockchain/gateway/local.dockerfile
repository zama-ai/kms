# syntax=docker/dockerfile:1.4

# Build Stage
FROM rust:1.85-slim-bookworm AS builder

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

WORKDIR /app/gateway

# Copy entire project for workspace support
COPY . .

# Create bin directory and build using cargo install with caching
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/gateway/target,sharing=locked \
    mkdir -p /app/gateway/bin && \
    cargo install --path blockchain/gateway --root blockchain/gateway --bins

# Runtime Stage
FROM debian:stable-slim

# Install only required runtime dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        libprotobuf-dev \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/gateway

# Copy binaries and config
COPY --from=builder /app/gateway/blockchain/gateway/bin/ /app/gateway/bin/
COPY ./blockchain/gateway/config/ /app/gateway/config/

ENV PATH="/app/gateway/bin:$PATH"

# Change user to limit root access
RUN groupadd -g 10005 gateway && \
    useradd -m -u 10003 -g gateway gateway
RUN chown -R gateway:gateway /app/gateway
USER gateway
