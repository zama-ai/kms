# syntax=docker/dockerfile:1.4

# Build Stage
FROM rust:1.82-slim-bookworm AS builder

# Install build dependencies with cache mount
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libprotobuf-dev \
    libssl-dev \
    make \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/kms-connector

# Copy entire project for workspace support
COPY . .

# Create bin directory and build using cargo install with caching
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/kms-connector/target,sharing=locked \
    mkdir -p /app/kms-connector/bin && \
    cargo install --path blockchain/connector --root blockchain/connector --bins

# Runtime Stage
FROM debian:stable-slim

# Install only required runtime dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/kms-connector

# Copy binaries and config
COPY --from=builder /app/kms-connector/blockchain/connector/bin/ /app/kms-connector/bin/
COPY ./blockchain/connector/config/ /app/kms-connector/config/

ENV PATH="/app/kms-connector/bin:$PATH"
