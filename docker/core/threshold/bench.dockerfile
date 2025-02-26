# syntax=docker/dockerfile:1.4

# RUST_IMAGE_VERSION arg can be used to override the default version
ARG RUST_IMAGE_VERSION=latest

# Multistage build to reduce image size
FROM rust:${RUST_IMAGE_VERSION}-slim-bookworm AS builder

# Install only essential build dependencies, alphabetically sorted
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        git \
        libprotobuf-dev \
        libssl-dev \
        make \
        pkg-config \
        protobuf-compiler \
        ssh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/ddec

# Setup SSH and git access
RUN mkdir -p -m 0600 /root/.ssh && \
    ssh-keyscan -H github.com >> ~/.ssh/known_hosts && \
    mkdir -p /app/ddec/bin

# Configure git with secure token handling
RUN --mount=type=secret,id=BLOCKCHAIN_ACTIONS_TOKEN \
    export BLOCKCHAIN_ACTIONS_TOKEN=$(cat /run/secrets/BLOCKCHAIN_ACTIONS_TOKEN) && \
    git config --global url."https://${BLOCKCHAIN_ACTIONS_TOKEN}@github.com".insteadOf ssh://git@github.com

# Copy project files
COPY . /app/ddec

# Build with improved caching
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/ddec/target,sharing=locked \
    cargo install --path core/threshold --root core/threshold --bins --features=choreographer

# Go toolchain stage for grpc-health-probe
FROM debian:stable-slim AS go-builder

# Install minimal Go build dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Go with platform support
ARG TARGETOS
ARG TARGETARCH
ARG GO_VERSION=1.21.6
RUN curl -o go.tgz -L "https://go.dev/dl/go${GO_VERSION}.${TARGETOS}-${TARGETARCH}.tar.gz" && \
    tar -C /usr/local -xzf go.tgz && \
    rm go.tgz

ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"

# Install grpc-health-probe with caching
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.35
RUN --mount=type=cache,target=/root/go/pkg \
    go install github.com/grpc-ecosystem/grpc-health-probe@${GRPC_HEALTH_PROBE_VERSION}

# Final minimal runtime stage
FROM debian:stable-slim

# Install only required runtime dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libprotobuf-dev \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/ddec
ENV PATH="/app/ddec/bin:$PATH"

# Copy only necessary binaries
COPY --from=builder /app/ddec/core/threshold/bin/ /app/ddec/bin/
COPY --from=go-builder /root/go/bin/grpc-health-probe /app/ddec/bin/grpc-health-probe

EXPOSE 50000

# Health check configuration
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["grpc-health-probe", "-addr=:50000"]
