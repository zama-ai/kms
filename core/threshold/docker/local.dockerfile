# syntax=docker/dockerfile:1.4

# RUST_IMAGE_VERSION arg can be used to override the default version
ARG RUST_IMAGE_VERSION=latest

# Build Stage - Rust binary
FROM rust:slim-bookworm AS builder

# Install minimal build dependencies, alphabetically sorted
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

# Setup SSH keys for git
RUN mkdir -p -m 0600 /root/.ssh && \
    ssh-keyscan -H github.com >> ~/.ssh/known_hosts

# Copy project files
COPY . .

# Build with cargo install and caching
ARG FEATURES
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/ddec/target,sharing=locked \
    mkdir -p /app/ddec/bin && \
    # cargo install --path . --bins --no-default-features --features=${FEATURES}
    # NOTE: if we're in a workspace then we need to set a different path
    cargo install --path core/threshold --root . --bins --no-default-features --features=${FEATURES}

# Go tooling stage - only for grpc-health-probe
FROM debian:stable-slim AS go-builder

# Install minimal Go build dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Go and grpc-health-probe
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

# Final runtime stage
FROM debian:stable-slim

# Install minimal runtime dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libprotobuf-dev \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/ddec

# Copy binaries from previous stages
COPY --from=builder /app/ddec/bin/ /app/ddec/bin/
COPY --from=go-builder /root/go/bin/grpc-health-probe /app/ddec/bin/

ENV PATH="/app/ddec/bin:$PATH"

EXPOSE 50000

# Change user to limit root access
RUN groupadd -g 10002 kms && \
    useradd -m -u 10004 -g kms kms
RUN chown -R kms:kms /app/ddec
USER kms

# Add health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["grpc-health-probe", "-addr=:50000"]
