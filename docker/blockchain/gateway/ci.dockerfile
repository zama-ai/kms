# syntax=docker/dockerfile:1
# Multistage build to reduce image size
FROM rust:1.85-slim-bookworm AS base

ARG LTO_RELEASE=release

# Install build dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    git \
    libprotobuf-dev \
    libssl-dev \
    make \
    pkg-config \
    protobuf-compiler \
    ssh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/gateway
COPY . .

# Setup SSH and git
RUN mkdir -p -m 0600 /root/.ssh && \
    ssh-keyscan -H github.com >> ~/.ssh/known_hosts && \
    mkdir -p /app/gateway/bin

# Configure git with secure token handling
RUN --mount=type=secret,id=BLOCKCHAIN_ACTIONS_TOKEN,env=BLOCKCHAIN_ACTIONS_TOKEN \
    git config --global url."https://$BLOCKCHAIN_ACTIONS_TOKEN@github.com".insteadOf ssh://git@github.com

# Build with improved caching
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/gateway/target,sharing=locked \
    cargo install --profile=${LTO_RELEASE} --path blockchain/gateway --root blockchain/gateway --bins


# Final runtime stage
FROM debian:stable-slim AS runtime

# Install runtime dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libssl3 \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/gateway
ENV PATH="$PATH:/app/gateway/bin"

# Copy binaries and config
COPY --from=base /app/gateway/blockchain/gateway/bin/ /app/gateway/bin/
COPY ./blockchain/gateway/config/ /app/gateway/config/

# Change user to limit root access
RUN groupadd -g 10003 gateway && \
    useradd -m -u 10005 -g gateway gateway
RUN chown -R gateway:gateway /app/gateway
USER gateway
