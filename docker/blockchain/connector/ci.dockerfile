# syntax=docker/dockerfile:1
# Multistage build to reduce image size
#change for test
FROM rust:1.84-slim-bookworm AS base

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
    pkg-config \
    protobuf-compiler \
    ssh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/kms-connector
COPY . .

# Setup SSH and git
RUN mkdir -p -m 0600 /root/.ssh && \
    ssh-keyscan -H github.com >> ~/.ssh/known_hosts && \
    mkdir -p /app/kms-connector/bin

# Configure git with secure token handling
RUN --mount=type=secret,id=BLOCKCHAIN_ACTIONS_TOKEN,env=BLOCKCHAIN_ACTIONS_TOKEN \
    git config --global url."https://$BLOCKCHAIN_ACTIONS_TOKEN@github.com".insteadOf ssh://git@github.com

# Build with improved caching
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/kms-connector/target,sharing=locked \
    cargo install --profile=${LTO_RELEASE} --path blockchain/connector --root blockchain/connector --bins

# Dependencies stage
FROM debian:stable-slim AS dependencies

WORKDIR /app/kms-connector
RUN mkdir -p /app/kms-connector/config
ENV PATH="$PATH:/app/kms-connector/bin"

# Final runtime stage
FROM debian:stable-slim AS runtime

# Install minimal runtime dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/kms-connector
ENV PATH="$PATH:/app/kms-connector/bin"

# Copy binaries and config
COPY --from=base /app/kms-connector/blockchain/connector/bin/ /app/kms-connector/bin/
COPY ./blockchain/connector/config/ /app/kms-connector/config/

# Change user to limit root access
RUN groupadd -g 10002 kms && \
    useradd -m -u 10003 -g kms kms
RUN chown -R kms:kms /app/kms-connector
USER kms
