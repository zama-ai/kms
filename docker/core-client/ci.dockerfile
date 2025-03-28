# syntax=docker/dockerfile:1.4


# RUST_IMAGE_VERSION arg can be used to override the default version
ARG RUST_IMAGE_VERSION=1.85.1

### Multistage build to reduce image size
## First stage sets up basic Rust build environment
FROM rust:${RUST_IMAGE_VERSION}-slim-bookworm AS builder

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

###### k6 test runner ######
# Second stage builds the k6 test runner
FROM golang:1.24.1-alpine${ALPINE_VERSION} AS go-builder

RUN apk --update add git && \
    go install go.k6.io/xk6/cmd/xk6@latest

RUN xk6 build --with github.com/grafana/xk6-exec@latest



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

COPY --from=go-builder /go/k6 /app/kms-core-client/k6/k6
COPY --from=go-builder /go/bin/xk6 /app/kms-core-client/k6/bin

ENV PATH="/app/kms-core-client/bin:$PATH"
