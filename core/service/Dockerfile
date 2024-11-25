# syntax=docker/dockerfile:1.4

FROM rust:1.82-slim-bookworm AS builder

# Install only necessary build dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy entire project for workspace support
COPY . .

# Build with cargo install using caching
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo install --path . --bin kms-server

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Copy binary and parameters
COPY --from=builder /usr/local/cargo/bin/kms-server /usr/local/bin/
COPY parameters /app/parameters

CMD ["kms-server"]
