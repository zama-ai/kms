# Multistage build to reduce image size
# First stage builds the binary
# This is a modified version of the gateway image.
# We should probably double check to make sure we need all dependencies
FROM rust:1.82-slim-bookworm AS base

RUN apt update && \
    apt install -y make protobuf-compiler ssh gcc libssl-dev libprotobuf-dev pkg-config

WORKDIR /app/simulator
COPY . .

# Install the binary leaving it in the WORKDIR/bin folder
RUN mkdir -p /app/simulator/bin
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo install --path blockchain/simulator --root blockchain/simulator --bins

# Second stage builds the runtime image.
# This stage will be the final image
FROM debian:stable-slim AS go-runtime

RUN apt update && \
    apt install -y libssl-dev libprotobuf-dev curl netcat-openbsd
WORKDIR /app/simulator

# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/simulator/bin"

# Third stage: Copy the binaries from the base stage and the go-runtime stage
FROM debian:stable-slim AS runtime
RUN apt update && apt install -y libssl3 wget
WORKDIR /app/simulator
# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/simulator/bin"

# Copy the binaries from the base stage
COPY --from=base /app/simulator/blockchain/simulator/bin/ /app/simulator/bin/
