# Multistage build to reduce image size
# First stage builds the binary
FROM rust:1.79-slim-bookworm AS base

RUN apt update && \
    apt install -y make protobuf-compiler iproute2 iputils-ping iperf net-tools dnsutils ssh git gcc libssl-dev libprotobuf-dev pkg-config

WORKDIR /app/kms-connector
COPY . .

# Add github.com to the list of known hosts. .ssh folder needs to be created first to avoid permission errors
RUN mkdir -p -m 0600 /root/.ssh
RUN ssh-keyscan -H github.com >> ~/.ssh/known_hosts

# Install the binary leaving it in the WORKDIR/bin folder
RUN mkdir -p /app/kms-connector/bin
RUN git config --global url."https://${BLOCKCHAIN_ACTIONS_TOKEN}@github.com".insteadOf ssh://git@github.com
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo install --path blockchain/connector --root blockchain/connector --bins

# Second stage builds the runtime image.
# This stage will be the final image
FROM debian:stable-slim AS go-runtime

RUN apt update && \
    apt install -y iproute2 iputils-ping iperf net-tools dnsutils libssl-dev libprotobuf-dev curl netcat-openbsd
WORKDIR /app/kms-connector
RUN mkdir -p /app/kms-connector/config

# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/kms-connector/bin"

# Third stage: Copy the binaries from the base stage and the go-runtime stage
FROM debian:stable-slim AS runtime
RUN apt update && apt install -y libssl3
WORKDIR /app/kms-connector
# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/kms-connector/bin"

# Copy the binaries from the base stage
COPY --from=base /app/kms-connector/blockchain/connector/bin/ /app/kms-connector/bin/
COPY ./blockchain/connector/config/default.toml /app/kms-connector/config/default.toml

