# Multistage build to reduce image size
# First stage builds the binary
FROM rust:1.79-slim-bookworm as base

RUN apt update && \
    apt install -y make protobuf-compiler ssh git gcc libssl-dev libprotobuf-dev pkg-config

WORKDIR /app/gateway
COPY . .

# Add github.com to the list of known hosts. .ssh folder needs to be created first to avoid permission errors
RUN mkdir -p -m 0600 /root/.ssh
RUN ssh-keyscan -H github.com >> ~/.ssh/known_hosts

# Install the binary leaving it in the WORKDIR/bin folder
RUN mkdir -p /app/gateway/bin
RUN git config --global url."https://${BLOCKCHAIN_ACTIONS_TOKEN}@github.com".insteadOf ssh://git@github.com
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo install --path blockchain/gateway --root blockchain/gateway --bins

# Second stage builds the runtime image.
# This stage will be the final image
FROM debian:stable-slim as go-runtime

RUN apt update && \
    apt install -y libssl-dev libprotobuf-dev curl netcat-openbsd
WORKDIR /app/gateway
RUN mkdir -p /app/gateway/config

# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/gateway/bin"

# Third stage: Copy the binaries from the base stage and the go-runtime stage
FROM debian:stable-slim as runtime
RUN apt update && apt install -y libssl3
WORKDIR /app/gateway
# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/gateway/bin"

# Copy the binaries from the base stage
COPY --from=base /app/gateway/blockchain/gateway/bin/ /app/gateway/bin/
COPY ./blockchain/gateway/config/ /app/gateway/config/

