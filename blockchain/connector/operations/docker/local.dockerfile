# Multistage build to reduce image size
# First stage builds the binary
FROM rust:1.78-slim-buster as base

RUN apt update && \
    apt install -y make protobuf-compiler iproute2 iputils-ping iperf net-tools dnsutils ssh git gcc libssl-dev libprotobuf-dev

WORKDIR /app/kms-connector
COPY . .

# Install the binary leaving it in the WORKDIR/bin folder
RUN mkdir -p /app/kms-connector/bin
RUN cargo install --path blockchain/connector --root blockchain/connector --bins

# Second stage builds the runtime image.
# This stage will be the final image
FROM debian:stable-slim as go-runtime

RUN apt update && \
    apt install -y iproute2 iputils-ping iperf net-tools dnsutils libssl-dev libprotobuf-dev curl netcat-openbsd
WORKDIR /app/kms-connector
RUN mkdir -p /app/kms-connector/config

# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/kms-connector/bin"

# Third stage: Copy the binaries from the base stage and the go-runtime stage
FROM debian:stable-slim as runtime
WORKDIR /app/kms-connector
# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/kms-connector/bin"

# Copy the binaries from the base stage
COPY --from=base /app/kms-connector/blockchain/connector/bin/ /app/kms-connector/bin/
COPY ./blockchain/connector/config/default.toml /app/kms-connector/config/default.toml

ENTRYPOINT ["/bin/bash"]
