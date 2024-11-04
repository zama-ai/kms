# syntax=docker/dockerfile:1

### Multistage build to reduce image size
## First stage sets up basic Rust build environment
FROM rust:1.81-slim-bookworm AS base

RUN --mount=type=cache,sharing=locked,target=/var/cache/apt apt update && \
    apt install -y make protobuf-compiler iproute2 iputils-ping iperf net-tools dnsutils ssh git gcc libssl-dev libprotobuf-dev pkg-config

# Add github.com to the list of known hosts. .ssh folder needs to be created first to avoid permission errors
RUN mkdir -p -m 0600 /root/.ssh
RUN ssh-keyscan -H github.com >> ~/.ssh/known_hosts
RUN --mount=type=secret,id=BLOCKCHAIN_ACTIONS_TOKEN,env=BLOCKCHAIN_ACTIONS_TOKEN git config --global url."https://$BLOCKCHAIN_ACTIONS_TOKEN@github.com".insteadOf ssh://git@github.com

## Second stage builds the kms-core binaries
FROM --platform=$BUILDPLATFORM base AS kms-core

# Fetch dependencies and build binaries
WORKDIR /app/kms
COPY . .
RUN mkdir -p /app/kms/core/service/bin
ENV CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target
RUN --mount=type=cache,sharing=locked,target=/var/cache/buildkit \
    cargo fetch --locked
RUN --mount=type=cache,sharing=locked,target=/var/cache/buildkit \
    cargo build --locked --release -p kms --bin kms-server --bin kms-gen-tls-certs --bin kms-init -F insecure && \
    cargo build --locked --release -p kms --bin kms-gen-keys -F testing -F insecure && \
    cp /var/cache/buildkit/target/release/kms-server \
       /var/cache/buildkit/target/release/kms-gen-tls-certs \
       /var/cache/buildkit/target/release/kms-init \
       /var/cache/buildkit/target/release/kms-gen-keys \
    ./core/service/bin

## Third stage builds nitro-cli (used to start enclaves only)
FROM --platform=$BUILDPLATFORM base AS nitro-cli

WORKDIR /build
RUN git clone https://github.com/aws/aws-nitro-enclaves-cli --branch v1.3.3 --single-branch

WORKDIR aws-nitro-enclaves-cli
RUN make nitro-cli-native

## Fourth stage builds Go dependencies
FROM --platform=$BUILDPLATFORM debian:stable-slim AS go-runtime
WORKDIR /app/kms

RUN --mount=type=cache,sharing=locked,target=/var/cache/apt apt update && \
    apt install -y curl netcat-openbsd

# We are going to need grpc-health-probe to check the health of the grpc server for docker-compose or future deployments
# Install go because grpc-health-probe is written in go and we need to compile it
ARG TARGETOS
ARG TARGETARCH
ARG go_file=go1.21.6.$TARGETOS-$TARGETARCH.tar.gz
RUN curl -OL https://go.dev/dl/$go_file
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf $go_file
RUN rm $go_file
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"
# Install grpc-health-probe
RUN go install github.com/grpc-ecosystem/grpc-health-probe@latest

## Fifth stage: Copy the binaries from preceding stages
# This stage will be the final image
FROM --platform=$BUILDPLATFORM debian:stable-slim
RUN apt update && apt install -y libssl3 ca-certificates curl jq socat
WORKDIR /app/kms/core/service

RUN mkdir -p /app/kms/core/service/keys

COPY ./core/service/config/ /app/kms/core/service/config

# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="/app/kms/core/service/bin:$PATH"
# Copy the binaries from the kms-core, go-runtime and nitro-cli stages
COPY --from=kms-core /app/kms/core/service/bin/ /app/kms/core/service/bin/
COPY --from=nitro-cli /build/aws-nitro-enclaves-cli/build/nitro_cli/release/nitro-cli /app/kms/core/service/bin
COPY --from=go-runtime /root/go/bin/grpc-health-probe /app/kms/core/service/bin/

# Copy parent-side and enclave-side init scripts
COPY ./core/service/operations/docker/start_enclave_and_proxies.sh /app/kms/core/service/bin/
COPY ./core/service/operations/docker/init_enclave_centralized.sh /app/kms/core/service/bin/

# This is only meaningful when the image is used to build the EIF that runs
# inside of a Nitro enclave. During deployment on k8s, containers are started
# with commands defined in Helm charts.
CMD ["/bin/bash", "/app/kms/core/service/bin/init_enclave_centralized.sh"]
