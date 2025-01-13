# syntax=docker/dockerfile:1

### Multistage build to reduce image size
## First stage sets up basic Rust build environment
FROM rust:1.82-slim-bookworm AS base

# Added memory usage optimization through `--no-install-recommends`
RUN --mount=type=cache,sharing=locked,target=/var/cache/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        dnsutils \
        gcc \
        git \
        iperf \
        iproute2 \
        iputils-ping \
        libprotobuf-dev \
        libssl-dev \
        make \
        net-tools \
        pkg-config \
        protobuf-compiler \
        ssh \
    && rm -rf /var/lib/apt/lists/*

# Add github.com to the list of known hosts. .ssh folder needs to be created first to avoid permission errors
RUN mkdir -p -m 0600 /root/.ssh
RUN ssh-keyscan -H github.com >> ~/.ssh/known_hosts
RUN --mount=type=secret,id=BLOCKCHAIN_ACTIONS_TOKEN,env=BLOCKCHAIN_ACTIONS_TOKEN git config --global url."https://$BLOCKCHAIN_ACTIONS_TOKEN@github.com".insteadOf ssh://git@github.com


## Second stage builds the kms-core binaries
FROM --platform=$BUILDPLATFORM base AS kms-core

# By default, cargo build --release.
# But you can provide --build-arg LTO_RELEASE="--profile release-lto-off" locally to build locally
ARG LTO_RELEASE=release

# Fetch dependencies and build binaries
WORKDIR /app/kms
COPY . .
RUN mkdir -p /app/kms/core/service/bin
ENV CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target
RUN --mount=type=cache,sharing=locked,target=/var/cache/buildkit \
    cargo fetch --locked
RUN --mount=type=cache,sharing=locked,target=/var/cache/buildkit \
    cargo build --locked --profile=${LTO_RELEASE} -p kms --bin kms-server --bin kms-gen-tls-certs --bin kms-init -F insecure && \
    cargo build --locked --profile=${LTO_RELEASE} -p kms --bin kms-gen-keys -F testing -F insecure && \
    cp /var/cache/buildkit/target/${LTO_RELEASE}/kms-server \
       /var/cache/buildkit/target/${LTO_RELEASE}/kms-gen-tls-certs \
       /var/cache/buildkit/target/${LTO_RELEASE}/kms-init \
       /var/cache/buildkit/target/${LTO_RELEASE}/kms-gen-keys \
    ./core/service/bin

## Third stage builds Go dependencies
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
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.35
RUN go install github.com/grpc-ecosystem/grpc-health-probe@${GRPC_HEALTH_PROBE_VERSION}
# Install yq-go to parse TOML configs in scripts
RUN go install github.com/mikefarah/yq/v4@latest

## Fourth stage: Copy the binaries from preceding stages
# This stage will be the final image
FROM --platform=$BUILDPLATFORM debian:stable-slim
RUN apt update && apt install -y libssl3 ca-certificates socat net-tools
WORKDIR /app/kms/core/service
COPY ./core/service/config/ /app/kms/core/service/config

# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="/app/kms/core/service/bin:$PATH"
# Copy the binaries from the kms-core and go-runtime stages
COPY --from=kms-core /app/kms/core/service/bin/ ./bin/
COPY --from=go-runtime /root/go/bin/grpc-health-probe ./bin/
COPY --from=go-runtime /root/go/bin/yq ./bin/

# Copy parent-side and enclave-side init scripts
COPY ./docker/core/service/start_parent_proxies.sh ./bin/
COPY ./docker/core/service/init_enclave.sh ./bin/

# Change user to limit root access
RUN groupadd -g 10002 kms && \
    useradd -m -u 10003 -g kms kms
# pre-create mount points for rights
RUN mkdir -p /app/kms/core/service/certs /app/kms/core/service/config
RUN chown -R kms:kms /app/kms
USER kms

# This is only meaningful when the image is used to build the EIF that runs
# inside of a Nitro enclave. During deployment on k8s, containers are started
# with commands defined in Helm charts.
CMD ["/bin/bash", "/app/kms/core/service/bin/init_enclave.sh"]
