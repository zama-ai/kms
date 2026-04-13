# syntax=docker/dockerfile:1

##################################################################
# THIS FILE IS MEANT TO BE USED FOR NIST TESTING                 #
# SO THE IMAGE IT USES SHOULD BE PUBLICLY ACCESSIBLE             #
##################################################################


################################################################
## Second stage builds the kms-core binaries
FROM rust:1.91.1-slim-bookworm AS kms-threshold

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        git \
        libprotobuf-dev \
        libssl-dev \
        make \
        pkg-config \
        protobuf-compiler \
        ssh \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app/ddec

# Setup SSH keys for git
RUN mkdir -p -m 0600 /root/.ssh && \
    ssh-keyscan -H github.com >> ~/.ssh/known_hosts

# Copy project files
COPY . .

# Build with cargo install and caching
ARG FEATURES

RUN mkdir -p /app/ddec/bin
RUN cargo install --locked --path core/threshold --root . --bins --no-default-features --features=${FEATURES}
    # cargo install --path . --root . --bins --no-default-features --features=${FEATURES}
    # NOTE: if we're in a workspace then we need to set a different path


# Go tooling stage - only for grpc-health-probe
FROM debian:13.2-slim AS go-builder

# Install minimal Go build dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

# Install Go and grpc-health-probe
ARG TARGETOS
ARG TARGETARCH
ARG GO_VERSION=1.21.6
RUN curl -o go.tgz -L "https://go.dev/dl/go${GO_VERSION}.${TARGETOS}-${TARGETARCH}.tar.gz" && \
    tar -C /usr/local -xzf go.tgz && \
    rm go.tgz

ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"

ARG GRPC_HEALTH_PROBE_VERSION=v0.4.42

RUN git clone https://github.com/grpc-ecosystem/grpc-health-probe && \
    cd grpc-health-probe && \
    git checkout ${GRPC_HEALTH_PROBE_VERSION} && \
    go mod tidy && \
    go build -ldflags="-s -w -extldflags '-static'" -o /out/grpc_health_probe .



FROM debian:13.2-slim AS prod

USER root
# Install required runtime dependencies
RUN  --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libprotobuf-dev \
    libssl3 \
    iproute2 \
    iputils-ping

WORKDIR /app/ddec

# Copy binaries from previous stages
COPY --from=kms-threshold /app/ddec/bin/ /app/ddec/bin/
COPY --from=go-builder /out/grpc_health_probe /app/ddec/bin/

ENV PATH="/app/ddec/bin:$PATH"

EXPOSE 50000

# Change user to limit root access
RUN groupadd -g 10002 kms && \
    useradd -m -u 10004 -g kms kms
RUN chown -R kms:kms /app/ddec
USER kms