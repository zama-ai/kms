# syntax=docker/dockerfile:1

################################################################
## Second stage builds the kms-core binaries
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms/rust-golden-image:latest AS kms-core

# By default, cargo build --release.
# But you can provide --build-arg LTO_RELEASE="--profile release-lto-off" locally to build locally
ARG LTO_RELEASE=release
ARG APP_CACHE_DIR=kms

# Fetch dependencies and build binaries
WORKDIR /app/kms
# Copy only what is needed to build kms binaries
COPY Cargo.toml Cargo.lock toolchain.txt ./
COPY backward-compatibility ./backward-compatibility
COPY bc2wrap ./bc2wrap
COPY core ./core
COPY core-client ./core-client
COPY observability ./observability
COPY tools ./tools
COPY docker ./docker

RUN mkdir -p /app/kms/core/service/bin

RUN --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/${APP_CACHE_DIR}/target,sharing=locked \
    cargo fetch --locked
RUN --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/${APP_CACHE_DIR}/target,sharing=locked \
    cargo build --locked --profile=${LTO_RELEASE} -p kms --bin kms-server --bin kms-gen-tls-certs --bin kms-init --bin kms-custodian -F insecure && \
    cargo build --locked --profile=${LTO_RELEASE} -p kms --bin kms-gen-keys -F testing -F threshold-fhe/testing -F insecure && \
    cp /app/kms/target/${LTO_RELEASE}/kms-server \
       /app/kms/target/${LTO_RELEASE}/kms-gen-tls-certs \
       /app/kms/target/${LTO_RELEASE}/kms-init \
       /app/kms/target/${LTO_RELEASE}/kms-gen-keys \
       /app/kms/target/${LTO_RELEASE}/kms-custodian \
    ./core/service/bin


ARG YQ_VERSION=v4.50.1
# Overridable arg to allow building for different architectures
ARG TARGETARCH=amd64
RUN wget -qO/usr/bin/yq https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${TARGETARCH} && \
    chmod +x /usr/bin/yq

################################################################
## Third stage: Copy the binaries from preceding stages
# This stage will be the final image
FROM --platform=$BUILDPLATFORM cgr.dev/zama.ai/glibc-dynamic:15.2.0-dev AS prod

USER root
# Install required runtime dependencies
RUN apk update && apk add --no-cache \
    libssl3 \
    socat \
    net-tools \
    libgcc \
    libstdc++

WORKDIR /app/kms/core/service

COPY --from=kms-core /usr/bin/yq /usr/bin/yq
RUN chmod +x /usr/bin/yq

COPY ./core/service/config/ /app/kms/core/service/config

# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="/app/kms/core/service/bin:$PATH"
# Copy the binaries from the kms-core and go-runtime stages
COPY --from=kms-core /app/kms/core/service/bin/ ./bin/

# Copy parent-side and enclave-side init scripts
COPY ./docker/core/service/start_parent_proxies.sh ./bin/
COPY ./docker/core/service/init_enclave.sh ./bin/

# Change user to limit root access
RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms
# pre-create mount points for rights
RUN mkdir -p /app/kms/core/service/certs /app/kms/core/service/config
RUN chown -R kms:kms /app/kms
USER kms

# This is only meaningful when the image is used to build the EIF that runs
# inside of a Nitro enclave. During deployment on k8s, containers are started
# with commands defined in Helm charts.
CMD ["/bin/bash", "/app/kms/core/service/bin/init_enclave.sh"]


################################################################
# Build the grpc-health-probe binary for development
FROM cgr.dev/zama.ai/golang:1.25 AS go-builder

ARG GRPC_HEALTH_PROBE_VERSION=v0.4.42

RUN git clone https://github.com/grpc-ecosystem/grpc-health-probe && \
    cd grpc-health-probe && \
    git checkout ${GRPC_HEALTH_PROBE_VERSION} && \
    go mod tidy && \
    go build -ldflags="-s -w -extldflags '-static'" -o /out/grpc_health_probe .


################################################################
## Fourth stage: Build and install grpc_health_probe -- For development only with extra tools
FROM --platform=$BUILDPLATFORM prod AS dev

USER root
COPY --from=go-builder /out/grpc_health_probe /bin/grpc_health_probe

CMD ["kms-server", "centralized"]
