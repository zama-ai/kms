# syntax=docker/dockerfile:1

ARG KMS_BINARIES_IMAGE=ghcr.io/zama-ai/kms/kms-binaries:latest
ARG RUST_GOLDEN_IMAGE=ghcr.io/zama-ai/kms/rust-golden-image:latest

################################################################
## Resolve the prebuilt shared binaries image
##
## Build callers should pass the matching immutable secure or insecure image.
## The default keeps direct production builds on the secure published tag.
FROM --platform=$BUILDPLATFORM ${KMS_BINARIES_IMAGE} AS kms-binaries-source

# Second stage: build raw IP proxies for enclave
FROM --platform=$BUILDPLATFORM ${RUST_GOLDEN_IMAGE} AS enclave-utils

RUN mkdir -p /out/enclave-utils/bin

ARG DNSPROXY_VERSION=v0.81.1
# Overridable arg to allow building for different architectures
ARG TARGETARCH=amd64
WORKDIR /tmp
RUN wget -qO dnsproxy.tar.gz https://github.com/AdGuardTeam/dnsproxy/releases/download/${DNSPROXY_VERSION}/dnsproxy-linux-${TARGETARCH}-${DNSPROXY_VERSION}.tar.gz && \
    tar xzf dnsproxy.tar.gz && \
    cp linux-${TARGETARCH}/dnsproxy /out/enclave-utils/bin/dnsproxy && \
    chmod +x /out/enclave-utils/bin/dnsproxy

ARG VSOCKTUN_VERSION=v0.1.0
RUN git clone --depth 1 --branch ${VSOCKTUN_VERSION} https://github.com/zama-ai/vsocktun && \
    cd vsocktun && \
    cargo build --locked --release && \
    cp target/release/vsocktun /out/enclave-utils/bin/vsocktun

################################################################
## Shared runtime image
FROM --platform=$BUILDPLATFORM cgr.dev/zama.ai/glibc-dynamic:16-dev AS runtime

USER root
# Install required runtime dependencies.
# `yq` is used by the startup scripts to query TOML config at runtime.
RUN apk update && apk add --no-cache \
    libssl3 \
    socat \
    net-tools \
    yq \
    iptables \
    libgcc \
    libstdc++

WORKDIR /app/kms/core/service

COPY ./core/service/config/ /app/kms/core/service/config

# Set the path to include the packaged binaries and not just the default /usr/local/bin
ENV PATH="/app/kms/core/service/bin:$PATH"
# Copy the enclave utilities shared by both runtime flavors.
COPY --from=enclave-utils /out/enclave-utils/bin/dnsproxy /usr/bin/dnsproxy
COPY --from=enclave-utils /out/enclave-utils/bin/vsocktun /usr/bin/vsocktun

# Copy the selected secure or insecure binary set. The final target validates
# that the caller supplied the matching flavor.
COPY --from=kms-binaries-source /out/core-service/bin/ ./bin/
COPY --from=kms-binaries-source /out/kms-build-flavor ./kms-build-flavor

# Copy parent-side and enclave-side init scripts
COPY ./docker/core/service/start_parent_proxies.sh ./bin/
COPY ./docker/core/service/init_enclave.sh ./bin/

# Change user to limit root access
RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms
# Pre-create mount points and hand ownership to the non-root runtime user
RUN mkdir -p /app/kms/core/service/certs /app/kms/core/service/config
RUN chown -R kms:kms /app/kms

USER kms

# nitro-cli preserves the source image command when building an EIF, so every
# service flavor that can be used as an enclave source must inherit this command.
CMD ["/bin/bash", "/app/kms/core/service/bin/init_enclave.sh"]


################################################################
# Build the grpc-health-probe binary for development
FROM cgr.dev/zama.ai/golang:1.25 AS go-builder

ARG GRPC_HEALTH_PROBE_VERSION=v0.4.46

RUN git clone https://github.com/grpc-ecosystem/grpc-health-probe && \
    cd grpc-health-probe && \
    git checkout ${GRPC_HEALTH_PROBE_VERSION} && \
    go mod tidy && \
    go build -ldflags="-s -w -extldflags '-static'" -o /out/grpc_health_probe .


################################################################
## Development image with insecure binaries and extra tools
FROM runtime AS dev

RUN test "$(cat ./kms-build-flavor)" = "insecure"
COPY --chown=kms:kms --from=go-builder /out/grpc_health_probe /bin/grpc_health_probe
LABEL org.zama.kms.flavor="insecure"


################################################################
## Published image with a workflow-selected binary flavor
FROM runtime AS prod

ARG EXPECTED_KMS_FLAVOR=secure
RUN case "${EXPECTED_KMS_FLAVOR}" in secure|insecure) ;; *) exit 1 ;; esac && \
    test "$(cat ./kms-build-flavor)" = "${EXPECTED_KMS_FLAVOR}"
LABEL org.zama.kms.flavor="${EXPECTED_KMS_FLAVOR}"
