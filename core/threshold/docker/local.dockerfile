# syntax=docker/dockerfile:1

################################################################
## Second stage builds the kms-core binaries
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms-golden-image:latest AS kms-threshold

WORKDIR /app/ddec

# Copy project files
COPY . .

# Build with cargo install and caching
ARG FEATURES
RUN --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    mkdir -p /app/ddec/bin && \
    # cargo install --path . --root . --bins --no-default-features --features=${FEATURES}
    # NOTE: if we're in a workspace then we need to set a different path
    cargo install --path core/threshold --root . --bins --no-default-features --features=${FEATURES}


# Go tooling stage - only for grpc-health-probe
FROM golang:1.24.1-alpine AS go-builder

ARG GRPC_HEALTH_PROBE_VERSION=v0.4.37

RUN apk update && apk add --no-cache git && \
    git clone https://github.com/grpc-ecosystem/grpc-health-probe && \
    cd grpc-health-probe && \
    git checkout ${GRPC_HEALTH_PROBE_VERSION} && \
    # Fix CVE-2025-27144
    go get github.com/go-jose/go-jose/v4@v4.0.5 && \
    # Fix  CVE-2025-22870
    go get golang.org/x/net@v0.36.0 && \
    go mod tidy && \
    go build -ldflags="-s -w -extldflags '-static'" -o /out/grpc_health_probe .



FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/glibc-dynamic:latest-dev AS prod

USER root
# Install required runtime dependencies
RUN apk update && apk add --no-cache \
    ca-certificates \
    protoc \
    protobuf \
    libssl3 \
    iproute2 \
    iputils

WORKDIR /app/ddec

# Copy binaries from previous stages
COPY --from=kms-threshold /app/ddec/bin/ /app/ddec/bin/
COPY --from=go-builder /out/grpc_health_probe /app/ddec/bin/

ENV PATH="/app/ddec/bin:$PATH"

EXPOSE 50000

# Change user to limit root access
# Change user to limit root access
RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms
RUN chown -R kms:kms /app/ddec
USER kms

# NOTE: when using tools such as tc to change the network configuration,
# you need to run the container as root instead of the kms user as above.
# USER root

# Add health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["grpc_health_probe", "-addr=:50000"]
