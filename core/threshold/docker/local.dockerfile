# syntax=docker/dockerfile:1

################################################################
## Second stage builds the kms-core binaries
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms/rust-golden-image:latest AS kms-threshold

WORKDIR /app/ddec
# Copy project files
COPY . .

# Build with cargo install and caching
ARG FEATURES

RUN mkdir -p /app/ddec/bin
RUN cargo install --locked --path core/threshold --root . --bins --no-default-features --features=${FEATURES}
    # cargo install --path . --root . --bins --no-default-features --features=${FEATURES}
    # NOTE: if we're in a workspace then we need to set a different path


# Go tooling stage - only for grpc-health-probe
FROM cgr.dev/zama.ai/golang:1.25.0 AS go-builder

ARG GRPC_HEALTH_PROBE_VERSION=v0.4.37

RUN git clone https://github.com/grpc-ecosystem/grpc-health-probe && \
    cd grpc-health-probe && \
    git checkout ${GRPC_HEALTH_PROBE_VERSION} && \
    go mod tidy && \
    go build -ldflags="-s -w -extldflags '-static'" -o /out/grpc_health_probe .



FROM --platform=$BUILDPLATFORM cgr.dev/zama.ai/glibc-dynamic:15.2.0-dev AS prod

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
