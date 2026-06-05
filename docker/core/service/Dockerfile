# syntax=docker/dockerfile:1

ARG KMS_BINARIES_IMAGE=ghcr.io/zama-ai/kms/kms-binaries:latest

################################################################
## Resolve the prebuilt shared binaries image
##
## CI retags the workflow-built `kms-binaries` image as `:latest` before the
## package jobs run. Local flows normally pass `KMS_BINARIES_IMAGE` explicitly.
FROM --platform=$BUILDPLATFORM ${KMS_BINARIES_IMAGE} AS kms-binaries-source


################################################################
## Final runtime image
FROM --platform=$BUILDPLATFORM cgr.dev/zama.ai/glibc-dynamic:15.2.0-dev AS prod

USER root
# Install required runtime dependencies.
# `yq` is used by the startup scripts to query TOML config at runtime.
RUN apk update && apk add --no-cache \
    libssl3 \
    socat \
    net-tools \
    yq \
    libgcc \
    libstdc++

WORKDIR /app/kms/core/service

COPY ./core/service/config/ /app/kms/core/service/config

# Set the path to include the packaged binaries and not just the default /usr/local/bin
ENV PATH="/app/kms/core/service/bin:$PATH"
COPY --from=kms-binaries-source /out/core-service/bin/ ./bin/

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

# This is only meaningful when the image is used to build the EIF that runs
# inside of a Nitro enclave. During deployment on k8s, containers are started
# with commands defined in Helm charts.
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
## Development image with extra tools
FROM --platform=$BUILDPLATFORM prod AS dev

USER root
COPY --from=go-builder /out/grpc_health_probe /bin/grpc_health_probe

CMD ["kms-server", "centralized"]
