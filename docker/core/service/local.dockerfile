# syntax=docker/dockerfile:1

################################################################
# First stage based on the golden image
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms/rust-golden-image:latest AS kms-server

WORKDIR /app/kms
COPY . .

# Install the binary leaving it in the WORKDIR/bin folder
RUN mkdir -p /app/kms/bin
RUN cargo install --path core/service --root . --bin kms-server -F insecure


################################################################
# Second stage: Copy the binaries from the base stage and the go-runtime stage
FROM --platform=$BUILDPLATFORM cgr.dev/zama.ai/glibc-dynamic:15.2.0-dev AS prod

USER root
# Install required runtime dependencies
RUN apk update && apk add --no-cache \
    libssl3 \
    ca-certificates

WORKDIR /app/kms

# Change user to limit root access
RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms

# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/kms/bin"
# Copy the binaries from the base stage
COPY --from=kms-server /app/kms/bin/ /app/kms/bin/

RUN chown -R kms:kms /app/kms
USER kms

CMD ["kms-server", "centralized"]


################################################################
# Third stage: Build the grpc-health-probe binary for development
FROM cgr.dev/zama.ai/golang:1.25.0 AS go-builder

ARG GRPC_HEALTH_PROBE_VERSION=v0.4.37

RUN git clone https://github.com/grpc-ecosystem/grpc-health-probe && \
    cd grpc-health-probe && \
    git checkout ${GRPC_HEALTH_PROBE_VERSION} && \
    go mod tidy && \
    go build -ldflags="-s -w -extldflags '-static'" -o /out/grpc_health_probe .


################################################################
## Fourth stage: Build and install grpc-health-probe -- For development only with extra tools
FROM --platform=$BUILDPLATFORM prod AS dev

ARG YQ_VERSION=v4.47.2
ARG TARGETARCH=amd64

USER root
COPY --from=go-builder /out/grpc_health_probe /bin/grpc_health_probe

CMD ["kms-server", "centralized"]
