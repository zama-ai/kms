# syntax=docker/dockerfile:1

ARG KMS_BINARIES_IMAGE=ghcr.io/zama-ai/kms/kms-binaries:latest

################################################################
## Resolve the prebuilt shared binaries image
##
## CI retags the workflow-built `kms-binaries` image as `:latest` before the
## package jobs run. Local flows normally pass `KMS_BINARIES_IMAGE` explicitly.
FROM --platform=$BUILDPLATFORM ${KMS_BINARIES_IMAGE} AS kms-binaries-source


################################################################
# Runtime image
FROM --platform=$BUILDPLATFORM cgr.dev/zama.ai/glibc-dynamic:15.2.0-dev AS prod

# Install only required runtime dependencies
USER root
RUN apk add --no-cache \
        openssl \
        wget \
        libgcc \
        libstdc++

WORKDIR /app/kms-core-client

# Copy binaries from the shared kms-binaries image
COPY --from=kms-binaries-source /out/core-client/bin/ /app/kms-core-client/bin/

# Change user to limit root access
RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms

RUN chown -R kms:kms /app/kms-core-client
USER kms

ENV PATH="/app/kms-core-client/bin:$PATH"


################################################################
# Development image
FROM prod AS dev
