# syntax=docker/dockerfile:1

ARG KMS_BINARIES_IMAGE=ghcr.io/zama-ai/kms/kms-binaries:latest

################################################################
## Resolve the prebuilt shared binaries image
##
## Build callers should pass the matching immutable secure or insecure image.
## The default keeps direct production builds on the secure published tag.
FROM --platform=$BUILDPLATFORM ${KMS_BINARIES_IMAGE} AS kms-binaries-source


################################################################
# Shared runtime image
FROM --platform=$BUILDPLATFORM cgr.dev/zama.ai/glibc-dynamic:16-dev AS runtime

# Install only required runtime dependencies
USER root
RUN apk add --no-cache \
        openssl \
        wget \
        libgcc \
        libstdc++

WORKDIR /app/kms-core-client

# Copy the selected secure or insecure binary set. The final target validates
# that the caller supplied the matching flavor.
COPY --from=kms-binaries-source /out/core-client/bin/ ./bin/
COPY --from=kms-binaries-source /out/kms-build-flavor ./kms-build-flavor

# Change user to limit root access
RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms

RUN chown -R kms:kms /app/kms-core-client

ENV PATH="/app/kms-core-client/bin:$PATH"

USER kms


################################################################
# Production image with secure binaries
FROM runtime AS prod

RUN test "$(cat ./kms-build-flavor)" = "secure"
LABEL org.zama.kms.flavor="secure"


################################################################
# Development image with insecure binaries
FROM runtime AS dev

RUN test "$(cat ./kms-build-flavor)" = "insecure"
LABEL org.zama.kms.flavor="insecure"
