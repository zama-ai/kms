# syntax=docker/dockerfile:1


################################################################
### Multistage build to reduce image size
## First stage sets up basic Rust build environment
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms-golden-image:latest AS base

USER root

# Setup SSH and git
RUN apk add --no-cache openssh-keyscan && \
    mkdir -p -m 0600 /root/.ssh && \
    ssh-keyscan -H github.com >> ~/.ssh/known_hosts && \
    mkdir -p /app/kms-connector/bin

# Configure git with secure token handling
RUN --mount=type=secret,id=BLOCKCHAIN_ACTIONS_TOKEN,env=BLOCKCHAIN_ACTIONS_TOKEN \
    git config --global url."https://$BLOCKCHAIN_ACTIONS_TOKEN@github.com".insteadOf ssh://git@github.com


################################################################
## Second stage builds the kms-core binaries
FROM --platform=$BUILDPLATFORM base AS kms-connector

# By default, cargo build --release.
# But you can provide --build-arg LTO_RELEASE="--profile release-lto-off" locally to build locally
ARG LTO_RELEASE=release

WORKDIR /app/kms-connector
COPY . .

# Build with improved caching
RUN --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo install --profile=${LTO_RELEASE} --path kms-connector --root kms-connector --bins

################################################################
# Final runtime stage
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/glibc-dynamic:latest-dev AS prod

# Install minimal runtime dependencies
USER root
RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    --mount=type=cache,target=/var/lib/apk,sharing=locked \
    apk add --no-cache \
        openssl \
        libgcc \
        libstdc++ \
    && rm -rf /var/lib/apk/lists/*

WORKDIR /app/kms-connector
ENV PATH="$PATH:/app/kms-connector/bin"

# Copy binaries and config
COPY --from=kms-connector /app/kms-connector/kms-connector/bin/ /app/kms-connector/bin/
COPY ./kms-connector/config/environments/config-base.toml /app/kms-connector/config/environments/config-base.toml

# Change user to limit root access
RUN addgroup -S kms --gid 10002 && \
    adduser -D -s /bin/sh --uid 10003 -G kms kms
RUN chown -R kms:kms /app/kms-connector
USER kms

################################################################
# Development Stage
FROM prod AS dev
