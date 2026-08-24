FROM cgr.dev/zama.ai/glibc-dynamic:16-dev AS prod

ARG RUST_IMAGE_VERSION=stable
ARG SCCACHE_VERSION=v0.15.0

# Install essential tools and dependencies
USER root

RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    --mount=type=cache,target=/var/lib/apk,sharing=locked \
    apk add --no-cache \
    curl \
    wget \
    bash \
    git \
    make \
    perl \
    binutils \
    gcc \
    libstdc++ \
    linux-headers \
    build-base \
    openssl-dev \
    protoc \
    protobuf

RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
        x86_64)  triple=x86_64-unknown-linux-musl ;; \
        aarch64) triple=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/sccache-${SCCACHE_VERSION}-${triple}.tar.gz" \
        | tar -xz --strip-components=1 -C /usr/local/bin "sccache-${SCCACHE_VERSION}-${triple}/sccache"; \
    chmod +x /usr/local/bin/sccache; \
    sccache --version

# Install Rust using rustup
ENV PATH="/root/.cargo/bin:${PATH}"
ENV RUSTUP_HOME=/root/.rustup
ENV CARGO_HOME=/root/.cargo

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain=$RUST_IMAGE_VERSION && \
    . $CARGO_HOME/env

# Set environment variables for building
ENV CC=gcc
ENV CXX=g++
ENV RUSTFLAGS="-C target-feature=-crt-static"
ENV OPENSSL_DIR=/usr

FROM prod AS dev
