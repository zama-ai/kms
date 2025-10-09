FROM cgr.dev/zama.ai/glibc-dynamic:15.2.0-dev AS prod

ARG RUST_IMAGE_VERSION=stable
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
