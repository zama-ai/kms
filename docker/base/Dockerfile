FROM cgr.dev/chainguard/glibc-dynamic:latest-dev AS prod

ARG RUST_IMAGE_VERSION=stable
# Install essential tools and dependencies
USER root

RUN apk add --no-cache \
    curl \
    wget \
    bash \
    git \
    make \
    perl \
    binutils \
    ca-certificates \
    gcc \
    libstdc++ \
    linux-headers \
    build-base \
    openssl-dev \
    protoc \
    protobuf \
    openssh

# Install Rust using rustup
ENV PATH="/root/.cargo/bin:${PATH}"
ENV RUSTUP_HOME=/root/.rustup
ENV CARGO_HOME=/root/.cargo

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain=$RUST_IMAGE_VERSION && \
    . $CARGO_HOME/env

RUN cargo install sccache --version ^0.7

# Set environment variables for building
ENV RUSTC_WRAPPER=sccache SCCACHE_DIR=/sccache
ENV CC=gcc
ENV CXX=g++
ENV RUSTFLAGS="-C target-feature=-crt-static"
ENV OPENSSL_DIR=/usr

FROM prod AS dev
