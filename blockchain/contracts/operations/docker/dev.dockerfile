# We use light alpine image of 285 MB instead of 500+ for original
FROM rust:1.82.0-alpine3.20 AS compiler

WORKDIR /app
COPY . .

# Install build dependencies for Alpine
RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    apk add --no-cache build-base clang llvm bash curl

# Add wasm target
RUN rustup target add wasm32-unknown-unknown

# Build ASC contract and report initial size
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --target wasm32-unknown-unknown --profile wasm --lib \
    --manifest-path /app/blockchain/contracts/asc/Cargo.toml && \
    echo "ASC Pre-optimization size: $(wc -c < /app/target/wasm32-unknown-unknown/wasm/asc.wasm) bytes"

# Build Tendermint-IPSC contract and report initial size
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --target wasm32-unknown-unknown --profile wasm --lib \
    --manifest-path /app/blockchain/contracts/tendermint-ipsc/Cargo.toml && \
    echo "Tendermint-IPSC Pre-optimization size: $(wc -c < /app/target/wasm32-unknown-unknown/wasm/tendermint_ipsc.wasm) bytes"

# Build Ethereum-IPSC contract and report initial size
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --target wasm32-unknown-unknown --profile wasm --lib \
    --manifest-path /app/blockchain/contracts/ethereum-ipsc/Cargo.toml && \
    echo "Ethereum-IPSC Pre-optimization size: $(wc -c < /app/target/wasm32-unknown-unknown/wasm/ethereum_ipsc.wasm) bytes"

# Install cargo-binstall and wasm-opt
# Binstall provides a low-complexity mechanism for installing Rust binaries as an alternative to
# building from source which saves CPU time and io
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash

# Install wasm-opt with architecture detection (amd | arm), specific version and no confirmation prompt
RUN ARCH=$(uname -m); \
    case "$ARCH" in \
        "x86_64") TARGET="x86_64-unknown-linux-musl" ;; \
        "aarch64") TARGET="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac && \
    cargo binstall wasm-opt@0.116.1 \
    --no-confirm \
    --force \
    --target $TARGET

# Create optimized directory
# Create directories for intermediate and final optimized files
RUN mkdir -p /app/optimized-input /app/optimized

# Copy built WASM files to intermediate directory
RUN --mount=type=cache,target=/app/target,sharing=locked \
    cp /app/target/wasm32-unknown-unknown/wasm/*.wasm /app/optimized-input/

# Optimize ASC and report final size, check size limit
RUN wasm-opt -Oz "/app/optimized-input/asc.wasm" -o "/app/optimized/asc.wasm" && \
    size=$(wc -c < /app/optimized/asc.wasm) && \
    echo "ASC Post-optimization size: $size bytes" && \
    if [ "$size" -ge 819200 ]; then \
        echo "Error: ASC wasm size ($size bytes) exceeds limit of 819,200 bytes" && \
        exit 1; \
    fi

# Optimize Tendermint-IPSC and report final size, check size limit
RUN wasm-opt -Oz "/app/optimized-input/tendermint_ipsc.wasm" -o "/app/optimized/tendermint_ipsc.wasm" && \
    size=$(wc -c < /app/optimized/tendermint_ipsc.wasm) && \
    echo "Tendermint-IPSC Post-optimization size: $size bytes" && \
    if [ "$size" -ge 819200 ]; then \
        echo "Error: Tendermint-IPSC wasm size ($size bytes) exceeds limit of 819,200 bytes" && \
        exit 1; \
    fi

# Optimize Ethereum-IPSC and report final size, check size limit
RUN wasm-opt -Oz "/app/optimized-input/ethereum_ipsc.wasm" -o "/app/optimized/ethereum_ipsc.wasm" && \
    size=$(wc -c < /app/optimized/ethereum_ipsc.wasm) && \
    echo "Ethereum-IPSC Post-optimization size: $size bytes" && \
    if [ "$size" -ge 819200 ]; then \
        echo "Error: Ethereum-IPSC wasm size ($size bytes) exceeds limit of 819,200 bytes" && \
        exit 1; \
    fi

# Runtime stage
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms-blockchain-validator:v0.51.0 AS runtime

WORKDIR /app
RUN apk add jq

COPY --from=compiler /app/optimized/asc.wasm /app/asc.wasm
COPY --from=compiler /app/optimized/tendermint_ipsc.wasm /app/tendermint_ipsc.wasm
COPY --from=compiler /app/optimized/ethereum_ipsc.wasm /app/ethereum_ipsc.wasm

COPY ./blockchain/scripts/setup_wasmd.sh /app/setup_wasmd.sh
COPY ./blockchain/scripts/deploy_contracts.sh /app/deploy_contracts.sh
COPY ./blockchain/scripts/bootstrap_validator.sh /app/bootstrap_validator.sh

CMD ["/bin/bash"]
