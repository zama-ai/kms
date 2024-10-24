# We use light alpine image of 285 MB instead of 500+ for original
FROM rust:1.82.0-alpine3.20 AS compiler

WORKDIR /app
COPY . .

# Install build dependencies for Alpine
RUN apk add --no-cache build-base clang llvm bash curl

# Add wasm target
RUN rustup target add wasm32-unknown-unknown

# Set optimization env vars for cargo
ENV CARGO_PROFILE_RELEASE_OPT_LEVEL='z'
ENV CARGO_PROFILE_RELEASE_LTO='true'
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1'
ENV CARGO_PROFILE_RELEASE_PANIC='abort'

# Build ASC contract and report initial size
RUN cargo build --target wasm32-unknown-unknown --release --lib \
    --manifest-path /app/blockchain/contracts/asc/Cargo.toml && \
    echo "ASC Pre-optimization size: $(wc -c < /app/target/wasm32-unknown-unknown/release/asc.wasm) bytes"

# Build Tendermint-IPSC contract and report initial size
RUN cargo build --target wasm32-unknown-unknown --release --lib \
    --manifest-path /app/blockchain/contracts/tendermint-ipsc/Cargo.toml && \
    echo "Tendermint-IPSC Pre-optimization size: $(wc -c < /app/target/wasm32-unknown-unknown/release/tendermint_ipsc.wasm) bytes"

# Build Ethereum-IPSC contract and report initial size
RUN cargo build --target wasm32-unknown-unknown --release --lib \
    --manifest-path /app/blockchain/contracts/ethereum-ipsc/Cargo.toml && \
    echo "Ethereum-IPSC Pre-optimization size: $(wc -c < /app/target/wasm32-unknown-unknown/release/ethereum_ipsc.wasm) bytes"

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
RUN mkdir -p /app/optimized

# Optimize ASC and report final size, check size limit. As of Oct. 23 optimized WASM size is around 657000 bytes
RUN wasm-opt -Oz "/app/target/wasm32-unknown-unknown/release/asc.wasm" -o "/app/optimized/asc.wasm" && \
    size=$(wc -c < /app/optimized/asc.wasm) && \
    echo "ASC Post-optimization size: $size bytes" && \
    if [ "$size" -ge 819200 ]; then \
        echo "Error: ASC wasm size ($size bytes) exceeds limit of 819,200 bytes" && \
        exit 1; \
    fi

# Optimize Tendermint-IPSC and report final size, check size limit
RUN wasm-opt -Oz "/app/target/wasm32-unknown-unknown/release/tendermint_ipsc.wasm" -o "/app/optimized/tendermint_ipsc.wasm" && \
    size=$(wc -c < /app/optimized/tendermint_ipsc.wasm) && \
    echo "Tendermint-IPSC Post-optimization size: $size bytes" && \
    if [ "$size" -ge 819200 ]; then \
        echo "Error: Tendermint-IPSC wasm size ($size bytes) exceeds limit of 819,200 bytes" && \
        exit 1; \
    fi

# Optimize Ethereum-IPSC and report final size, check size limit
RUN wasm-opt -Oz "/app/target/wasm32-unknown-unknown/release/ethereum_ipsc.wasm" -o "/app/optimized/ethereum_ipsc.wasm" && \
    size=$(wc -c < /app/optimized/ethereum_ipsc.wasm) && \
    echo "Ethereum-IPSC Post-optimization size: $size bytes" && \
    if [ "$size" -ge 819200 ]; then \
        echo "Error: Ethereum-IPSC wasm size ($size bytes) exceeds limit of 819,200 bytes" && \
        exit 1; \
    fi

# Runtime stage
FROM ghcr.io/zama-ai/kms-blockchain-validator:v0.51.0 AS runtime

WORKDIR /app
RUN apk add jq
COPY --from=compiler /app/optimized/asc.wasm /app/asc.wasm
COPY --from=compiler /app/optimized/tendermint_ipsc.wasm /app/tendermint_ipsc.wasm
COPY --from=compiler /app/optimized/ethereum_ipsc.wasm /app/ethereum_ipsc.wasm

CMD ["/bin/bash"]
