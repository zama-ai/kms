FROM rust:1.80 AS compiler

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y clang
RUN rustup target add wasm32-unknown-unknown
RUN RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release --lib --manifest-path /app/blockchain/contracts/asc/Cargo.toml
RUN RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release --lib --manifest-path /app/blockchain/contracts/tendermint-ipsc/Cargo.toml
RUN cargo install wasm-opt --locked
RUN mkdir -p /app/optimized

RUN wasm-opt -Os --signext-lowering "/app/target/wasm32-unknown-unknown/release/asc.wasm" -o "/app/optimized/asc.wasm"
RUN wasm-opt -Os --signext-lowering "/app/target/wasm32-unknown-unknown/release/tendermint_ipsc.wasm" -o "/app/optimized/tendermint_ipsc.wasm"

FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms-blockchain-validator:v0.51.0 AS runtime

WORKDIR /app
RUN apk add jq

COPY --from=compiler /app/optimized/asc.wasm /app/asc.wasm
COPY --from=compiler /app/optimized/tendermint_ipsc.wasm /app/tendermint_ipsc.wasm

COPY ./blockchain/scripts/setup_wasmd.sh /app/setup_wasmd.sh
COPY ./blockchain/scripts/bootstrap_asc.sh /app/bootstrap.sh
COPY ./blockchain/scripts/pub_key_to_minio.sh /app/pub_key_to_minio.sh

CMD ["/bin/bash"]

