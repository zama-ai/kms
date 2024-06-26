FROM rust:1.79 as compiler

WORKDIR /app
COPY . .

RUN rustup target add wasm32-unknown-unknown
RUN RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release --lib --manifest-path /app/blockchain/contracts/asc/Cargo.toml
RUN cargo install wasm-opt --locked
RUN mkdir -p /app/optimized

RUN wasm-opt -Os --signext-lowering "/app/target/wasm32-unknown-unknown/release/asc.wasm" -o "/app/optimized/asc.wasm"

FROM ghcr.io/zama-ai/kms-blockchain-validator:v0.51.0 as runtime

WORKDIR /app
RUN apk add jq
COPY --from=compiler /app/optimized/asc.wasm /app/asc.wasm

CMD ["/bin/bash"]
