FROM rust:1.77.1 as compiler

WORKDIR /app
COPY . .

RUN rustup target add wasm32-unknown-unknown
RUN RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release --lib --manifest-path /app/contracts/Cargo.toml
RUN cargo install wasm-opt --locked
RUN mkdir -p /app/optimized

RUN wasm-opt -Os --signext-lowering "/app/contracts/target/wasm32-unknown-unknown/release/asc.wasm" -o "/app/optimized/asc.wasm"

FROM cosmwasm/wasmd:v0.50.0 as runtime

WORKDIR /app
COPY --from=compiler /app/optimized/asc.wasm /app/asc.wasm

CMD ["/bin/bash"]

