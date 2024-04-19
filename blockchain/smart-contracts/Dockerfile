FROM rust:1.77.1 as compiler

WORKDIR /app
COPY . .

RUN cd /app/smart-contracts
RUN rustup target add wasm32-unknown-unknown
RUN RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release --lib --manifest-path /app/smart-contracts/Cargo.toml
RUN cargo install wasm-opt --locked
RUN mkdir -p /app/optimized

RUN wasm-opt -Os --signext-lowering "/app/smart-contracts/target/wasm32-unknown-unknown/release/counter_test.wasm" -o "/app/optimized/counter_test.wasm"
RUN wasm-opt -Os --signext-lowering "/app/smart-contracts/target/wasm32-unknown-unknown/release/configuration.wasm" -o "/app/optimized/configuration.wasm"

FROM cosmwasm/wasmd:v0.50.0 as runtime

WORKDIR /app
COPY --from=compiler /app/optimized/counter_test.wasm /app/counter_test.wasm
COPY --from=compiler /app/optimized/configuration.wasm /app/configuration.wasm

CMD ["/bin/bash"]

