FROM rust:1.77.1 as compiler

WORKDIR /app
COPY . .

RUN rustup target add wasm32-unknown-unknown
RUN RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release --lib
RUN cargo install wasm-opt --locked
RUN mkdir -p /app/optimized

RUN wasm-opt -Os --signext-lowering "/app/target/wasm32-unknown-unknown/release/counter_test.wasm" -o "/app/optimized/counter_test.wasm"

FROM cosmwasm/wasmd:v0.50.0 as runtime

WORKDIR /app
COPY --from=compiler /app/optimized/counter_test.wasm /app/counter_test.wasm

CMD ["/bin/bash"]

