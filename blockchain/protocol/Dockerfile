FROM rust:1.77.1

WORKDIR /app
COPY . .

# Install the necessary dependencies
RUN apt update && apt install -y net-tools protobuf-compiler

# Build your application
RUN cargo build --release

CMD ["/app/target/release/protocol"]

