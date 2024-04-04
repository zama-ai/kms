FROM rust:1.77

WORKDIR /app
COPY . .

# Install the necessary dependencies
RUN apt update && apt install -y net-tools

# Build your application
RUN cargo build --release

CMD ["/app/target/release/chain"]

