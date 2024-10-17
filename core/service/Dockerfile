FROM rust:1.81-bookworm AS builder

WORKDIR /usr/src/kms-server
COPY . .

# Add github.com to the list of known hosts. .ssh folder needs to be created first to avoid permission errors
RUN mkdir -p -m 0600 /root/.ssh
RUN ssh-keyscan -H github.com >> ~/.ssh/known_hosts


# install protoc
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler

RUN --mount=type=ssh cargo install --path . --bin kms-server

FROM debian:bookworm
COPY --from=builder /usr/src/kms-server/target/release/kms-server /usr/local/bin/kms-server
RUN mkdir -p -m 0600 /app/parameters
COPY --from=builder /usr/src/kms-server/parameters /app/parameters
WORKDIR /app

CMD ["kms-server"]
