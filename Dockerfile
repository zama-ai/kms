FROM rust:1.74

WORKDIR /usr/src/kms-server
COPY . .

# install protoc
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler

RUN cargo install --path . --bin kms-server

CMD ["kms-server"]