FROM rust:1.74

ARG CONCRETE_ACTIONS_TOKEN

WORKDIR /usr/src/kms-server
COPY . .

# install protoc
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler

RUN git config --global url."https://${CONCRETE_ACTIONS_TOKEN}@github.com".insteadOf ssh://git@github.com
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo install --path . --bin kms-server

CMD ["kms-server"]
