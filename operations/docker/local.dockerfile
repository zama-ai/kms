FROM rust:1.76

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

CMD ["kms-server"]

