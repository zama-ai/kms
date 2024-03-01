FROM rust:1.76

ARG CONCRETE_ACTIONS_TOKEN

WORKDIR /usr/src/kms-server
COPY . .

# install protoc
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler

# Add github.com to the list of known hosts. .ssh folder needs to be created first to avoid permission errors
RUN mkdir -p -m 0600 /root/.ssh
RUN ssh-keyscan -H github.com >> ~/.ssh/known_hosts

RUN git config --global url."https://${CONCRETE_ACTIONS_TOKEN}@github.com".insteadOf ssh://git@github.com
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo install --path . --bin kms-server

CMD ["kms-server"]


