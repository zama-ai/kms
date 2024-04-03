# Multistage build to reduce image size
# First stage builds the binary
FROM rust:1.77-slim-buster as base

ARG BLOCKCHAIN_ACTIONS_TOKEN
RUN --mount=type=cache,sharing=locked,target=/var/cache/apt apt update && \
    apt install -y make protobuf-compiler iproute2 iputils-ping iperf net-tools dnsutils ssh git gcc libssl-dev libprotobuf-dev pkg-config libssl-dev

WORKDIR /app/kms
COPY . .

# Add github.com to the list of known hosts. .ssh folder needs to be created first to avoid permission errors
RUN mkdir -p -m 0600 /root/.ssh
RUN ssh-keyscan -H github.com >> ~/.ssh/known_hosts

# Install the binary leaving it in the WORKDIR/bin folder
RUN mkdir -p /app/kms/bin
RUN git config --global url."https://${BLOCKCHAIN_ACTIONS_TOKEN}@github.com".insteadOf ssh://git@github.com
RUN --mount=type=ssh --mount=type=cache,sharing=locked,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo install --path . --root . --bin kms-server

# Second stage builds the runtime image.
# This stage will be the final image
FROM debian:stable-slim as go-runtime
WORKDIR /app/kms

RUN --mount=type=cache,sharing=locked,target=/var/cache/apt apt update && \
    apt install -y curl netcat-openbsd

# We are going to need grpc-health-probe to check the health of the grpc server for docker-compose or future deployments
# Install go because grpc-health-probe is written in go and we need to compile it
RUN curl -OL https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
RUN rm go1.21.6.linux-amd64.tar.gz
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"
# Install grpc-health-probe
RUN go install github.com/grpc-ecosystem/grpc-health-probe@latest

# Third stage: Copy the binaries from the base stage and the go-runtime stage
FROM debian:stable-slim as runtime
WORKDIR /app/kms

# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/kms/bin"
# Copy the binaries from the base stage
COPY --from=base /app/kms/bin/ /app/kms/bin/
COPY --from=go-runtime /root/go/bin/grpc-health-probe /app/kms/bin/

CMD ["kms-server"]

