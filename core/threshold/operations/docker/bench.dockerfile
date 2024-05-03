# Multistage build to reduce image size
# First stage builds the binary
FROM rust:1.78-slim-buster as base

ARG CONCRETE_ACTIONS_TOKEN

RUN apt update && \
    apt install -y make protobuf-compiler iproute2 iputils-ping iperf net-tools dnsutils ssh git gcc libssl-dev libprotobuf-dev

WORKDIR /app/ddec
COPY . .

# Add github.com to the list of known hosts. .ssh folder needs to be created first to avoid permission errors
RUN mkdir -p -m 0600 /root/.ssh
RUN ssh-keyscan -H github.com >> ~/.ssh/known_hosts

# Install the binary leaving it in the WORKDIR/bin folder
RUN mkdir -p /app/ddec/bin
RUN git config --global url."https://${CONCRETE_ACTIONS_TOKEN}@github.com".insteadOf ssh://git@github.com
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo install --path . --root . --bins --features=choreographer --features=testing

# Second stage builds the runtime image.
# This stage will be the final image
FROM debian:stable-slim as go-runtime

RUN apt update && \
    apt install -y iproute2 iputils-ping iperf net-tools dnsutils libssl-dev libprotobuf-dev curl netcat-openbsd
WORKDIR /app/ddec
RUN mkdir -p /app/ddec/config

# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/ddec/bin"

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
WORKDIR /app/ddec
# Set the path to include the binaries and not just the default /usr/local/bin
ENV PATH="$PATH:/app/ddec/bin"


# Copy the binaries from the base stage
COPY --from=base /app/ddec/bin/ /app/ddec/bin/
COPY --from=go-runtime /root/go/bin/grpc-health-probe /app/ddec/bin/grpc-health-probe
COPY ./config/default.toml /app/ddec/config/default.toml

EXPOSE 50000
