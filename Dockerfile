FROM rust:1.68

RUN apt update && \
    apt install -y make protobuf-compiler iproute2 iputils-ping iperf net-tools dnsutils

RUN rustup component add rustfmt

RUN mkdir -p /usr/src/ddec
WORKDIR /usr/src/ddec
COPY . .

RUN cargo install --path .

EXPOSE 50000
