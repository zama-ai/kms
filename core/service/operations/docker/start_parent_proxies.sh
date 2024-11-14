#!/bin/bash

# This script will start proxies that permit the enclave to access external
# services, like AWS API. It's mostly meant for running the enclave on a
# standalone EC2 instance. There might be better ways to start proxies in larger
# production environments, like K8S.

if [ "$#" -ne 4 ]; then
    echo "usage: start_parent_proxies.sh ENCLAVE_CID ENCLAVE_LOG_PORT ENCLAVE_CONFIG_PORT KMS_SERVER_CONFIG_FILE"
    exit 1
fi

start_aws_api_proxy() {
    local SERVICE_NAME="$1"
    local VSOCK_PORT="$2"
    local TCP_DST="$3"
    echo "start_proxies: starting parent-side AWS $SERVICE_NAME proxy"
    socat VSOCK-LISTEN:"$VSOCK_PORT",fork,reuseaddr TCP:"$TCP_DST" &
}

ENCLAVE_CID="$1"
ENCLAVE_LOG_PORT="$2"
ENCLAVE_CONFIG_PORT="$3"
KMS_SERVER_CONFIG_FILE="$4"

get_configured_port() {
    local SERVICE_NAME="$1"
    grep ^"$SERVICE_NAME" "$KMS_SERVER_CONFIG_FILE" | sed 's/\"//g' | cut -d "=" -f 2 | cut -d ":" -f 3
}

get_value() {
    local KEY="$1"
    grep ^"$KEY" "$KMS_SERVER_CONFIG_FILE" | sed 's/\"//g;s/ //g' | cut -d "=" -f 2
}

# start the log stream for the enclave
echo "start_proxies: starting enclave log stream"
socat -u VSOCK-LISTEN:"$ENCLAVE_LOG_PORT",fork STDOUT &

# start the config stream for the enclave
echo "start_proxies: starting enclave config stream"
socat VSOCK-LISTEN:"$ENCLAVE_CONFIG_PORT",fork,reuseaddr OPEN:"$KMS_SERVER_CONFIG_FILE",rdonly &

# start TCP proxies to let the enclave access AWS APIs
AWS_REGION=$(get_value "aws_region")
start_aws_api_proxy "IMDS" "$(get_configured_port "aws_imds_proxy")" "169.254.169.254:80"
start_aws_api_proxy "S3" "$(get_configured_port "aws_s3_proxy")" "s3.$AWS_REGION.amazonaws.com:443"
start_aws_api_proxy "KMS" "$(get_configured_port "aws_kms_proxy")" "kms.$AWS_REGION.amazonaws.com:443"

# start a TCP proxy to let the world access the gRPC API in the enclave
echo "start_enclave: starting parent-side gRPC proxy"
KMS_SERVER_GRPC_PORT=$(get_configured_port "url")
socat TCP-LISTEN:"$KMS_SERVER_GRPC_PORT",fork,reuseaddr VSOCK-CONNECT:"$ENCLAVE_CID":"$KMS_SERVER_GRPC_PORT"
