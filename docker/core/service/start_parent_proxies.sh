#!/bin/bash

# This script will start proxies that permit the enclave to access external
# services, like AWS API. It's mostly meant for running the enclave on a
# standalone EC2 instance. There might be better ways to start proxies in larger
# production environments, like K8S.

if [ "$#" -ne 4 ]; then
    echo "usage: start_parent_proxies.sh ENCLAVE_CID ENCLAVE_LOG_PORT ENCLAVE_CONFIG_PORT KMS_SERVER_CONFIG_FILE"
    exit 1
fi

ENCLAVE_CID="$1"
ENCLAVE_LOG_PORT="$2"
ENCLAVE_CONFIG_PORT="$3"
KMS_SERVER_CONFIG_FILE="$4"

get_configured_host_and_port() {
    local SERVICE_NAME="$1"
    get_value "$SERVICE_NAME" | sed 's/^https\?:\/\///'
}

get_configured_port() {
    local SERVICE_NAME="$1"
    get_value "$SERVICE_NAME" | cut -d ":" -f 3
}

get_value() {
    local KEY="$1"
    yq -e -p toml -oy ".$KEY" "$KMS_SERVER_CONFIG_FILE"
}

is_threshold() {
    yq -e -p toml -oy '.threshold' "$KMS_SERVER_CONFIG_FILE" &>/dev/null
}

start_tcp_proxy_out() {
    local NAME="$1"
    local VSOCK_PORT="$2"
    local TCP_DST="$3"
    echo "start_proxies: starting parent-side $NAME proxy"
    socat -T60 VSOCK-LISTEN:"$VSOCK_PORT",fork,reuseaddr TCP:"$TCP_DST",nodelay &
}

start_tcp_proxy_in() {
    local NAME="$1"
    local PORT="$2"
    echo "start_proxies: starting parent-side $NAME proxy"
    socat -T60 TCP-LISTEN:"$PORT",fork,nodelay,reuseaddr VSOCK-CONNECT:"$ENCLAVE_CID":"$PORT"
}

# start the log stream for the enclave
echo "start_proxies: starting enclave log stream"
socat -T60 -u VSOCK-LISTEN:"$ENCLAVE_LOG_PORT",fork STDOUT &

# start the config stream for the enclave
echo "start_proxies: starting enclave config stream"
socat -T60 VSOCK-LISTEN:"$ENCLAVE_CONFIG_PORT",fork,reuseaddr OPEN:"$KMS_SERVER_CONFIG_FILE",rdonly &

# start TCP proxies to let the enclave use tracing and AWS APIs
AWS_REGION=$(get_value "aws.region")
start_tcp_proxy_out "tracing" "$(get_configured_port "tracing.endpoint")" "$(get_configured_host_and_port "tracing.endpoint")"
start_tcp_proxy_out "AWS IMDS" "$(get_configured_port "aws.imds_endpoint")" "169.254.169.254:80"
start_tcp_proxy_out "AWS S3" "$(get_configured_port "aws.s3_endpoint")" "s3.$AWS_REGION.amazonaws.com:443"
start_tcp_proxy_out "AWS KMS" "$(get_configured_port "aws.awskms_endpoint")" "kms.$AWS_REGION.amazonaws.com:443"

# if needed, start TCP proxies for threshold peer-to-peer connections
is_threshold && \
    {
	start_tcp_proxy_in "gRPC peer" "$(get_configured_port "threshold.listen_port")" &

	# one outgoing proxy for each threshold peer
	EXPR="start_tcp_proxy_out 'threshold party \(.party_id)' \(.port) \(.address):\(.port);"
	START_TCP_PROXY_OUT_CMDS=$(\
	    yq -p toml -op ".threshold.peers | map(\"$EXPR\")" "$KMS_SERVER_CONFIG_FILE" \
		| sed 's/^.* = //g')
	eval "$START_TCP_PROXY_OUT_CMDS"
    }

# start a TCP proxy to let the world access the gRPC API in the enclave
start_tcp_proxy_in "gRPC client" "$(get_configured_port "service.listen_port")"
