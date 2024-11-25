#!/bin/bash -x

set -o pipefail

PARENT_CID=3
LOG_PORT=3000
CONFIG_PORT=4000
KMS_SERVER_CONFIG_FILE="config.toml"

logger() {
    socat -u STDIN VSOCK-CONNECT:$PARENT_CID:$LOG_PORT
}

log() {
    echo "debug: init_enclave: $1"
    echo "init_enclave: $1" | logger
}

fail() {
    log "$1"
    exit
}

get_configured_port() {
    local SERVICE_NAME="$1"
    get_value "$SERVICE_NAME" | cut -d ":" -f 3
}

get_value() {
    local KEY="$1"
    yq -e -p toml -oy ".$KEY" "$KMS_SERVER_CONFIG_FILE" || fail "$KEY not present in config"
}

is_threshold() {
    yq -e -p toml -oy '.threshold' "$KMS_SERVER_CONFIG_FILE" &>/dev/null
}

start_tcp_proxy_out() {
    local NAME="$1"
    local PORT="$2"
    log "starting enclave-side $NAME proxy"
    socat \
	TCP-LISTEN:"$PORT",fork,reuseaddr \
	VSOCK-CONNECT:$PARENT_CID:"$PORT" \
	|& logger &
}

start_tcp_proxy_in() {
    local NAME="$1"
    local PORT="$2"
    log "starting enclave-side $NAME proxy"
    socat \
	VSOCK-LISTEN:"$PORT",fork,reuseaddr \
	TCP:127.0.0.1:"$PORT" \
	|& logger &
}

export PATH="/app/kms/core/service/bin:$PATH"
cd /app/kms/core/service |& logger  || fail "cannot set working directory"

# we use socat to convert TCP connections into vsocks and vice versa,
# so we don't have to make tokio and hyper in kms-server talk to vsocks
# this trick requires a loopback interface
ifconfig lo 127.0.0.1 |& logger || fail "cannot setup loopback interface"
route add -net 127.0.0.0 netmask 255.0.0.0 lo |& logger || fail "cannot add loopback route"

# receive kms-server configuration from the parent
log "requesting kms-server config"
socat -u VSOCK-CONNECT:$PARENT_CID:$CONFIG_PORT CREATE:$KMS_SERVER_CONFIG_FILE |& logger || fail "cannot receive kms-server config"

# AWS API proxies
start_tcp_proxy_out "AWS IMDS" "$(get_configured_port "aws.imds_endpoint")"
start_tcp_proxy_out "AWS S3" "$(get_configured_port "aws.s3_endpoint")"
start_tcp_proxy_out "AWS KMS" "$(get_configured_port "aws.awskms_endpoint")"

# ensure that keys exist if running in centralized mode
# do nothing if [threshold] config section exists
is_threshold || \
    {
	log "generating keys for centralized KMS"
	kms-gen-keys \
	    --pub-url "$(get_value "public_vault.storage")" \
	    --priv-url "$(get_value "private_vault.storage")" \
	    --root-key-id "$(get_value "private_vault.keychain")" \
	    --aws-region "$(get_value "aws.region")" \
	    --aws-imds-endpoint "$(get_value "aws.imds_endpoint")" \
	    --aws-s3-endpoint "$(get_value "aws.s3_endpoint")" \
	    --aws-kms-endpoint "$(get_value "aws.awskms_endpoint")" \
	    centralized --write-privkey \
	    |& logger || fail "cannot generate keys"
    }

# gRPC proxies
start_tcp_proxy_in "gRPC client" "$(get_configured_port "service.listen_port")"
is_threshold && \
    {
	start_tcp_proxy_in "gRPC peer" "$(get_configured_port "threshold.listen_port")" &

	# one outgoing proxy for each threshold peer
	EXPR="start_tcp_proxy_out 'threshold party \(.party_id)' \(.port);"
	START_TCP_PROXY_OUT_CMDS=$( \
	    yq -p toml -op ".threshold.peers | map (\"$EXPR\")" $KMS_SERVER_CONFIG_FILE \
		| sed 's/^.* = //g')
	eval "$START_TCP_PROXY_OUT_CMDS"
    }

# showtime!
log "starting kms-server"
kms-server --config-file=$KMS_SERVER_CONFIG_FILE |& logger
