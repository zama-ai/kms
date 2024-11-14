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
    grep ^"$SERVICE_NAME" "$KMS_SERVER_CONFIG_FILE" | sed 's/\"//g' | cut -d "=" -f 2 | cut -d ":" -f 3
}

get_value() {
    local KEY="$1"
    grep ^"$KEY" "$KMS_SERVER_CONFIG_FILE" | sed 's/\"//g;s/ //g' | cut -d "=" -f 2
}

start_aws_api_proxy() {
    local SERVICE_NAME="$1"
    local PORT="$2"
    log "starting enclave-side AWS $SERVICE_NAME proxy"
    socat TCP-LISTEN:"$PORT",fork VSOCK-CONNECT:$PARENT_CID:"$PORT" |& logger &
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
start_aws_api_proxy "IMDS" "$(get_configured_port "aws_imds_proxy")"
start_aws_api_proxy "S3" "$(get_configured_port "aws_s3_proxy")"
start_aws_api_proxy "KMS" "$(get_configured_port "aws_kms_proxy")"

# ensure that keys exist
log "generating keys"
kms-gen-keys centralized --write-privkey \
	     --pub-url "$(get_value "public_storage_url")" \
	     --priv-url "$(get_value "private_storage_url")" \
	     --aws-region "$(get_value "aws_region")" \
	     --aws-imds-endpoint "$(get_value "aws_imds_proxy")" \
	     --aws-s3-endpoint "$(get_value "aws_s3_proxy")" \
	     --aws-kms-endpoint "$(get_value "aws_kms_proxy")" \
	     --root-key-id "$(get_value "root_key_id")" \
	     |& logger || fail "cannot generate keys"

# gRPC proxy
log "starting gRPC proxy"
KMS_SERVER_GRPC_PORT=$(get_configured_port "url")
socat VSOCK-LISTEN:"$KMS_SERVER_GRPC_PORT",fork TCP:127.0.0.1:"$KMS_SERVER_GRPC_PORT" |& logger &

# showtime!
log "starting kms-server"
kms-server centralized --config-file=$KMS_SERVER_CONFIG_FILE |& logger
