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
start_aws_api_proxy "IMDS" "$(get_configured_port "aws.imds_endpoint")"
start_aws_api_proxy "S3" "$(get_configured_port "aws.s3_endpoint")"
start_aws_api_proxy "KMS" "$(get_configured_port "aws.awskms_endpoint")"

# ensure that keys exist if running in centralized mode
# do nothing if [threshold] config section exists
yq -e -p toml -oy '.threshold' "$KMS_SERVER_CONFIG_FILE" &>/dev/null || \
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

# gRPC proxy
log "starting gRPC proxy"
KMS_SERVER_GRPC_PORT=$(get_configured_port "service.listen_port")
socat VSOCK-LISTEN:"$KMS_SERVER_GRPC_PORT",fork TCP:127.0.0.1:"$KMS_SERVER_GRPC_PORT" |& logger &

# showtime!
log "starting kms-server"
kms-server --config-file=$KMS_SERVER_CONFIG_FILE |& logger
