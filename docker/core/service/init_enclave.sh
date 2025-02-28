#!/bin/bash -x

set -o pipefail

PARENT_CID=3
LOG_PORT=3000
CONFIG_PORT=4000
TOKEN_PORT=4100
KMS_SERVER_CONFIG_FILE="config.toml"
AWS_WEB_IDENTITY_TOKEN_FILE="token"
export AWS_WEB_IDENTITY_TOKEN_FILE

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

has_value() {
    local KEY="$1"
    yq -e -p toml -oy ".$KEY" "$KMS_SERVER_CONFIG_FILE" &>/dev/null
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
socat -u VSOCK-CONNECT:$PARENT_CID:$CONFIG_PORT \
      CREATE:$KMS_SERVER_CONFIG_FILE \
    |& logger || fail "cannot receive kms-server config"

# keep receiving fresh web identity tokens from the parent
has_value "aws.role_arn" && \
    {
	AWS_ROLE_ARN="$(get_value "aws.role_arn")"
	export AWS_ROLE_ARN
	mkfifo $AWS_WEB_IDENTITY_TOKEN_FILE
	while true;
	do
	    socat -U PIPE:$AWS_WEB_IDENTITY_TOKEN_FILE \
		  VSOCK-CONNECT:$PARENT_CID:$TOKEN_PORT \
		|& logger || fail "cannot receive web identity token"
	done &
    }

# the `aws-config` crate doesn't have a simple way to configure AWS API
# endpoints for credentials providers (except IMDS), so we set the STS endpoint
# through the environment
has_value "aws.sts_endpoint" && {
    AWS_ENDPOINT_URL_STS="$(get_value "aws.sts_endpoint")"
    export AWS_ENDPOINT_URL_STS
}

# (optional) telemetry and AWS API proxies
has_value "telemetry.metrics_bind_address" && \
    start_tcp_proxy_in "metrics" "$(get_configured_port "telemetry.metrics_bind_address")"
has_value "telemetry.tracing_endpoint" && \
    start_tcp_proxy_out "tracing" "$(get_configured_port "telemetry.tracing_endpoint")"
start_tcp_proxy_out "AWS IMDS" "$(get_configured_port "aws.imds_endpoint")"
start_tcp_proxy_out "AWS STS" "$(get_configured_port "aws.sts_endpoint")"
start_tcp_proxy_out "AWS S3" "$(get_configured_port "aws.s3_endpoint")"
start_tcp_proxy_out "AWS KMS" "$(get_configured_port "aws.awskms_endpoint")"

# ensure that all keys exist if running in centralized mode
has_value "threshold" || \
    {
	log "generating keys for centralized KMS"
	kms-gen-keys \
	    --pub-url "$(get_value "public_vault.storage")" \
	    --priv-url "$(get_value "private_vault.storage")" \
	    --root-key-id "$(get_value "private_vault.keychain")" \
	    --aws-region "$(get_value "aws.region")" \
	    --aws-imds-endpoint "$(get_value "aws.imds_endpoint")" \
	    --aws-sts-endpoint "$(get_value "aws.sts_endpoint")" \
	    --aws-s3-endpoint "$(get_value "aws.s3_endpoint")" \
	    --aws-kms-endpoint "$(get_value "aws.awskms_endpoint")" \
	    centralized --write-privkey \
	    |& logger || fail "cannot generate keys"
    }
# ensure that signing keys if running in threshold mode
has_value "threshold" && \
    {
	log "generating signing keys for threshold KMS"
	kms-gen-keys \
	    --pub-url "$(get_value "public_vault.storage")" \
	    --priv-url "$(get_value "private_vault.storage")" \
	    --root-key-id "$(get_value "private_vault.keychain")" \
	    --aws-region "$(get_value "aws.region")" \
	    --aws-imds-endpoint "$(get_value "aws.imds_endpoint")" \
	    --aws-sts-endpoint "$(get_value "aws.sts_endpoint")" \
	    --aws-s3-endpoint "$(get_value "aws.s3_endpoint")" \
	    --aws-kms-endpoint "$(get_value "aws.awskms_endpoint")" \
	    --cmd signing-keys \
	    threshold \
            --signing-key-party-id "$(get_value "threshold.my_id")" \
	    |& logger || fail "cannot generate keys"
    }

# gRPC proxies
start_tcp_proxy_in "gRPC client" "$(get_configured_port "service.listen_port")"
has_value "threshold" && \
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
