#!/bin/bash -x

set -o pipefail

PARENT_CID=3
TUN_IF=vsocktun

# Don't bind to port 9000 as it is reserved by the AWS Nitro hypervisor for
# communicating with the enclave.
LOG_PORT=3000
CONFIG_PORT=4000
NETWORK_TUNNEL_PORT=2100
TUN_TOKIO_WORKER_THREADS=4

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

get_value() {
    local KEY="$1"
    yq -e -p toml -oy ".$KEY" "$KMS_SERVER_CONFIG_FILE" || fail "$KEY not present in config"
}

has_value() {
    local KEY="$1"
    yq -e -p toml -oy ".$KEY" "$KMS_SERVER_CONFIG_FILE" &>/dev/null
}

export PATH="/app/kms/core/service/bin:$PATH"
cd /app/kms/core/service |& logger  || fail "cannot set working directory"

# receive keygen or server configuration from the parent
log "requesting KMS config"
socat -u VSOCK-CONNECT:$PARENT_CID:$CONFIG_PORT \
      CREATE:$KMS_SERVER_CONFIG_FILE \
    |& logger || fail "cannot receive KMS config"
[ -f "$KMS_SERVER_CONFIG_FILE" ] || fail "did not receive KMS config"

# log configuration hash for sanity
[ -f "$KMS_SERVER_CONFIG_FILE" ] && \
    {
	KMS_SERVER_CONFIG_HASH="$(sha256sum $KMS_SERVER_CONFIG_FILE | cut -d " " -f 1)"
	log "received KMS config with sha256 $KMS_SERVER_CONFIG_HASH"
    }

# extract bootstrap settings from the received config
TOKEN_PORT="$(get_value "enclave_bootstrap.web_identity_token_port")"

# we are relaying raw IP packets from the enclave networking stack to the parent
# networking stack over vsock so we don't have to make tokio and hyper in
# kms-server talk vsock, this requires a virtual network interface and a NAT on
# the parent
ifconfig lo 127.0.0.1 |& logger || fail "cannot setup loopback interface"
route add -net 127.0.0.0 netmask 255.0.0.0 lo |& logger || fail "cannot add loopback route"
log "starting enclave-side network tunnel"
vsocktun enclave \
    --parent-cid "$PARENT_CID" \
    --tun-name "$TUN_IF" \
    --vsock-port "$NETWORK_TUNNEL_PORT" \
    --tokio-worker-threads "$TUN_TOKIO_WORKER_THREADS" |& logger &
for _ in $(seq 1 30);
do
    if ifconfig "$TUN_IF" &>/dev/null; then
	break
    fi
    sleep 1
done
ifconfig "$TUN_IF" |& logger || fail "cannot setup tunnel interface"
log "enclave /etc/resolv.conf from vsocktun bootstrap:"
cat /etc/resolv.conf |& logger

# keep receiving fresh web identity tokens from the parent
has_value "aws.role_arn" || log "AWS role ARN not set"
has_value "aws.role_arn" && \
    {
	AWS_ROLE_ARN="$(get_value "aws.role_arn")"
	export AWS_ROLE_ARN
	mkfifo $AWS_WEB_IDENTITY_TOKEN_FILE
	while true;
	do
	    socat -U PIPE:$AWS_WEB_IDENTITY_TOKEN_FILE \
		  VSOCK-CONNECT:$PARENT_CID:"$TOKEN_PORT" \
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

# We need to be able to run kms-gen-keys independently of running kms-server
# because kms-gen-keys also generates party CA certificates and those need to be
# included in the peer list and voted on before all parties can start.

# Ensure that signing keys exist when this invocation received a keygen config.
# FHE keys and CRS are generated at runtime by kms-server (in centralized mode)
# or by the threshold protocol (in threshold mode), so this script only handles
# signing keys. kms-gen-keys parses the config file itself so values from the
# parent-provided config are never reinterpreted as shell syntax.
log "attempting signing key generation"
if kms-gen-keys --config-file "$KMS_SERVER_CONFIG_FILE" |& logger; then
    KEYGEN_STATUS=0
else
    KEYGEN_STATUS=$?
fi

log "attempting to start kms-server"
if kms-server --config-file="$KMS_SERVER_CONFIG_FILE" |& logger; then
    SERVER_STATUS=0
else
    SERVER_STATUS=$?
fi

if [ "$KEYGEN_STATUS" -ne 0 ] && [ "$SERVER_STATUS" -ne 0 ]; then
    fail "neither kms-gen-keys nor kms-server completed successfully"
fi
