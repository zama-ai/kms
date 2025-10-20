#!/bin/bash -x

set -o pipefail

PARENT_CID=3
TUN_NET=10.118.0.0/24
GW_ADDR=10.118.0.1
TUN_ADDR=10.118.0.2/24
TUN_IF=vsocktun

# Don't bind to port 9000 as it is reserved by the AWS Nitro hypervisor for
# communicating with the enclave.
NET_PORT=2000
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
    local SERVICE_URL
    SERVICE_URL=$(get_value "$SERVICE_NAME")
    echo "${SERVICE_URL##*:}"
}

get_value() {
    local KEY="$1"
    yq -e -p toml -oy ".$KEY" "$KMS_SERVER_CONFIG_FILE" || fail "$KEY not present in config"
}

has_value() {
    local KEY="$1"
    yq -e -p toml -oy ".$KEY" "$KMS_SERVER_CONFIG_FILE" &>/dev/null
}

start_tcp_proxy_in() {
    local NAME="$1"
    local PORT="$2"
    log "starting incoming enclave-side $NAME proxy"
    socat \
	VSOCK-LISTEN:"$PORT",fork,reuseaddr \
	TCP:127.0.0.1:"$PORT" \
	|& logger &
}

export PATH="/app/kms/core/service/bin:$PATH"
cd /app/kms/core/service |& logger  || fail "cannot set working directory"

# receive kms-server configuration from the parent
log "requesting kms-server config"
socat -u VSOCK-CONNECT:$PARENT_CID:$CONFIG_PORT \
      CREATE:$KMS_SERVER_CONFIG_FILE \
    |& logger || fail "cannot receive kms-server config"
[ -f "$KMS_SERVER_CONFIG_FILE" ] || fail "did not receive kms-server config"

# log configuration hash for sanity
[ -f "$KMS_SERVER_CONFIG_FILE" ] && \
    {
	KMS_SERVER_CONFIG_HASH="$(sha256sum $KMS_SERVER_CONFIG_FILE | cut -d " " -f 1)"
	log "received kms-server config with sha256 $KMS_SERVER_CONFIG_HASH"
    }

# we are relaying raw IP packets from the enclave networking stack to the parent
# networking stack over vsock so we don't have to make tokio and hyper in
# kms-server talk vsock, this requires a virtual network interface and a NAT on
# the parent
ifconfig lo 127.0.0.1 |& logger || fail "cannot setup loopback interface"
route add -net 127.0.0.0 netmask 255.0.0.0 lo |& logger || fail "cannot add loopback route"
socat TUN:"$TUN_ADDR",tun-name=$TUN_IF,iff-up VSOCK-CONNECT:$PARENT_CID:"$NET_PORT" |& logger &
sleep 2
route add -net $TUN_NET dev $TUN_IF |& logger || fail "cannot add route to gateway"
route add default gw $GW_ADDR |& logger || fail "cannot add default route"
dnsproxy -u https://1.1.1.1/dns-query |& logger &

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

# We need to be able to run kms-gen-keys independently of running kms-server
# because kms-gen-keys also generates party CA certificates and those need to be
# included in the peer list and voted on before all parties can start.

# If the [keygen] section is present in the received configuration file,
# kms-gen-keys will run. It doesn't have any fields. It's not a section
# understood by the configuration parser in kms-server, so kms-server will not
# start if this section is present.
has_value "keygen" && \
    {
	AWS_IMDS_ENDPOINT_ARG=""
	has_value "aws.imds_endpoint" && \
	    AWS_IMDS_ENDPOINT_ARG="--aws-imds-endpoint $(get_value "aws.imds_endpoint")"

	AWS_STS_ENDPOINT_ARG=""
	has_value "aws.sts_endpoint" && \
	    AWS_STS_ENDPOINT_ARG="--aws-sts-endpoint $(get_value "aws.sts_endpoint")"

	AWS_S3_ENDPOINT_ARG=""
	has_value "aws.s3_endpoint" && \
	    AWS_S3_ENDPOINT_ARG="--aws-s3-endpoint $(get_value "aws.s3_endpoint")"

	AWS_KMS_ENDPOINT_ARG=""
	has_value "aws.awskms_endpoint" && \
	    AWS_KMS_ENDPOINT_ARG="--aws-kms-endpoint $(get_value "aws.awskms_endpoint")"
	
	AWS_ARGS="--aws-region $(get_value "aws.region") $AWS_IMDS_ENDPOINT_ARG $AWS_STS_ENDPOINT_ARG $AWS_S3_ENDPOINT_ARG $AWS_KMS_ENDPOINT_ARG"

	PUBLIC_S3_PREFIX_ARG=""
	has_value "public_vault.storage.s3.prefix" && \
	    PUBLIC_S3_PREFIX_ARG="--public-s3-prefix $(get_value "public_vault.storage.s3.prefix")"
	PRIVATE_S3_PREFIX_ARG=""
	has_value "private_vault.storage.s3.prefix" && \
	    PRIVATE_S3_PREFIX_ARG="--private-s3-prefix $(get_value "private_vault.storage.s3.prefix")"

	VAULT_ARGS="--public-storage s3 \
		    --public-s3-bucket $(get_value "public_vault.storage.s3.bucket") $PUBLIC_S3_PREFIX_ARG \
                    --private-storage s3 \
                    --private-s3-bucket $(get_value "private_vault.storage.s3.bucket") $PRIVATE_S3_PREFIX_ARG \
                    --root-key-id $(get_value "private_vault.keychain.aws_kms.root_key_id") \
                    --root-key-spec $(get_value "private_vault.keychain.aws_kms.root_key_spec")"

	KMS_GEN_KEYS_CMD="kms-gen-keys $AWS_ARGS $VAULT_ARGS"

	# ensure that all keys exist if running in centralized mode
	has_value "threshold" || \
	    {
		log "generating keys for centralized KMS"
		eval "$KMS_GEN_KEYS_CMD centralized --write-privkey" \
		    |& logger || fail "cannot generate keys"
	    }

	# Ensure that signing keys exist if running in threshold mode. Note that
	# the [threshold] section used for kms-gen-keys is not the same as one
	# used for kms-server. It has three fields only: my_id, num_parties, and
	# tls_subject. The latter two are not accepted by kms-server.
	has_value "threshold" && \
	    {
		log "generating signing keys for threshold KMS"
		PARTY_ID_ARG=""
		has_value "threshold.my_id" && \
		    PARTY_ID_ARG="--signing-key-party-id $(get_value "threshold.my_id")"
		eval "$KMS_GEN_KEYS_CMD \
                       --cmd signing-keys threshold $PARTY_ID_ARG \
                       --num-parties $(get_value "threshold.num_parties") \
                       --tls-subject $(get_value "threshold.tls_subject")" \
		    |& logger || fail "cannot generate keys"
	    }
    }
has_value "keygen" || \
    log "[keygen] configuration section not present, skipping key generation"

has_value "service" && \
    {
	# telemetry proxy
	has_value "telemetry.metrics_bind_address" || log "metrics endpoint not set"
	has_value "telemetry.metrics_bind_address" && \
	    start_tcp_proxy_in "metrics" "$(get_configured_port "telemetry.metrics_bind_address")"

	# gRPC proxies
	start_tcp_proxy_in "gRPC client" "$(get_configured_port "service.listen_port")"
	has_value "threshold" && start_tcp_proxy_in "gRPC peer" "$(get_configured_port "threshold.listen_port")"
	# showtime!
	log "starting kms-server"
	kms-server --config-file=$KMS_SERVER_CONFIG_FILE |& logger
    }
has_value "service" || \
    log "[service] configuration section not present, not launching kms-server"
