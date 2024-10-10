#!/bin/bash
local PARENT_CID=3

export PATH="/app/kms/core/service/bin:$PATH"
cd /app/kms/core/service

# receive AWS credentials from the parent
socat -u VSOCK-LISTEN:4000 CREATE:credentials.json
export AWS_ACCESS_KEY_ID=$(jq '.AccessKeyId' credentials.json)
export AWS_SECRET_ACCESS_KEY=$(jq '.SecretAccessKey' credentials.json)
export AWS_SESSION_TOKEN=$(jq '.Token' credentials.json)

# receive kms-server configuration from the parent
socat -u VSOCK-LISTEN:5000 CREATE:config.toml

# AWS S3 proxy
socat TCP-LISTEN:6000,fork VSOCK-CONNECT:$PARENT_CID:6000 &
# AWS KMS proxy
socat TCP-LISTEN:7000,fork VSOCK-CONNECT:$PARENT_CID:7000 &
# gRPC proxy
socat VSOCK-LISTEN:8000,fork TCP:127.0.0.1:50051 &

export RUST_LOG=debug,aws_config=debug,aws_smithy_runtime=trace
kms-server centralized --config-file=config.toml
