#!/bin/bash
if [ "$#" -ne 5 ]; then
    echo "usage: run_kms_proxy.sh AWS_REGION IAM_ROLE ENCLAVE_CPU_COUNT ENCLAVE_MEM_SIZE KMS_SERVER_CONFIG_FILE"
    exit 1
fi

local AWS_REGION="$1"
local IAM_ROLE="$2"
local ENCLAVE_CPU_COUNT="$3"
local ENCLAVE_MEM_SIZE="$4"
local KMS_SERVER_CONFIG_FILE="$5"

nitro-cli run-enclave --cpu-count "$ENCLAVE_CPU_COUNT" --memory "$ENCLAVE_MEM_SIZE" --eif-path /app/kms/core/service/enclave.eif

local ENCLAVE_CID = $(nitro-cli describe-enclaves | jq -r .[0].EnclaveCID)

# pass AWS credentials to the enclave
local TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600"`
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/"$IAM_ROLE" | socat -u STDIN VSOCK-CONNECT:"$ENCLAVE_CID":4000

# pass kms-server configuration
socat -u STDIN VSOCK-CONNECT:"$ENCLAVE_CID":5000 < "$KMS_SERVER_CONFIG_FILE"

# start TCP proxies (gRPC and AWS)
socat VSOCK-LISTEN:6000,fork TCP:s3."$AWS_REGION".amazonaws.com:443 &
socat VSOCK-LISTEN:7000,fork TCP:kms."$AWS_REGION".amazonaws.com:443 &
socat TCP-LISTEN:50051,fork VSOCK-CONNECT:"$ENCLAVE_CID":8000 &
