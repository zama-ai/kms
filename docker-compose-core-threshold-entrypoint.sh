#!/usr/bin/env bash

set -euxo pipefail

AWS_ACCESS_KEY_ID=$(cat /minio_secrets/access_key)
export AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=$(cat /minio_secrets/secret_key)
export AWS_SECRET_ACCESS_KEY

echo 'Starting kms service'

if [[ "${KMS_DOCKER_BACKUP_SECRET_SHARING}" = "true" ]]; then
	KMS_CORE__BACKUP_VAULT__KEYCHAIN__SECRET_SHARING__ENABLED=true kms-server --config-file "${KMS_DOCKER_CONFIG_FILE}"
elif [[ "${KMS_DOCKER_EMPTY_PEERLIST}" = "true" ]]; then
	kms-server --ignore-peerlist --config-file "${KMS_DOCKER_CONFIG_FILE}"
else
	kms-server --config-file "${KMS_DOCKER_CONFIG_FILE}"
fi

