#!/usr/bin/env bash

set -euxo pipefail

AWS_ACCESS_KEY_ID=$(cat /minio_secrets/access_key)
export AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=$(cat /minio_secrets/secret_key)
export AWS_SECRET_ACCESS_KEY

echo 'Starting kms service'

if [[ "${KMS_CORE__BACKUP_VAULT__KEYCHAIN__SECRET_SHARING__ENABLED}" = "true" ]]; then
	KMS_CORE__BACKUP_VAULT__KEYCHAIN__SECRET_SHARING__ENABLED=true kms-server --config-file "${KMS_CONFIG_FILE}"
elif [[ "${SET_EMPTY_PEERLIST}" = "true" ]]; then
	kms-server --ignore-peerlist --config-file "${KMS_CONFIG_FILE}"
else
	kms-server --config-file "${KMS_CONFIG_FILE}"
fi

