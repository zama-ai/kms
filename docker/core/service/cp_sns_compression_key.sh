#!/usr/bin/env bash -x

# Usage:
# Setup AWS CLI with the S3 credentials
# ./cp_sns_compression_key.sh <EXISTING_KEY_ID> <NEW_KEY_ID> <PARTY_ID> <IS_PRIVATE_STORAGE> <S3_URL> <S3_BUCKET>
# Example:
# ./cp_sns_compression_key.sh 7e6d24be2e4b3556615c6161cb39dfba595d7ed66006523dc6340382760991ab 45e5a33b1094e59a0c4088d81c60d5bb5510ff67c12633956d2063450eea1e5b 1 false http://localhost:9000 kms

set -eu
set -o pipefail

# The key ID for the old key, without sns compression
EXISTING_KEY_ID="$1"
# The key ID for the new key, with sns compression
NEW_KEY_ID="$2"
# A number that corresponds to X in PUB-pX or PRIV-pX
PARTY_ID="$3"
# Set this to true for private storage, false for public storage
IS_PRIVATE_STORAGE="$4"
# S3 URL, e.g. http://localhost:9000
S3_URL="$5"
# S3 Bucket, for the public storage this is usually "kms"
S3_BUCKET="$6"

# Here we assume AWS CLI is configured with the S3 credentials
# For minio, remember to set
# aws configure set default.s3.signature_version s3v4

# check that we can do basic commands
aws --endpoint-url "$S3_URL" s3 ls >/dev/null || {
    echo "Failed to connect to S3 at $S3_URL"
    exit 1
}

# define all key types depending on whether it's private storage or not
if [ "$IS_PRIVATE_STORAGE" = "true" ]; then
    PARTY=PRIV-p"$PARTY_ID"
    KEY_TYPES=("FheKeyInfo")
else
    PARTY=PUB-p"$PARTY_ID"
    KEY_TYPES=("PublicKey" "PublicKeyMetadata" "ServerKey")
fi

check_existence() {
    local key_path="$1"
    if ! aws --endpoint--url "$S3_URL" s3api head-object --bucket "$S3_BUCKET" --key "$key_path" &>/dev/null; then
        echo "Key $key_path does not exist on bucket $S3_BUCKET."
        exit 1
    fi
}

# first check that all the keys we need to deal with exists
for key_type in "${KEY_TYPES[@]}"; do
    check_existence "$PARTY"/"$key_type"/"$EXISTING_KEY_ID"
    check_existence "$PARTY"/"$key_type"/"$NEW_KEY_ID"
done

echo "All keys exist, proceeding with copy."

# do the actual copying, this will overwrite keys on EXISTING_KEY_ID
for key_type in "${KEY_TYPES[@]}"; do
    aws --endpoint--url "$S3_URL" s3 cp \
        "s3://$S3_BUCKET/$PARTY/$key_type/$NEW_KEY_ID" \
        "s3://$S3_BUCKET/$PARTY/$key_type/$EXISTING_KEY_ID"
    # --copy-props "metadata-directive"
done

echo "Successfully copied keys from $NEW_KEY_ID to $EXISTING_KEY_ID."