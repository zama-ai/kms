#!/usr/bin/env bash -x

set -eu
set -o pipefail

# This tool uses the mc tool, see here for installation
# https://min.io/docs/minio/linux/reference/minio-mc.html#install-mc

# The key ID for the old key, without sns compression
EXISTING_KEY_ID="$1"
# The key ID for the new key, with sns compression
NEW_KEY_ID="$2"
# A number that corresponds to X in PUB-pX or PRIV-pX
PARTY_ID="$3"
# Set this to true for private storage, false for public storage
IS_PRIVATE_STORAGE="$4"

# Alias can be anything, just need to be consistent in this script
ALIAS="myminio"
mc alias set "$ALIAS" "$PUBLIC_S3_URL" "$S3_ACCESS_KEY" "$S3_SECRET_KEY"

# check that the login works
mc admin info "$ALIAS"

# define all key types depending on whether it's private storage or not
if [ "$IS_PRIVATE_STORAGE" = "true" ]; then
    PARTY=PRIV-p"$PARTY_ID"
    KEY_TYPES=("FheKeyInfo")
else
    PARTY=PUB-p"$PARTY_ID"
    KEY_TYPES=("PublicKey" "PublicKeyMetadata" "ServerKey")
fi

check_existance() {
    local key_path="$1"
    # note that mc stat checks the prefix only, so if the key is "abcd" and we do "mc stat abc" then it will pass
    # but this shouldn't be an issue for us because our key IDs are fixed length
    if ! mc stat "$key_path" &>/dev/null; then
        echo "Key $key_path does not exist."
        exit 1
    fi
}

# first check that all the keys we need to deal with exists
for key_type in "${KEY_TYPES[@]}"; do
    check_existance "$ALIAS"/kms/"$PARTY"/"$key_type"/"$EXISTING_KEY_ID"
    check_existance "$ALIAS"/kms/"$PARTY"/"$key_type"/"$NEW_KEY_ID"
done

# do the actual copying, this will overwrite keys on EXISTING_KEY_ID
for key_type in "${KEY_TYPES[@]}"; do
    mc cp "$ALIAS"/kms/"$PARTY"/"$key_type"/"$NEW_KEY_ID" "$ALIAS"/kms/"$PARTY"/"$key_type"/"$EXISTING_KEY_ID" --preserve
done
