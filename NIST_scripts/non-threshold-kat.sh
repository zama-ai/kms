#!/bin/bash

# This script is used to run the non-threshold KAT generation for NIST submission.
# In particular, it regenerates the KAT files, store them and check against the expected hash.


# Assumes the build.sh script was used
TARGET_DIR="$HOME/kms/core/threshold"
OUTPUT_DIR="$TARGET_DIR/tfhe_kat"

EXPECTED_HASH_CLIENT_KEY="4cdc4104d6daf18f2eb85aac19630e3b33aeb6149699e6de63bce3d51d102a13" # Replace with actual expected hash
EXPECTED_HASH_SERVER_KEY="9c3c9016e604e8ab9016ddcffe94f242d03de1cab42cbf5911c4a9f0e2ffafdc" # Replace with actual expected hash
EXPECTED_HASH_CTXT_43="61c1be6c42fcdc98504d6e98b9a1a40d39dc8519a206d2c518dfee328ea11671"
EXPECTED_HASH_CTXT_4445="685073102b954e79f1aca630d15bd327988c1576c4b33ab2036694f2c3b97940"
EXPECTED_HASH_CTXT_ADD="216a8d45ee31dac10c7c366adf34560f1d9fc2b0b992baa620b081444ae856bc"
EXPECTED_HASH_CTXT_MUL="9786688401190e4a020e1515384a8acc4294c527d8ef7aace4d10d585b587aab"


# Check hash fn
check_hash() {
    local file_path=$1
    local expected_hash=$2

    local computed_hash
    computed_hash=$(sha256sum "$file_path" | cut -d ' ' -f 1)

    if [ "$computed_hash" != "$expected_hash" ]; then
        echo "❌ Hash mismatch for $file_path. Expected: $expected_hash, Got: $computed_hash"
        exit 1
    else
        echo "✅ Hash match for $file_path: $computed_hash"
    fi
}

# Run the latency benchmarks
cargo run --bin non-threshold-kat --release -- --path-to-kat-folder $OUTPUT_DIR --generate-kat

check_hash "$OUTPUT_DIR/client_key.bin" "$EXPECTED_HASH_CLIENT_KEY"
check_hash "$OUTPUT_DIR/server_key.bin" "$EXPECTED_HASH_SERVER_KEY"
check_hash "$OUTPUT_DIR/ciphertext_43.bin" "$EXPECTED_HASH_CTXT_43"
check_hash "$OUTPUT_DIR/ciphertext_4445.bin" "$EXPECTED_HASH_CTXT_4445"
check_hash "$OUTPUT_DIR/ciphertext_add.bin" "$EXPECTED_HASH_CTXT_ADD"
check_hash "$OUTPUT_DIR/ciphertext_mult.bin" "$EXPECTED_HASH_CTXT_MUL"

