#!/bin/bash

# This script is used to run the non-threshold KAT generation for NIST submission.
# In particular, it regenerates the KAT files, store them and check against the expected hash.


# Assumes the build.sh script was used
OUTPUT_DIR="./tfhe_kat"

EXPECTED_HASH_CLIENT_KEY="e632247063e3712eb6de0244fdf08bede700dc7052d018fbc9420e60cfceb36b"
EXPECTED_HASH_SERVER_KEY="9580a04fc3277c52842ea23b52a45a1ae787d27533f57f4aba8812c64dbdb531"
EXPECTED_HASH_CTXT_43="55d217ab5f970299619a3a08c7388eb74887c0f7830aa0b60d5ee50a467b4498"
EXPECTED_HASH_CTXT_4445="85fb15a41a29abea8e732afd43c640b21b7009f96e0c11460c83e07e302b2c8f"
EXPECTED_HASH_CTXT_ADD="b586addc5282f8455aa7a02cc715889df881b97f5d3d4c78e13f80c53d95f7d5"
EXPECTED_HASH_CTXT_MUL="53d133225f103fd45419b90ee92678aceec2d931033b6d8203e8080b13d25b02"


# Check hash fn
check_hash() {
    local file_path=$1
    local expected_hash=$2

    local computed_hash
    computed_hash=$(sha256sum "$file_path" | cut -d ' ' -f 1)

    if [ "$computed_hash" != "$expected_hash" ]; then
        echo "❌ Hash mismatch for $file_path. Expected: $expected_hash, Got: $computed_hash"
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

# NOTE: Those two are CPU dependent due to FFT, so the hash may vary across different machines
check_hash "$OUTPUT_DIR/ciphertext_add.bin" "$EXPECTED_HASH_CTXT_ADD"
check_hash "$OUTPUT_DIR/ciphertext_mult.bin" "$EXPECTED_HASH_CTXT_MUL"
