#!/bin/bash

# This script is used to run the non-threshold KAT generation for NIST submission.
# In particular, it regenerates the KAT files, store them and check against the expected hash.


# Assumes the build.sh script was used
TARGET_DIR="$HOME/kms/core/threshold"
OUTPUT_DIR="$TARGET_DIR/tfhe_kat"

EXPECTED_HASH_CLIENT_KEY="e632247063e3712eb6de0244fdf08bede700dc7052d018fbc9420e60cfceb36b"
EXPECTED_HASH_SERVER_KEY="5c4c8d372972a13297dc691f90ac2cb9784f44b20d5b090f29c8155b64dff99d"
EXPECTED_HASH_CTXT_43="55d217ab5f970299619a3a08c7388eb74887c0f7830aa0b60d5ee50a467b4498"
EXPECTED_HASH_CTXT_4445="85fb15a41a29abea8e732afd43c640b21b7009f96e0c11460c83e07e302b2c8f"
EXPECTED_HASH_CTXT_ADD="600bef55a6ba73abdd7d57c325659bc906aabbd525eeeaafc53d0e369245a36c"
EXPECTED_HASH_CTXT_MUL="c196cb43e9b8eadc052f365767e4b34e1e4a7e033de0c94e53ff96fe4bc893eb"


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

