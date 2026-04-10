#!/bin/bash

# This script regenerates and verifies the non-threshold tfhe-zk-pok KAT artifacts.
# Run from core/threshold/:  bash NIST_scripts/non-threshold-zk-pok-kat.sh

set -e

OUTPUT_DIR="./zk_pok_kat"
EXPECTED_HASH_PROOF="086484f0f203ccc2b4bb1b6d33137594ac9e968fa5c72f04a1484eb5cbc9100a"
EXPECTED_HASH_CRS="761f7cf0334d9aaf65eb55fab0dcc094dae6e1ccc7347c6ca48b4b63ce40b9e6"

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

mkdir -p "$OUTPUT_DIR"

echo "Generating ZK PoK KAT artifacts into $OUTPUT_DIR ..."
cargo run --bin non-threshold-zk-pok-kat --release -- \
    --path-to-kat-folder "$OUTPUT_DIR" \
    --generate-kat

check_hash "$OUTPUT_DIR/proof.bin" "$EXPECTED_HASH_PROOF"
check_hash "$OUTPUT_DIR/crs.bin" "$EXPECTED_HASH_CRS"
