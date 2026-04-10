#!/bin/bash

# This script regenerates and verifies the non-threshold tfhe-zk-pok KAT artifacts.
# Run from core/threshold/:  bash NIST_scripts/non-threshold-zk-pok-kat.sh

set -e

OUTPUT_DIR="./kat/zk-pok"
EXPECTED_HASH_PROOF="05491c9c547814cb7b2ad15f8218915e11d1639015c25bdec00702d19a0fa990"
EXPECTED_HASH_CRS="e7133c99195bdd0d8d00800b86e54f5d11d348da8954604d02cacb424d011e78"

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
