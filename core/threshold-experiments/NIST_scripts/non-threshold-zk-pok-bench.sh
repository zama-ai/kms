#!/bin/bash

# This script runs the non-threshold tfhe-zk-pok benchmarks.
# Run from core/threshold-experiments/:  bash NIST_scripts/non-threshold-zk-pok-bench.sh

set -e
TARGET_DIR="$(pwd)/non_threshold_bench/zk-bench"
OUTPUT_FILE="$TARGET_DIR/bench_results.json"
MEMORY_OUTPUT_FILE="$TARGET_DIR/memory_bench_results.txt"

# Create target directory and clear output files
mkdir -p "$TARGET_DIR"
: > "$OUTPUT_FILE"
: > "$MEMORY_OUTPUT_FILE"

echo "Running ZK PoK speed benchmarks → $OUTPUT_FILE"
cargo-criterion \
    --bench non-threshold_tfhe-zk-pok_speed \
    --message-format json >> "$OUTPUT_FILE"

echo ""
echo "Running ZK PoK memory benchmarks → $MEMORY_OUTPUT_FILE"
cargo bench \
    --bench non-threshold_tfhe-zk-pok_memory \
    --features="measure_memory" \
    >> "$MEMORY_OUTPUT_FILE"

echo ""
echo "Parsing results into CSV → $TARGET_DIR/output/"
python3 non-threshold-parser.py "$TARGET_DIR"

echo ""
echo "Done. Results saved to $TARGET_DIR"
