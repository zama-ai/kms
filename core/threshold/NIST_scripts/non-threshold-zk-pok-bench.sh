#!/bin/bash

# This script runs the non-threshold tfhe-zk-pok benchmarks.
# Run from core/threshold/:  bash NIST_scripts/non-threshold-zk-pok-bench.sh

set -e
TARGET_DIR="$(pwd)/non_threshold_bench/zk-bench"
OUTPUT_FILE="$TARGET_DIR/bench_results.json"
MEMORY_OUTPUT_FILE="$TARGET_DIR/memory_bench_results.txt"
# measure_memory activates the peak_alloc global allocator for memory benches.
# The experimental feature of tfhe-zk-pok is already pulled in via dev-dependencies
# and does not need to be repeated here.
FEATURES="measure_memory"

mkdir -p "$TARGET_DIR"

#echo "Running ZK PoK speed benchmarks → $OUTPUT_FILE"
#cargo-criterion \
#    --bench non-threshold_tfhe-zk-pok_speed \
#    --features="$FEATURES" \
#    --message-format json >> "$OUTPUT_FILE"
#
#echo ""
#echo "Running ZK PoK memory benchmarks → $MEMORY_OUTPUT_FILE"
#cargo bench \
#    --bench non-threshold_tfhe-zk-pok_memory \
#    --features="$FEATURES" \
#    >> "$MEMORY_OUTPUT_FILE"

echo ""
echo "Parsing results into CSV → $TARGET_DIR/output/"
python3 non-threshold-parser.py "$TARGET_DIR"

echo ""
echo "Done. Results saved to $TARGET_DIR"
