#!/bin/bash

# This script is used to run the non-threshold benchmarks (TFHE and BGV) for the NIST submission.
# In particular, it runs the benchmarks located in core/experiments/benches/non-threshold.
# And parses the results into a format suitable for the NIST submission.


TARGET_DIR="$(pwd)/non_threshold_bench/tfhe_bench"
OUTPUT_FILE="$TARGET_DIR/bench_results.json"
MEMORY_OUTPUT_FILE="$TARGET_DIR/memory_bench_results.txt"

SPEED_BENCH_LIST=(
    "non-threshold_tfhe-rs_keygen_speed"
    "non-threshold_tfhe-rs_basic-ops_speed"
    "non-threshold_tfhe-rs_erc20_speed"
    "non-threshold_bgv_keygen_speed"
    "non-threshold_bgv_basic-ops_speed"
)

MEMORY_BENCH_LIST=(
    "non-threshold_tfhe-rs_keygen_memory"
    "non-threshold_tfhe-rs_basic-ops_memory"
    "non-threshold_tfhe-rs_erc20_memory"
    "non-threshold_bgv_keygen_memory"
    "non-threshold_bgv_basic-ops_memory"
)

# Create target directory and clear output files
mkdir -p $TARGET_DIR
: > "$OUTPUT_FILE"
: > "$MEMORY_OUTPUT_FILE"

# Run the latency benchmarks
echo "Running TFHE speed benchmarks → $OUTPUT_FILE"
for bench in "${SPEED_BENCH_LIST[@]}"; do
    cargo-criterion --bench $bench --message-format json >> $OUTPUT_FILE
done

## Run the memory benchmarks
echo ""
echo "Running TFHE memory benchmarks → $MEMORY_OUTPUT_FILE"
for bench in "${MEMORY_BENCH_LIST[@]}"; do
    cargo bench --bench $bench --features=measure_memory >> $MEMORY_OUTPUT_FILE
done


echo ""
echo "Parsing results into CSV → $TARGET_DIR/output/"
python3 non-threshold-parser.py $TARGET_DIR

echo ""
echo "Done. Results saved to $TARGET_DIR"
