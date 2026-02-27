#!/bin/bash

# This script is used to run the non-threshold benchmarks (TFHE and BGV) for the NIST submission.
# In particular, it runs the benchmarks located in core/threshold/benches/non-threshold.
# And parses the results into a format suitable for the NIST submission.


TARGET_DIR="$(pwd)/non_threshold_bench"
OUTPUT_FILE="$TARGET_DIR/bench_results.json"
MEMORY_OUTPUT_FILE="$TARGET_DIR/memory_bench_results.txt"
# Note: Doesn't hurt to set those features even when not needed, and it allows compiling only once
FEATURES="experimental,measure_memory"

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

mkdir -p $TARGET_DIR

# Run the latency benchmarks
for bench in "${SPEED_BENCH_LIST[@]}"; do
    cargo-criterion --bench $bench --features=$FEATURES --message-format json >> $OUTPUT_FILE
done

## Run the memory benchmarks
for bench in "${MEMORY_BENCH_LIST[@]}"; do
    cargo bench --bench $bench --features=$FEATURES >> $MEMORY_OUTPUT_FILE
done


python3 non-threshold-parser.py $TARGET_DIR