#!/bin/bash

# This script is used to run the non-threshold benchmarks for the NIST submission.
# In particular, it runs the benchmarks located in core/threshold/benches/non-threshold.
# And parses the results into a format suitable for the NIST submission.


# Assumes the build.sh script was used
TARGET_DIR="$(pwd)/tfhe_bench"
OUTPUT_FILE="$TARGET_DIR/bench_results.json"
MEMORY_OUTPUT_FILE="$TARGET_DIR/memory_bench_results.txt"

mkdir -p $TARGET_DIR

## Run the latency benchmarks
cargo-criterion --bench non-threshold_keygen_speed --message-format json >> $OUTPUT_FILE
cargo-criterion --bench non-threshold_basic-ops_speed --message-format json >> $OUTPUT_FILE
cargo-criterion --bench non-threshold_erc20_speed --message-format json >> $OUTPUT_FILE
#
## Run the memory benchmarks
cargo bench --bench non-threshold_keygen_memory --features=measure_memory >> $MEMORY_OUTPUT_FILE
cargo bench --bench non-threshold_basic-ops_memory --features=measure_memory >> $MEMORY_OUTPUT_FILE
cargo bench --bench non-threshold_erc20_memory --features=measure_memory >> $MEMORY_OUTPUT_FILE

python3 non-threshold-parser.py $TARGET_DIR