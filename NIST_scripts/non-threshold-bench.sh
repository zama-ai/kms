#!/bin/bash

# This script is used to run the non-threshold benchmarks for the NIST submission.
# In particular, it runs the benchmarks located in core/threshold/benches/non-threshold.
# And parses the results into a format suitable for the NIST submission.


# Assumes the build.sh script was used
TARGET_DIR="$HOME/kms/core/threshold"
OUTPUT_FILE="$TARGET_DIR/bench_results.json"
MEMORY_OUTPUT_FILE="$TARGET_DIR/memory_bench_results.txt"

cd $TARGET_DIR
touch $OUTPUT_FILE

# Run the latency benchmarks
cargo-criterion --bench non-threshold_keygen --message-format json >> $OUTPUT_FILE
cargo-criterion --bench non-threshold_basic-ops --message-format json >> $OUTPUT_FILE
cargo-criterion --bench non-threshold_erc20 --message-format json >> $OUTPUT_FILE

# Run the memory benchmarks
cargo bench --bench non-threshold_keygen --features=measure_memory >> $MEMORY_OUTPUT_FILE
cargo bench --bench non-threshold_basic-ops --features=measure_memory >> $MEMORY_OUTPUT_FILE
cargo bench --bench non-threshold_erc20 --features=measure_memory >> $MEMORY_OUTPUT_FILE
