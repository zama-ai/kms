#!/bin/bash

# Path to the Cargo.lock file
CARGO_LOCK_FILE="./Cargo.lock"

# Extract all versions of the tfhe package
tfhe_versions=$(grep -A 1 'name = "tfhe"' "$CARGO_LOCK_FILE" | grep 'version =' | awk '{print $3}' | tr -d '"')

# Count the number of unique versions
unique_versions=$(echo "$tfhe_versions" | sort | uniq | wc -l)

if [ "$unique_versions" -gt 1 ]; then
    echo "Multiple versions of 'tfhe' found:"
    echo "$tfhe_versions" | tr ' ' '\n'
    echo "Make sure the tfhe-rs version used here is matching the one from the kms-core's dependencies"
    exit 1
else
    echo "No multiple versions of 'tfhe' found."
fi