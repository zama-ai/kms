#!/usr/bin/env bash
# CRS-gen reproducible sweep for the large-session cluster
# (5 parties, threshold 1, all honest). Mirrors the
# tfhe_reproducible_large_session.sh wrapper pattern.

VARIANT="large"
NUM_PARTIES=5
THRESHOLD=1
MALICIOUS=0
SEED=42

# Parameter sets to sweep. Each iteration uses (sid=N, seed=$SEED+N-1) with
# N starting at 1, so reordering changes the hashes.
CRS_PARAMS_LIST=(
    "nist-params-p8-sns-fglwe"
    "nist-params-p8-sns-lwe"
    "nist-params-p32-sns-fglwe"
    "nist-params-p32-sns-lwe"
    "bc-params-sns"
)

# Per-params expected SHA-256 of crs.bin under the large-session cluster.
# Different topology from the small wrapper, so the hashes generally differ.
# TODO: replace the placeholder zeros with the actual hashes after the first
# successful run; the script's hash check prints the produced hash on mismatch.
declare -A EXPECTED_CRS_HASHES=(
    ["nist-params-p8-sns-fglwe"]="402d2596dd2a01949cb6446d343d156134e4fc682b5317765b1ce17c4a477ccf"
    ["nist-params-p8-sns-lwe"]="96b63f5d88ad7e633d56c601246ef51f4ad9b88e5332adabb87d2099e3e9433c"
    ["nist-params-p32-sns-fglwe"]="c47f607f85151f4756acf11612cb2de12c833caecc85edd8e2bf61f4cdc3ed95"
    ["nist-params-p32-sns-lwe"]="f6dfca9ac62936c86521c70086f138d015a5ae000adb274a3a89a6663e68f01b"
    ["bc-params-sns"]="2e7d128a5032f594524adfe42954a401329bc0cdfaf85eb68749eadaf1cc7feb"
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/crs_reproducible_common.sh" "$@"
