#!/usr/bin/env bash
# CRS-gen reproducible sweep for the small-session cluster with one
# `drop_all` party (4 parties, threshold 1, party 1 misbehaves).
# Mirrors the tfhe_reproducible_small_session_malicious.sh wrapper pattern.

VARIANT="small_malicious"
NUM_PARTIES=4
THRESHOLD=1
MALICIOUS=1
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

# Per-params expected SHA-256 of crs.bin under the small-session cluster
# with one drop_all party. The CRS gen protocol is supposed to
# detect and recover from the misbehavior, so these may end up matching
# the small (honest) wrapper's hashes — but record them independently in
# case the recovery path produces a different bit-for-bit result.
declare -A EXPECTED_CRS_HASHES=(
    ["nist-params-p8-sns-fglwe"]="789d353e71b0f69f34ec2698ee119da35553d0d61ade77796a384c162ed61699"
    ["nist-params-p8-sns-lwe"]="4e34fc7d6f2773d2d07ff0a780db40fbc975db40ee43c0cb0a98eb523da8dd3b"
    ["nist-params-p32-sns-fglwe"]="36246ecd8d1af24b818e59ed5f0dd93c3f168e513d2197bb1d92bdf3eb884554"
    ["nist-params-p32-sns-lwe"]="3186dc2953de256e51f873ff851b8c28164cdae85daad3893f3d5bb0e908b07c"
    ["bc-params-sns"]="ab7f0cb7ff5ef62f733d387de2fff5c380cbddd055e29601dae823f50a98e392"
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/crs_reproducible_common.sh" "$@"
