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
    ["nist-params-p8-sns-fglwe"]="f94ef7d281ae12c9b6167904da22ce094c98ccd5bc0a36bf953c5f71a9de8ae2"
    ["nist-params-p8-sns-lwe"]="80774f4c4d46d6015f7ac359a69db3e2b9b5df0fbbc06b697961829325fc6179"
    ["nist-params-p32-sns-fglwe"]="78ccac25047caf58aa1851ace650c929ea17ce2d3be4d1dc59f95471804f91f9"
    ["nist-params-p32-sns-lwe"]="51874feb9bf4e4f24c669fe628c6cd898cdc15cf37f3a3085b2f3c11c0bcd53f"
    ["bc-params-sns"]="bb5a0db83ec9917e7a4188436ae086eab625b495f84c09dd4e7da182ad54e9f4"
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/crs_reproducible_common.sh" "$@"
