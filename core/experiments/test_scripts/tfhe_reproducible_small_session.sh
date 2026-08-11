#!/usr/bin/env bash

SESSION_TYPE="small"
EXPECTED_KEY_HASH="d8c457e129b69d664439ae4c6772259567b29949fa5c70e5dcc7fbaa3be50e77"
EXPECTED_RESHARED_KEY_HASH="037649a0037dc581181fa6fcf2310351507b53cd8c15602cfa29a77d12a82c7f"
DDEC_MODES="noise-flood-small bit-dec-small"
MAIN_PATH="./temp/tfhe_small_reproducible"
PARAMS="params-test-bk-sns"
SEED=42
NUM_CTXTS=${NUM_CTXTS:-10}
# Cluster identity / preproc knobs recorded in BENCH_PARAMS.txt by the common
# script. NUM_SESSIONS / PERCENTAGE_OFFLINE mirror the hardcoded mobygo args
# below; if you change one, change the other.
NUM_PARTIES=4
THRESHOLD=1
NUM_SESSIONS=5
PERCENTAGE_OFFLINE=100

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/tfhe_reproducible_common.sh"