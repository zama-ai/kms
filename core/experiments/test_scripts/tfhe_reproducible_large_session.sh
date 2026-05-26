#!/usr/bin/env bash

SESSION_TYPE="large"
EXPECTED_KEY_HASH="a3b2d3c8dd78d94baf9a0f609142da242e6ce528c2746743a0289105580fbd03"
EXPECTED_RESHARED_KEY_HASH="2892517be20215823d7ebb9deff701802512bee21306e281b3d78ff66e68da6a"
DDEC_MODES="noise-flood-large bit-dec-large"
MAIN_PATH="./temp/tfhe_large_reproducible"
PARAMS="params-test-bk-sns"
SEED=42
NUM_CTXTS=${NUM_CTXTS:-10}
# Cluster identity / preproc knobs recorded in BENCH_PARAMS.txt by the common
# script. NUM_SESSIONS / PERCENTAGE_OFFLINE mirror the hardcoded mobygo args
# below; if you change one, change the other.
NUM_PARTIES=5
THRESHOLD=1
NUM_SESSIONS=5
PERCENTAGE_OFFLINE=100

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/tfhe_reproducible_common.sh"