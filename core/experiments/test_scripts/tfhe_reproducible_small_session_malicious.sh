#!/usr/bin/env bash

SESSION_TYPE="small"
EXPECTED_KEY_HASH="82fe65a87954f9fbccb936c74d29d47ffb45b2ba2cd66c92efc92c18cd3a667e"
EXPECTED_RESHARED_KEY_HASH="d7d223bb1868b3fa221d4cfa08e1a7ab2c2a9e2c618da67bb811ec82ed8589ed"
DDEC_MODES="noise-flood-small bit-dec-small"
MAIN_PATH="./temp/tfhe_small_reproducible_malicious"
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