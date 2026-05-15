#!/usr/bin/env bash

SESSION_TYPE="small"
EXPECTED_KEY_HASH="d8c457e129b69d664439ae4c6772259567b29949fa5c70e5dcc7fbaa3be50e77"
EXPECTED_RESHARED_KEY_HASH="037649a0037dc581181fa6fcf2310351507b53cd8c15602cfa29a77d12a82c7f"
EXPECTED_CRS_HASH="8edd9a3f0bd528de0326220b4dd9554bc1492ca29dd8c4d686904dd7e039f20f"
DDEC_MODES="noise-flood-small bit-dec-small"
MAIN_PATH="./temp/tfhe_small_reproducible"
PARAMS="params-test-bk-sns"
SEED=42
NUM_CTXTS=${NUM_CTXTS:-10}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/tfhe_reproducible_common.sh"