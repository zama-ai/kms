#!/usr/bin/env bash

SESSION_TYPE="large"
EXPECTED_KEY_HASH="a3b2d3c8dd78d94baf9a0f609142da242e6ce528c2746743a0289105580fbd03"
EXPECTED_RESHARED_KEY_HASH="2892517be20215823d7ebb9deff701802512bee21306e281b3d78ff66e68da6a"
EXPECTED_CRS_HASH="e30572a638c8e2b46d00184ae86053418bce2f67897cc1162fac45d0a0f93a7e"
DDEC_MODES="noise-flood-large bit-dec-large"
MAIN_PATH="./temp/tfhe_large_reproducible"
PARAMS="params-test-bk-sns"
SEED=42
NUM_CTXTS=${NUM_CTXTS:-10}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/tfhe_reproducible_common.sh"