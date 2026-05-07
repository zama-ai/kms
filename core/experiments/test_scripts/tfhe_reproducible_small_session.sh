#!/usr/bin/env bash

SESSION_TYPE="small"
EXPECTED_KEY_HASH="86e53c36c19d03ef7794486d982e7cc8bba4ddea704b7b9587e43aed5e7a804e"
EXPECTED_RESHARED_KEY_HASH="b7f36bba2da051dca4740721a66da374c07cc657ede4bee3cea4ec198bd15b33"
EXPECTED_CRS_HASH="8edd9a3f0bd528de0326220b4dd9554bc1492ca29dd8c4d686904dd7e039f20f"
DDEC_MODES="noise-flood-small bit-dec-small"
MAIN_PATH="./temp/tfhe_small_reproducible"
PARAMS="params-test-bk-sns"
SEED=42
NUM_CTXTS=10

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/tfhe_reproducible_common.sh"