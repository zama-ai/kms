SESSION_TYPE="large"
EXPECTED_KEY_HASH="a1420068eea9184e833f31c859c1b10621e648966cff3697b9e151ab744f03df"
EXPECTED_RESHARED_KEY_HASH="5b13254b3c2dcb604b6653902a7ed74f0263abef98fa4a0b133972f40d84c7ef"
EXPECTED_CRS_HASH="e30572a638c8e2b46d00184ae86053418bce2f67897cc1162fac45d0a0f93a7e"
DDEC_MODES="noise-flood-large bit-dec-large"
MAIN_PATH="./temp/tfhe_large_reproducible"
PARAMS="params-test-bk-sns"
SEED=42

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/tfhe_reproducible_common.sh"