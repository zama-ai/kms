#!/usr/bin/env bash

echo "Running test script on config file $1".
#Setting all the variables needed
ROOT_DIR=$(cargo locate-project --workspace -q --message-format plain|grep -o '.*/')
STAIRWAYCTL_EXEC="${ROOT_DIR}/target/debug/stairwayctl"
CURR_SID=1
MAIN_PATH="./temp/bgv-reproducible"
KEY_PATH="${MAIN_PATH}/key"
CTXT_PATH="${MAIN_PATH}/ctxt"
SEED=42
NUM_CTXTS=${NUM_CTXTS:-10}
NUM_SESSIONS=5
PERCENTAGE_OFFLINE=100
NUM_PARTIES=4
THRESHOLD=1
CTXT_VALUE=12345

# Per-run output folder. See the TFHE reproducible common script for the
# rationale — same convention so the parser sees one shape across protocols.
EXPERIMENT_NAME="$(basename "$1" .toml)"
RUN_DATE="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DEST="${RUN_DEST:-./temp/session_stats/${EXPERIMENT_NAME}_${RUN_DATE}}"
mkdir -p "$RUN_DEST"

_move_session_stats() {
    mv ./temp/session_stats/session_stats_*.txt "$RUN_DEST/" 2>/dev/null || true
}
trap _move_session_stats EXIT

MEASURE_MEMORY_FLAG=0
case "$EXPERIMENT_NAME" in
    *-mem) MEASURE_MEMORY_FLAG=1 ;;
esac

cat > "$RUN_DEST/BENCH_PARAMS.txt" <<EOF
=== ${RUN_DATE} ===
EXPERIMENT_NAME=${EXPERIMENT_NAME}
PROTOCOL=bgv
SESSION_TYPE=small
NUM_PARTIES=${NUM_PARTIES}
THRESHOLD=${THRESHOLD}
MALICIOUS=0
MEASURE_MEMORY=${MEASURE_MEMORY_FLAG}
PARAMS=default
NUM_CTXTS=${NUM_CTXTS}
NUM_SESSIONS=${NUM_SESSIONS}
PERCENTAGE_OFFLINE=${PERCENTAGE_OFFLINE}
HAS_PRSS_INIT=1
HAS_CRS=0
HAS_RESHARE=0
EOF

mkdir -p $KEY_PATH
mkdir -p $CTXT_PATH

exec 2>&1
set -x
set -e

#build stairwayctl
cargo build --bin stairwayctl

#Init the PRSS
echo "Initializing PRSS"
$STAIRWAYCTL_EXEC -c $1 prss-init --ring level-one --sid $CURR_SID --seed $SEED
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))
$STAIRWAYCTL_EXEC -c $1 prss-init --ring level-ksw --sid $CURR_SID --seed $SEED
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))


##KEY GEN
echo "Generating keys"
#Create preproc for dkg
$STAIRWAYCTL_EXEC -c $1 preproc-key-gen --num-sessions 5 --sid $CURR_SID --seed $SEED
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true --interval 30
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))
#Execute DKG using the produced preproc
$STAIRWAYCTL_EXEC -c $1 threshold-key-gen --sid $CURR_SID --preproc-sid $((CURR_SID - 1)) --seed $SEED
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true --interval 30
#Get the key
$STAIRWAYCTL_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID --storage-path $KEY_PATH
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))

# Makes sure the generated keys has the expected hash
EXPECTED_HASH="b985234cfaac60cf34771f353a66ffeda48da6409f2369163cc6d5f4273c0377"
KEY_HASH=$(sha256sum $KEY_PATH/pk.bin|cut -d ' ' -f 1)
if [ "$KEY_HASH" != "$EXPECTED_HASH" ]; then
    echo "❌ Key hash does not match expected value. Got $KEY_HASH, expected $EXPECTED_HASH"
    exit 1
else
    echo "✅ Key hash matches expected value: $KEY_HASH"
fi

if [ "${2:-}" = "GEN" ]; then
    echo "Generating ctxts"
    ### Generate all ctxts
    # Encrypt
     $STAIRWAYCTL_EXEC -c $1 encrypt --path-pubkey $KEY_PATH/pk.bin --value $CTXT_VALUE --output-file ${CTXT_PATH}/ctxt_${CTXT_VALUE}.bin
else
    echo "Skipping ctxt generation"
fi

###DDEC
echo "Decrypting ctxt"
for NUM_PARALLEL_SESSIONS in 1 2 4 8 16 32
do
    $STAIRWAYCTL_EXEC -c $1 threshold-decrypt-from-file --path-pubkey $KEY_PATH/pk.bin --input-file ${CTXT_PATH}/ctxt_${CTXT_VALUE}.bin --sid $CURR_SID --seed $SEED --num-parallel-sessions $NUM_PARALLEL_SESSIONS --num-ctxt-per-session $NUM_CTXTS
    $STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
    ##Get the result
    $STAIRWAYCTL_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID --expected-value $CTXT_VALUE
    CURR_SID=$(( CURR_SID + 1 ))
    SEED=$(( SEED + 1 ))
done