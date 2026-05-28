#!/usr/bin/env bash
# Common logic for tfhe reproducible session tests.
# Sourced by the small/large wrapper scripts after they set:
#   SESSION_TYPE   — "small" or "large"
#   EXPECTED_KEY_HASH  — expected sha256 of pk.bin
#   DDEC_MODES     — space-separated decryption modes (e.g. "noise-flood-small bit-dec-small")
#   NUM_PARTIES, THRESHOLD, NUM_SESSIONS, PERCENTAGE_OFFLINE
#                  — recorded in BENCH_PARAMS.txt; the bench scripts use
#                    NUM_SESSIONS / PERCENTAGE_OFFLINE values that match the
#                    hardcoded mobygo args below.

echo "Running test script on config file $1".

# Per-run output folder. Each invocation gets its own folder that holds
# BENCH_PARAMS.txt and the moved session_stats_<i>.txt files; the parser
# scans these folders to build a campaign's CSVs. The folder name embeds
# the experiment (derived from the config filename) and a UTC timestamp so
# multiple runs in the same campaign don't collide. The wrapper script
# (threshold-test-params.sh) sets RUN_DEST explicitly to land each run into
# its campaign folder; standalone invocations fall back to a per-run folder
# under ./temp/session_stats/.
EXPERIMENT_NAME="$(basename "$1" .toml)"
RUN_DATE="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DEST="${RUN_DEST:-./temp/session_stats/${EXPERIMENT_NAME}_${RUN_DATE}}"
mkdir -p "$RUN_DEST"

# The session_stats files live at ./temp/session_stats/session_stats_<i>.txt
# (a docker compose mount writes them from inside each party container). On
# exit, sweep them into the per-run folder so they end up next to this run's
# BENCH_PARAMS.txt. The trap fires whether the script succeeds or aborts.
_move_session_stats() {
    mv ./temp/session_stats/session_stats_*.txt "$RUN_DEST/" 2>/dev/null || true
}
trap _move_session_stats EXIT

# Detect mem/malicious runs from the experiment name so the parser doesn't
# have to re-parse the name. Both end up in BENCH_PARAMS.txt below.
MEASURE_MEMORY_FLAG=0
case "$EXPERIMENT_NAME" in
    *-mem) MEASURE_MEMORY_FLAG=1 ;;
esac
MALICIOUS_FLAG=0
case "$EXPERIMENT_NAME" in
    *-malicious-*) MALICIOUS_FLAG=1 ;;
esac

# HAS_PRSS_INIT mirrors the conditional below: small sessions PRSS-init twice,
# large sessions skip PRSS init entirely. The parser uses this flag to know
# how many leading metric lines to expect.
if [ "$SESSION_TYPE" = "small" ]; then
    HAS_PRSS_INIT_FLAG=1
else
    HAS_PRSS_INIT_FLAG=0
fi
# CRS generation has been factored out to test_scripts/crs_reproducible.sh
# (it sweeps multiple parameter sets in one cluster lifecycle). This common
# script therefore no longer emits a CRS_GEN line.
HAS_CRS_FLAG=0
HAS_RESHARE_FLAG=1

# Message types decrypted per DDEC mode. Recorded in BENCH_PARAMS.txt so
# the parser drives the expected schedule + the ptxt_type CSV column off
# it (rather than hardcoding the list on its side). The DDEC loop at the
# bottom of this script iterates this same array, so it's the single
# source of truth for "which TFHE types this run decrypts".
CTXT_TYPES_LIST=(bool u4 u8 u16 u32 u64 u128)

cat > "$RUN_DEST/BENCH_PARAMS.txt" <<EOF
=== ${RUN_DATE} ===
EXPERIMENT_NAME=${EXPERIMENT_NAME}
PROTOCOL=tfhe
SESSION_TYPE=${SESSION_TYPE}
NUM_PARTIES=${NUM_PARTIES}
THRESHOLD=${THRESHOLD}
MALICIOUS=${MALICIOUS_FLAG}
MEASURE_MEMORY=${MEASURE_MEMORY_FLAG}
PARAMS=${PARAMS}
NUM_CTXTS=${NUM_CTXTS}
NUM_SESSIONS=${NUM_SESSIONS}
PERCENTAGE_OFFLINE=${PERCENTAGE_OFFLINE}
DDEC_MODES=${DDEC_MODES}
CTXT_TYPES=${CTXT_TYPES_LIST[*]}
HAS_PRSS_INIT=${HAS_PRSS_INIT_FLAG}
HAS_DKG=1
HAS_CRS=${HAS_CRS_FLAG}
HAS_RESHARE=${HAS_RESHARE_FLAG}
EOF

#build mobygo
cargo build --bin mobygo
ROOT_DIR=$(cargo locate-project --workspace -q --message-format plain|grep -o '.*/')
MOBYGO_EXEC="${ROOT_DIR}/target/debug/mobygo"
CURR_SID=1
KEY_PATH="${MAIN_PATH}/key"
RESHARED_KEY_PATH="${MAIN_PATH}/key-reshared"
CTXT_PATH="${MAIN_PATH}/ctxt"

INIT_VALUE=1
KEY_SID=0

mkdir -p $KEY_PATH
mkdir -p $RESHARED_KEY_PATH
mkdir -p $CTXT_PATH

export RUN_MODE=dev

exec 2>&1
set -e
#Init the PRSS only if the session is small
if [ "$SESSION_TYPE" = "small" ]; then
    echo "Initializing PRSS"
    $MOBYGO_EXEC -c $1 prss-init --ring residue-poly-z64 --sid $CURR_SID --seed $SEED
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true
    CURR_SID=$(( CURR_SID + 1 ))
    SEED=$(( SEED + 1 ))
    $MOBYGO_EXEC -c $1 prss-init --ring residue-poly-z128 --sid $CURR_SID --seed $SEED
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true
    CURR_SID=$(( CURR_SID + 1 ))
    SEED=$(( SEED + 1 ))
else
    echo "Skipping PRSS initialization for large session"
fi


##KEY GEN
echo "Generating keys"
#Create preproc for dkg with test parameters
$MOBYGO_EXEC -c $1 preproc-key-gen --dkg-params $PARAMS --num-sessions $NUM_SESSIONS --session-type $SESSION_TYPE --sid $CURR_SID --seed $SEED
#Checking every 30s
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true --interval 30
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))
#Execute DKG using the produced preproc
$MOBYGO_EXEC -c $1 threshold-key-gen --dkg-params $PARAMS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) --seed $SEED
#Checking every 30s
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true --interval 30
#Get the key
$MOBYGO_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID  --storage-path $KEY_PATH
KEY_SID=$CURR_SID
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))

# Makes sure the generated keys has the expected hash
KEY_HASH=$(sha256sum $KEY_PATH/pk.bin|cut -d ' ' -f 1)
if [ "$KEY_HASH" != "$EXPECTED_KEY_HASH" ]; then
    echo "❌ Key hash does not match expected value. Got $KEY_HASH, expected $EXPECTED_KEY_HASH"
    exit 1
else
    echo "✅ Key hash matches expected value: $KEY_HASH"
fi



if [ "${2:-}" = "GEN" ]; then
    echo "Generating ctxts"
    ### Generate all ctxts
    VALUE=$INIT_VALUE
    for CTXT_TYPE in bool u4 u8 u16 u32 u64 u128
    do
        echo "#TYPE $CTXT_TYPE#"
        # Encrypt the type
         $MOBYGO_EXEC -c $1 encrypt --path-pubkey $KEY_PATH/pk.bin --tfhe-type $CTXT_TYPE --value $VALUE --output-file ${CTXT_PATH}/ctxt_${VALUE}_${CTXT_TYPE}.bin
         VALUE=$(( VALUE * 2 ))
    done
else
    echo "Skipping ctxt generation"
fi

# CRS generation lives in test_scripts/crs_reproducible.sh now. The bumps
# below replace what CRS-gen used to consume so the Reshare step downstream
# picks up the same (sid, seed) pair it did before this refactor — that
# keeps EXPECTED_RESHARED_KEY_HASH stable.
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))

### Reshare
echo "Resharing key"
$MOBYGO_EXEC -c $1 reshare --old-key-sid $KEY_SID --session-type $SESSION_TYPE --new-key-sid $CURR_SID --seed $SEED
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true
$MOBYGO_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID  --storage-path $RESHARED_KEY_PATH
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))

# Make sure the reshared key has the expected hash
RESHARED_KEY_HASH=$(sha256sum $RESHARED_KEY_PATH/pk.bin|cut -d ' ' -f 1)
if [ "$RESHARED_KEY_HASH" != "$EXPECTED_RESHARED_KEY_HASH" ]; then
    echo "❌ Reshared key hash does not match expected value. Got $RESHARED_KEY_HASH, expected $EXPECTED_RESHARED_KEY_HASH"
    exit 1
else
    echo "✅ Reshared key hash matches expected value: $RESHARED_KEY_HASH"
fi

### Make sure we can decrypt all
for DDEC_MODE in $DDEC_MODES
 do
    VALUE=$INIT_VALUE
    echo "### STARTING REQUESTS ON DDEC MODE $DDEC_MODE ###"
    for CTXT_TYPE in "${CTXT_TYPES_LIST[@]}"
    do
        echo "#TYPE $CTXT_TYPE#"
        #Create preproc
        $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --path-pubkey $RESHARED_KEY_PATH/pk.bin --tfhe-type $CTXT_TYPE --num-ctxts $NUM_CTXTS --sid $CURR_SID
        $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true
        CURR_SID=$(( CURR_SID + 1 ))
        #Send ctxt and ask for decryption using the produced preproc
        $MOBYGO_EXEC -c $1 threshold-decrypt-from-file --decryption-mode $DDEC_MODE --path-pubkey $RESHARED_KEY_PATH/pk.bin --input-file ${CTXT_PATH}/ctxt_${VALUE}_${CTXT_TYPE}.bin --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) --num-ctxts $NUM_CTXTS
        $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true
        #Get the result
        EXPECTED_VALUES=$(printf ",$VALUE%.0s" $(seq 1 $NUM_CTXTS) | cut -c2-)
        $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID --expected-values $EXPECTED_VALUES
        CURR_SID=$(( CURR_SID + 1 ))
        VALUE=$(( VALUE * 2 ))
    done
done