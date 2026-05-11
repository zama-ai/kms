#!/usr/bin/env bash
# Common logic for tfhe reproducible session tests.
# Sourced by the small/large wrapper scripts after they set:
#   SESSION_TYPE   — "small" or "large"
#   EXPECTED_KEY_HASH  — expected sha256 of pk.bin
#   DDEC_MODES     — space-separated decryption modes (e.g. "noise-flood-small bit-dec-small")

echo "Running test script on config file $1".
#build mobygo
cargo build --bin mobygo
ROOT_DIR=$(cargo locate-project --workspace -q --message-format plain|grep -o '.*/')
MOBYGO_EXEC="${ROOT_DIR}/target/debug/mobygo"
CURR_SID=1
KEY_PATH="${MAIN_PATH}/key"
RESHARED_KEY_PATH="${MAIN_PATH}/key-reshared"
CRS_PATH="${MAIN_PATH}/crs"
CTXT_PATH="${MAIN_PATH}/ctxt"

INIT_VALUE=1
KEY_SID=0

mkdir -p $KEY_PATH
mkdir -p $RESHARED_KEY_PATH
mkdir -p $CRS_PATH
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
$MOBYGO_EXEC -c $1 preproc-key-gen --dkg-params $PARAMS --num-sessions 5 --session-type $SESSION_TYPE --sid $CURR_SID --seed $SEED
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

### CRS generation
echo "Generating CRS"
$MOBYGO_EXEC -c $1 crs-gen --parameters $PARAMS --sid $CURR_SID --seed $SEED
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true
$MOBYGO_EXEC -c $1 crs-gen-result --sid $CURR_SID  --storage-path $CRS_PATH
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))

# Make sure the generated CRS has the expected hash
CRS_HASH=$(sha256sum $CRS_PATH/crs.bin|cut -d ' ' -f 1)
if [ "$CRS_HASH" != "$EXPECTED_CRS_HASH" ]; then
    echo "❌ CRS hash does not match expected value. Got $CRS_HASH, expected $EXPECTED_CRS_HASH"
    exit 1
else
    echo "✅ CRS hash matches expected value: $CRS_HASH"
fi


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
    for CTXT_TYPE in bool u4 u8 u16 u32 u64 u128
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