echo "Running test script on config file $1".
#Setting all the variables needed
ROOT_DIR=$(cargo locate-project --workspace -q --message-format plain|grep -o '.*/')
STAIRWAYCTL_EXEC="${ROOT_DIR}/target/debug/stairwayctl"
CURR_SID=1
KEY_PATH="./temp/bgv-key"
CTXT_PATH="./temp/bgv-ctxt"
NUM_CTXTS=10
SEED=42
CTXT_VALUE=12345

exec 2>&1
set -x
set -e

#build stairwayctl
cargo build --bin stairwayctl

#Init the PRSS
$STAIRWAYCTL_EXEC -c $1 prss-init --ring level-one --sid $CURR_SID --seed $SEED
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))
$STAIRWAYCTL_EXEC -c $1 prss-init --ring level-ksw --sid $CURR_SID --seed $SEED
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))


##KEY GEN
#Create preproc for dkg
$STAIRWAYCTL_EXEC -c $1 preproc-key-gen --num-sessions 5 --sid $CURR_SID --seed $SEED
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true --interval 30
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))
#Execute DKG using the produced preproc
$STAIRWAYCTL_EXEC -c $1 threshold-key-gen --sid $CURR_SID --preproc-sid $((CURR_SID - 1)) --seed $SEED
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true --interval 30
#Get the key
mkdir -p $KEY_PATH
$STAIRWAYCTL_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID --storage-path $KEY_PATH
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))

# Makes sure the generated keys has the expected hash
EXPECTED_HASH="93be446a1b956773f973a8e578bcd6877db71c17ee2afd5caa34ac35a6c37c4e"
KEY_HASH=$(sha256sum $KEY_PATH/pk.bin|cut -d ' ' -f 1)
if [ "$KEY_HASH" != "$EXPECTED_HASH" ]; then
    echo "❌ Key hash does not match expected value. Got $KEY_HASH, expected $EXPECTED_HASH"
    exit 1
else
    echo "✅ Key hash matches expected value: $KEY_HASH"
fi

if [ $2 = "GEN" ]; then
    echo "Generating ctxts"
    mkdir -p $CTXT_PATH
    ### Generate all ctxts
    # Encrypt
     $STAIRWAYCTL_EXEC -c $1 encrypt --path-pubkey $KEY_PATH/pk.bin --value $CTXT_VALUE --output-file ${CTXT_PATH}/ctxt_${CTXT_VALUE}.bin
else
    echo "Skipping ctxt generation"
fi

###DDEC
$STAIRWAYCTL_EXEC -c $1 threshold-decrypt --path-pubkey $KEY_PATH/pk.bin --num-ctxt-per-session $NUM_CTXTS --num-parallel-sessions $NUM_PARALLEL_SESSIONS --sid $CURR_SID --seed $SEED
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
##Get the result
$STAIRWAYCTL_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID --expected-values $CTXT_VALUE
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))

printf "Press enter to shutdown experiment\n"
read _
