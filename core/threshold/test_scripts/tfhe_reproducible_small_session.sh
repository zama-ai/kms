echo "Running test script on config file $1".
#build mobygo
cargo build --bin mobygo --features="choreographer"
ROOT_DIR=$(cargo locate-project --workspace -q --message-format plain|grep -o '.*/')
MOBYGO_EXEC="${ROOT_DIR}/target/debug/mobygo"
CURR_SID=1
KEY_PATH="./temp/tfhe-key"
CTXT_PATH="./temp/tfhe-ctxt"
NUM_CTXTS=10
PARAMS="params-test-bk-sns"
SEED=42
INIT_VALUE=1

export RUN_MODE=dev

exec 2>&1
set -e
#Init the PRSS
$MOBYGO_EXEC -c $1 prss-init --ring residue-poly-z64 --sid $CURR_SID --seed $SEED
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))
$MOBYGO_EXEC -c $1 prss-init --ring residue-poly-z128 --sid $CURR_SID --seed $SEED
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))

##KEY GEN
#Create preproc for dkg with test parameters
$MOBYGO_EXEC -c $1 preproc-key-gen --dkg-params $PARAMS --num-sessions 5 --session-type small --sid $CURR_SID --seed $SEED
#Checking every 30s
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true --interval 30
CURR_SID=$(( CURR_SID + 1 ))
SEED=$(( SEED + 1 ))
#Execute DKG using the produced preproc
$MOBYGO_EXEC -c $1 threshold-key-gen --dkg-params $PARAMS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) --seed $SEED
#Checking every 30s
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true --interval 30
#Get the key
mkdir -p $KEY_PATH
$MOBYGO_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID  --storage-path $KEY_PATH
CURR_SID=$(( CURR_SID + 1 ))

# Makes sure the generated keys has the expected hash
EXPECTED_HASH="e8a52aa35fe9d4f1a1252285b6fd8c0626e4395385467633eb2789d6792abb47"
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
    VALUE=$INIT_VALUE
    for CTXT_TYPE in bool u4 u8 u16 u32 u64
    do
        echo "#TYPE $CTXT_TYPE#"
        # Encrypt the type
         $MOBYGO_EXEC -c $1 encrypt --path-pubkey $KEY_PATH/pk.bin --tfhe-type $CTXT_TYPE --value $VALUE --output-file ${CTXT_PATH}/ctxt_${VALUE}_${CTXT_TYPE}.bin
         VALUE=$(( VALUE * 2 ))
    done
else
    echo "Skipping ctxt generation"
fi



### Make sure we can decrypt all
for DDEC_MODE in noise-flood-small bit-dec-small
 do
    VALUE=$INIT_VALUE
    echo "### STARTING REQUESTS ON DDEC MODE $DDEC_MOD ###"
    for CTXT_TYPE in bool u4 u8 u16 u32 u64
    do
        echo "#TYPE $CTXT_TYPE#"
        #Create preproc
        $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type $CTXT_TYPE --sid $CURR_SID
        $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true
        CURR_SID=$(( CURR_SID + 1 ))
        #Send ctxt and ask for decryption using the produced preproc
        $MOBYGO_EXEC -c $1 threshold-decrypt-from-file --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --input-file ${CTXT_PATH}/ctxt_${VALUE}_${CTXT_TYPE}.bin --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1))
        $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true
        #Get the result
        $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID --expected-values $VALUE
        CURR_SID=$(( CURR_SID + 1 ))
        VALUE=$(( VALUE * 2 ))
    done
done

printf "Press enter to shutdown experiment\n"
read _