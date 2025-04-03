echo "Running test script on config file $1".
#build mobygo
cargo build --bin mobygo --features="choreographer"
ROOT_DIR=$(cargo locate-project --workspace -q --message-format plain|grep -o '.*/')
MOBYGO_EXEC="${ROOT_DIR}/target/debug/mobygo"
CURR_SID=1
KEY_PATH="./temp/tfhe-key"
NUM_CTXTS=10
PARAMS="params-test-bk-sns"

export RUN_MODE=dev

exec 2>&1
set -x
set -e
#Init the PRSS
$MOBYGO_EXEC -c $1 prss-init --ring residue-poly-z64 --sid $CURR_SID
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
CURR_SID=$(( CURR_SID + 1 ))
$MOBYGO_EXEC -c $1 prss-init --ring residue-poly-z128 --sid $CURR_SID
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
CURR_SID=$(( CURR_SID + 1 ))

##KEY GEN
#Create preproc for dkg with test parameters
$MOBYGO_EXEC -c $1 preproc-key-gen --dkg-params $PARAMS --num-sessions 5 --session-type small --sid $CURR_SID 
#Checking every half hour 
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true --interval 300 
CURR_SID=$(( CURR_SID + 1 ))
#Execute DKG using the produced preproc
$MOBYGO_EXEC -c $1 threshold-key-gen --dkg-params $PARAMS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
#Checking every 10mn
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true --interval 300 
#Get the key
mkdir -p $KEY_PATH
$MOBYGO_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID  --storage-path $KEY_PATH
CURR_SID=$(( CURR_SID + 1 ))

###Perform 10 dec of each types
for DDEC_MODE in noise-flood-small bit-dec-small noise-flood-large bit-dec-large
 do
    echo "### STARTING REQUESTS ON DDEC MODE $DDEC_MOD ###"
    for CTXT_TYPE in bool u4 u8 u16 u32 u64 u128 u160
    do
        echo "#TYPE $CTXT_TYPE#"
        #Create preproc  
        $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type $CTXT_TYPE --num-ctxts $NUM_CTXTS --sid $CURR_SID 
        $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
        CURR_SID=$(( CURR_SID + 1 ))
        #Send ctxt and ask for decryption using the produced preproc
        $MOBYGO_EXEC -c $1 threshold-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type $CTXT_TYPE --num-ctxts $NUM_CTXTS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
        $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
        #Get the result
        $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID 
        CURR_SID=$(( CURR_SID + 1 ))
    done
done  

printf "Press enter to shutdown experiment\n"
read _ 