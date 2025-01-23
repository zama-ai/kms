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
export RUST_LOG=info

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

##FAKE KEY GEN (centralized generation and shared)
#Get the key
#mkdir -p $KEY_PATH
#$MOBYGO_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID --storage-path $KEY_PATH --generate-params $PARAMS 
#CURR_SID=$(( CURR_SID + 1 ))
#Execute DKG using dummy preproc (because for now we only generate 10% of preproc)
$MOBYGO_EXEC -c $1 threshold-key-gen --dkg-params $PARAMS --sid $CURR_SID 
#Checking every 10mn
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true --interval 120 
#Get the key
mkdir -p $KEY_PATH
$MOBYGO_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID  --storage-path $KEY_PATH
CURR_SID=$(( CURR_SID + 1 ))

###Perform 10 dec of each types
for DDEC_MODE in prss-decrypt 
do
    echo "### STARTING REQUESTS ON DDEC MODE $DDEC_MOD ###"
    ##Bool
    echo "#TYPE BOOL#"
    #Create preproc  
    $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --num-blocks $NUM_CTXTS --sid $CURR_SID 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    CURR_SID=$(( CURR_SID + 1 ))
    #Send ctxt and ask for decryption using the produced preproc
    $MOBYGO_EXEC -c $1 threshold-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type bool --num-ctxts $NUM_CTXTS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    #Get the result
    $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID 
    CURR_SID=$(( CURR_SID + 1 ))

    ##u4
    echo "#TYPE U4#"
    #Create preproc  
    $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --num-blocks $(( 2 * NUM_CTXTS )) --sid $CURR_SID 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    CURR_SID=$(( CURR_SID + 1 ))
    #Send ctxt and ask for decryption using the produced preproc
    $MOBYGO_EXEC -c $1 threshold-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type u4 --num-ctxts $NUM_CTXTS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    #Get the result
    $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID 
    CURR_SID=$(( CURR_SID + 1 ))

    ##u8
    echo "#TYPE U8#"
    #Create preproc  
    $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --num-blocks $(( 4 * NUM_CTXTS )) --sid $CURR_SID 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    CURR_SID=$(( CURR_SID + 1 ))
    #Send ctxt and ask for decryption using the produced preproc
    $MOBYGO_EXEC -c $1 threshold-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type u8 --num-ctxts $NUM_CTXTS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    #Get the result
    $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID 
    CURR_SID=$(( CURR_SID + 1 ))

    ##u16
    echo "#TYPE U16#"
    #Create preproc  
    $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --num-blocks $(( 8 * NUM_CTXTS )) --sid $CURR_SID 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    CURR_SID=$(( CURR_SID + 1 ))
    #Send ctxt and ask for decryption using the produced preproc
    $MOBYGO_EXEC -c $1 threshold-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type u16 --num-ctxts $NUM_CTXTS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    #Get the result
    $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID 
    CURR_SID=$(( CURR_SID + 1 ))

    ##u32
    echo "#TYPE U32#"
    #Create preproc  
    $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --num-blocks $(( 16 * NUM_CTXTS )) --sid $CURR_SID 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    CURR_SID=$(( CURR_SID + 1 ))
    #Send ctxt and ask for decryption using the produced preproc
    $MOBYGO_EXEC -c $1 threshold-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type u32 --num-ctxts $NUM_CTXTS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    #Get the result
    $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID 
    CURR_SID=$(( CURR_SID + 1 ))

    ##u64
    echo "#TYPE U64#"
    #Create preproc  
    $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --num-blocks $(( 32 * NUM_CTXTS )) --sid $CURR_SID 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    CURR_SID=$(( CURR_SID + 1 ))
    #Send ctxt and ask for decryption using the produced preproc
    $MOBYGO_EXEC -c $1 threshold-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type u64 --num-ctxts $NUM_CTXTS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    #Get the result
    $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID 
    CURR_SID=$(( CURR_SID + 1 ))

    ##u128
    echo "#TYPE U128#"
    #Create preproc  
    $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --num-blocks $(( 64 * NUM_CTXTS )) --sid $CURR_SID 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    CURR_SID=$(( CURR_SID + 1 ))
    #Send ctxt and ask for decryption using the produced preproc
    $MOBYGO_EXEC -c $1 threshold-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type u128 --num-ctxts $NUM_CTXTS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    #Get the result
    $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID 
    CURR_SID=$(( CURR_SID + 1 ))

    ##u160
    echo "#TYPE U160#"
    #Create preproc  
    $MOBYGO_EXEC -c $1 preproc-decrypt --decryption-mode $DDEC_MODE --num-blocks $(( 80 * NUM_CTXTS )) --sid $CURR_SID 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    CURR_SID=$(( CURR_SID + 1 ))
    #Send ctxt and ask for decryption using the produced preproc
    $MOBYGO_EXEC -c $1 threshold-decrypt --decryption-mode $DDEC_MODE --path-pubkey $KEY_PATH/pk.bin --tfhe-type u160 --num-ctxts $NUM_CTXTS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
    $MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
    #Get the result
    $MOBYGO_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID 
    CURR_SID=$(( CURR_SID + 1 ))
done  

printf "Press enter to shutdown experiment\n"
read _ 