echo "Running test script on config file $1".
#build mobygo
cargo build --bin mobygo --features="choreographer"
ROOT_DIR=$(cargo locate-project --workspace -q --message-format plain|grep -o '.*/')
MOBYGO_EXEC="${ROOT_DIR}/target/debug/mobygo"
CURR_SID=1
KEY_PATH="./temp/tfhe-key"
NUM_CTXTS=10
PARAMS="nist-params-p32-sns-fglwe"

exec 2>&1
set -x
set -e
#Init the PRSS
$MOBYGO_EXEC -c $1 prss-init --ring residue-poly64 --sid $CURR_SID
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
CURR_SID=$(( CURR_SID + 1 ))
$MOBYGO_EXEC -c $1 prss-init --ring residue-poly128 --sid $CURR_SID
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true 
CURR_SID=$(( CURR_SID + 1 ))

##KEY GEN
#Create preproc for dkg with test parameters
$MOBYGO_EXEC -c $1 preproc-key-gen --dkg-params $PARAMS --num-sessions 5 --session-type small --sid $CURR_SID 
#Checking every half hour 
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true --interval 1800
CURR_SID=$(( CURR_SID + 1 ))
#Execute DKG using the produced preproc
$MOBYGO_EXEC -c $1 threshold-key-gen --dkg-params $PARAMS --sid $CURR_SID  --preproc-sid $(( CURR_SID - 1)) 
#Checking every 10mn
$MOBYGO_EXEC -c $1 status-check --sid $CURR_SID  --keep-retry true --interval 600 
#Get the key
mkdir -p $KEY_PATH
$MOBYGO_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID  --storage-path $KEY_PATH
CURR_SID=$(( CURR_SID + 1 ))

###Perform 10 dec of each types
for DDEC_MODE in prss-decrypt bit-dec-small-decrypt large-decrypt bit-dec-large-decrypt
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