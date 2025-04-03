echo "Running test script on config file $1".
#Setting all the variables needed
ROOT_DIR=$(cargo locate-project --workspace -q --message-format plain|grep -o '.*/')
STAIRWAYCTL_EXEC="${ROOT_DIR}/target/debug/stairwayctl"
CURR_SID=1
KEY_PATH="./temp/bgv-key"
NUM_CTXTS=10

exec 2>&1
set -x
set -e

#build stairwayctl
cargo build --bin stairwayctl --features="choreographer,experimental,testing"

#Init the PRSS
$STAIRWAYCTL_EXEC -c $1 prss-init --ring level-one --sid $CURR_SID
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
CURR_SID=$(( CURR_SID + 1 ))
$STAIRWAYCTL_EXEC -c $1 prss-init --ring level-ksw --sid $CURR_SID
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
CURR_SID=$(( CURR_SID + 1 ))


##KEY GEN
#Create preproc for dkg
$STAIRWAYCTL_EXEC -c $1 preproc-key-gen --num-sessions 5 --sid $CURR_SID
#Checking every 10 min
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true --interval 600
CURR_SID=$(( CURR_SID + 1 ))
#Execute DKG using the produced preproc
$STAIRWAYCTL_EXEC -c $1 threshold-key-gen --sid $CURR_SID --preproc-sid $((CURR_SID - 1))
#Checking every 10 min
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true --interval 600
#Get the key
mkdir -p $KEY_PATH
$STAIRWAYCTL_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID --storage-path $KEY_PATH 
CURR_SID=$(( CURR_SID + 1 ))

###DDEC
#Perform NUM_CTXTS decryptions
for NUM_PARALLEL_SESSIONS in 1 2 4 #8 16 32 64 
do
    $STAIRWAYCTL_EXEC -c $1 threshold-decrypt --path-pubkey $KEY_PATH/pk.bin --num-ctxt-per-session $NUM_CTXTS --num-parallel-sessions $NUM_PARALLEL_SESSIONS --sid $CURR_SID
    $STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
    ##Get the result
    $STAIRWAYCTL_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID
    CURR_SID=$(( CURR_SID + 1 ))
done

printf "Press enter to shutdown experiment\n"
read _ 