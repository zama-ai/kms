echo "Running test script on config file $1".
#Setting all the variables needed
ROOT_DIR=$(cargo locate-project --workspace -q --message-format plain|grep -o '.*/')
STAIRWAYCTL_EXEC="${ROOT_DIR}/target/debug/stairwayctl"
CURR_SID=1
KEY_PATH="./temp/bgv-key"
NUM_CTXTS=10

exec 2>&1
set -x

#build stairwayctl
cargo build --bin stairwayctl --features="choreographer,experimental,testing"

#Init the PRSS
$STAIRWAYCTL_EXEC -c $1 prss-init --ring level-one --sid $CURR_SID
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
CURR_SID=$(( CURR_SID + 1 ))
$STAIRWAYCTL_EXEC -c $1 prss-init --ring level-ksw --sid $CURR_SID
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
CURR_SID=$(( CURR_SID + 1 ))


##FAKE KEY GEN (centralized generation and shared)
#Get the key
mkdir -p $KEY_PATH
$STAIRWAYCTL_EXEC -c $1 threshold-key-gen-result --sid $CURR_SID --storage-path $KEY_PATH --generate-params true
CURR_SID=$(( CURR_SID + 1 ))

###DDEC
#Perform NUM_CTXTS decryptions
$STAIRWAYCTL_EXEC -c $1 threshold-decrypt --path-pubkey $KEY_PATH/pk.bin --num-msgs $NUM_CTXTS --sid $CURR_SID
$STAIRWAYCTL_EXEC -c $1 status-check --sid $CURR_SID --keep-retry true
##Get the result
$STAIRWAYCTL_EXEC -c $1 threshold-decrypt-result --sid $CURR_SID

printf "Press enter to shutdown experiment\n"
read _ 