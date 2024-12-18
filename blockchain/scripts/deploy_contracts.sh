#!/bin/sh

# TODO: better handle paths, maybe add an env var to specify the smart contracts folder

set -euo pipefail

#############################
#         Contracts         #
#############################

# Deploy and instantiate the ASC, IPSC, CSC and BSC CosmWasm smart contracts
# For the ASC we instantiate:
# - A debugging ASC with no proof verification (dummy IPSC)
# - A ASC bounded to a Ethereum IPSC
# - A ASC bounded to a Ethermint IPSC
#
# NOTE: To deploy the ASC and BSC we first need to know the address of the CSC

echo ""
echo "+++++++++++++++++++++++"
echo "Starting contracts setups"
echo "+++++++++++++++++++++++"
echo ""

ulimit unlimited

export KEYRING_PASSWORD="1234567890"
export VALIDATOR_NODE_ENDPOINT="${VALIDATOR_NODE_ENDPOINT:-tcp://localhost:26657}"
export NODE="$VALIDATOR_NODE_ENDPOINT"
export WASMD_NODE="$VALIDATOR_NODE_ENDPOINT"
export MODE="${MODE:-centralized}"
export STORAGE_BASE_URL="http://localhost:9000"

# Export the signing keys for each KMS core party
export SIGNING_KEY_1="01"
export SIGNING_KEY_2="02"
export SIGNING_KEY_3="03"
export SIGNING_KEY_4="04"

# Export the public storage labels for each KMS core party
export PARTY_1_PUBLIC_STORAGE_LABEL="PUB-p1"
export PARTY_2_PUBLIC_STORAGE_LABEL="PUB-p2"
export PARTY_3_PUBLIC_STORAGE_LABEL="PUB-p3"
export PARTY_4_PUBLIC_STORAGE_LABEL="PUB-p4"

# Get addresses
# NOTE: here we use the connector address because it's the one we allow to do key-gen
# but this is only because the default configuration of the simulator when running in
# the docker compose setup uses the connectors wallet.
CONNECTOR_ADDRESS_1=$(echo $KEYRING_PASSWORD | wasmd keys show connector1 --output json |jq -r '.address')
CONNECTOR_ADDRESS_2=$(echo $KEYRING_PASSWORD | wasmd keys show connector2 --output json |jq -r '.address')
CONNECTOR_ADDRESS_3=$(echo $KEYRING_PASSWORD | wasmd keys show connector3 --output json |jq -r '.address')
CONNECTOR_ADDRESS_4=$(echo $KEYRING_PASSWORD | wasmd keys show connector4 --output json |jq -r '.address')
VALIDATOR_ADDRESS=$(echo $KEYRING_PASSWORD | wasmd keys show validator --output json |jq -r '.address')

# Upload CSC
echo "Uploading CSC"
CSC_UPLOAD_TX=$(echo $KEYRING_PASSWORD | wasmd tx wasm store /app/csc.wasm --from validator --chain-id testing --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json --node "$NODE")
export CSC_UPLOAD_TX
echo "CSC_UPLOAD_TX: ${CSC_UPLOAD_TX}"
sleep 6

# Upload ASC
echo "Uploading ASC"
ASC_UPLOAD_TX=$(echo $KEYRING_PASSWORD | wasmd tx wasm store /app/asc.wasm --from validator --chain-id testing --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json --node "$NODE")
export ASC_UPLOAD_TX
echo "ASC_UPLOAD_TX: ${ASC_UPLOAD_TX}"
sleep 6

# Upload BSC
echo "Uploading BSC"
BSC_UPLOAD_TX=$(echo $KEYRING_PASSWORD | wasmd tx wasm store /app/bsc.wasm --from validator --chain-id testing --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json --node "$NODE")
export BSC_UPLOAD_TX
echo "BSC_UPLOAD_TX: ${BSC_UPLOAD_TX}"
sleep 6

# Upload IPSC Ethermint (Tendermint?)
echo "Uploading IPSC Ethermint"
TM_IPSC_ETHERMINT_UPLOAD_TX=$(echo $KEYRING_PASSWORD | wasmd tx wasm store /app/tendermint_ipsc.wasm --from validator --chain-id testing --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json --node "$NODE")
export TM_IPSC_ETHERMINT_UPLOAD_TX
echo "TM_IPSC_ETHERMINT_UPLOAD_TX: ${TM_IPSC_ETHERMINT_UPLOAD_TX}"
sleep 6

# Upload IPSC Ethereum
echo "Uploading IPSC Ethereum"
TM_IPSC_ETHEREUM_UPLOAD_TX=$(echo $KEYRING_PASSWORD | wasmd tx wasm store /app/ethereum_ipsc.wasm --from validator --chain-id testing --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json --node "$NODE")
export TM_IPSC_ETHEREUM_UPLOAD_TX
echo "TM_IPSC_ETHERMINT_UPLOAD_TX: ${TM_IPSC_ETHEREUM_UPLOAD_TX}"
sleep 6

# Extract the transaction hash
CSC_TX_HASH=$(echo "${CSC_UPLOAD_TX}" | jq -r '.txhash')
export CSC_TX_HASH

ASC_TX_HASH=$(echo "${ASC_UPLOAD_TX}" | jq -r '.txhash')
export ASC_TX_HASH

BSC_TX_HASH=$(echo "${BSC_UPLOAD_TX}" | jq -r '.txhash')
export BSC_TX_HASH

TM_IPSC_ETHERMINT_TX_HASH=$(echo "${TM_IPSC_ETHERMINT_UPLOAD_TX}" | jq -r '.txhash')
export TM_IPSC_ETHERMINT_TX_HASH

TM_IPSC_ETHEREUM_TX_HASH=$(echo "${TM_IPSC_ETHEREUM_UPLOAD_TX}" | jq -r '.txhash')
export TM_IPSC_ETHEREUM_TX_HASH

echo "CSC_TX_HASH: ${CSC_TX_HASH}"
echo "ASC_TX_HASH: ${ASC_TX_HASH}"
echo "BSC_TX_HASH: ${BSC_TX_HASH}"
echo "TM_IPSC_ETHERMINT_TX_HASH: ${TM_IPSC_ETHERMINT_TX_HASH}"
echo "TM_IPSC_ETHEREUM_TX_HASH: ${TM_IPSC_ETHEREUM_TX_HASH}"

if [ -z "${CSC_TX_HASH}" ]; then
  echo "Failed to upload CSC"
  exit 1
fi

if [ -z "${ASC_TX_HASH}" ]; then
  echo "Failed to upload ASC"
  exit 1
fi

if [ -z "${BSC_TX_HASH}" ]; then
  echo "Failed to upload BSC"
  exit 1
fi

if [ -z "${TM_IPSC_ETHERMINT_TX_HASH}" ]; then
  echo "Failed to upload Ethermint IPSC"
  exit 1
fi

if [ -z "${TM_IPSC_ETHEREUM_TX_HASH}" ]; then
  echo "Failed to upload Ethereum IPSC"
  exit 1
fi

# Query the transaction to get the code ID
CSC_CODE_ID=$(wasmd query tx --output json --node "$NODE" "${CSC_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
export CSC_CODE_ID

ASC_CODE_ID=$(wasmd query tx --output json --node "$NODE" "${ASC_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
export ASC_CODE_ID

BSC_CODE_ID=$(wasmd query tx --output json --node "$NODE" "${BSC_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
export BSC_CODE_ID

TM_IPSC_ETHERMINT_CODE_ID=$(wasmd query tx --output json --node "$NODE" "${TM_IPSC_ETHERMINT_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
export TM_IPSC_ETHERMINT_CODE_ID

TM_IPSC_ETHEREUM_CODE_ID=$(wasmd query tx --output json --node "$NODE" "${TM_IPSC_ETHEREUM_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
export TM_IPSC_ETHEREUM_CODE_ID

if [ -z "${CSC_CODE_ID}" ]; then
  echo "Failed to retrieve CSC code ID"
  exit 1
fi

if [ -z "${ASC_CODE_ID}" ]; then
  echo "Failed to retrieve ASC code ID"
  exit 1
fi

if [ -z "${BSC_CODE_ID}" ]; then
  echo "Failed to retrieve BSC code ID"
  exit 1
fi

if [ -z "${TM_IPSC_ETHERMINT_CODE_ID}" ]; then
  echo "Failed to retrieve Ethermint IPSC code ID"
  exit 1
fi

if [ -z "${TM_IPSC_ETHEREUM_CODE_ID}" ]; then
  echo "Failed to retrieve Ethereum IPSC code ID"
  exit 1
fi

echo "CSC code ID: ${CSC_CODE_ID}"
echo "ASC code ID: ${ASC_CODE_ID}"
echo "BSC code ID: ${BSC_CODE_ID}"
echo "Ethermint IPSC code ID: ${TM_IPSC_ETHERMINT_CODE_ID}"
echo "Ethereum IPSC code ID: ${TM_IPSC_ETHEREUM_CODE_ID}"

# Instantiate the CSC
echo "Instantiating CSC"
if [ "$MODE" = "threshold" ]; then
  echo "(for threshold mode)"
  CSC_INST_TX_HASH=$(echo $KEYRING_PASSWORD | wasmd tx wasm instantiate "${CSC_CODE_ID}" '{ "parties": {"'"${SIGNING_KEY_1}"'": {"public_storage_label": "'"${PARTY_1_PUBLIC_STORAGE_LABEL}"'"}, "'"${SIGNING_KEY_2}"'": {"public_storage_label": "'"${PARTY_2_PUBLIC_STORAGE_LABEL}"'"}, "'"${SIGNING_KEY_3}"'": {"public_storage_label": "'"${PARTY_3_PUBLIC_STORAGE_LABEL}"'"}, "'"${SIGNING_KEY_4}"'": {"public_storage_label": "'"${PARTY_4_PUBLIC_STORAGE_LABEL}"'"}}, "response_count_for_majority_vote": 3, "response_count_for_reconstruction": 3, "degree_for_reconstruction": 1, "param_choice": "default", "storage_base_url": "'"${STORAGE_BASE_URL}"'", "allowlists":{"admin": ["'"${CONNECTOR_ADDRESS_1}"'"], "configure": ["'"${CONNECTOR_ADDRESS_1}"'"]} }' --label "csc-threshold" --from validator --output json --node "$NODE" --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 | jq -r '.txhash')
elif [ "$MODE" = "centralized" ]; then
  echo "(for centralized mode)"
  CSC_INST_TX_HASH=$(echo $KEYRING_PASSWORD | wasmd tx wasm instantiate "${CSC_CODE_ID}" '{ "parties": {"'"${SIGNING_KEY_1}"'": {"public_storage_label": "'"${PARTY_1_PUBLIC_STORAGE_LABEL}"'"}}, "response_count_for_majority_vote": 1, "response_count_for_reconstruction": 1, "degree_for_reconstruction": 0, "param_choice": "default", "storage_base_url": "'"${STORAGE_BASE_URL}"'", "allowlists":{"admin": ["'"${CONNECTOR_ADDRESS_1}"'"], "configure": ["'"${CONNECTOR_ADDRESS_1}"'"]} }' --label "csc-centralized" --from validator --output json --node "$NODE" --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 | jq -r '.txhash')
else
    echo "MODE is ${MODE} which is neither 'threshold' nor 'centralized', can't instantiate smart contract"
    exit 1
fi
export CSC_INST_TX_HASH
echo "CSC_INST_TX_HASH: ${CSC_INST_TX_HASH}"

# Wait for the transaction to be included in a block to retrieve the CSC's address
# to be able to instantiate the ASCs
echo "Waiting for CSC instantiation to be mined..."
sleep 10

echo "CSC instantiation result"
CSC_INST_RESULT=$(wasmd query tx "${CSC_INST_TX_HASH}" --output json --node "$NODE")
export CSC_INST_RESULT
echo "CSC_INST_RESULT : ${CSC_INST_RESULT}"
CSC_ADDRESS=$(echo "${CSC_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
export CSC_ADDRESS
echo "CSC_ADDRESS : ${CSC_ADDRESS}"

if [ -z "${CSC_ADDRESS}" ]; then
  echo "Failed to instantiate CSC"
  exit 1
fi

# Instantiate the IPSC smart contracts
echo "Instantiating IPSC Ethermint"
TM_IPSC_ETHERMINT_INST_TX_HASH=$(echo $KEYRING_PASSWORD | wasmd tx wasm instantiate "${TM_IPSC_ETHERMINT_CODE_ID}" '{}' --label "tendermint-ipsc" --from validator --output json --node "$NODE" --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')
export TM_IPSC_ETHERMINT_INST_TX_HASH
echo "TM_IPSC_ETHERMINT_INST_TX_HASH: ${TM_IPSC_ETHERMINT_INST_TX_HASH}"
sleep 6

echo "Instantiating IPSC Ethereum"
TM_IPSC_ETHEREUM_INST_TX_HASH=$(echo $KEYRING_PASSWORD | wasmd tx wasm instantiate "${TM_IPSC_ETHEREUM_CODE_ID}" '{}' --label "ethereum-ipsc" --from validator --output json --node "$NODE" --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')
export TM_IPSC_ETHEREUM_INST_TX_HASH
echo "TM_IPSC_ETHEREUM_INST_TX_HASH: ${TM_IPSC_ETHEREUM_INST_TX_HASH}"
sleep 6

# Wait for the transaction to be included in a block to retrieve corresponding addresses
# to be able to instantiate the ASCs
echo "Waiting for IPSC instantiate transactions to be mined..."
sleep 10

echo "Ethermint IPSC instantiation result"
TM_IPSC_ETHERMINT_INST_RESULT=$(wasmd query tx "${TM_IPSC_ETHERMINT_INST_TX_HASH}" --output json --node "$NODE")
export TM_IPSC_ETHERMINT_INST_RESULT
echo "TM_IPSC_ETHERMINT_INST_RESULT : ${TM_IPSC_ETHERMINT_INST_RESULT}"
IPSC_ETHERMINT_ADDRESS=$(echo "${TM_IPSC_ETHERMINT_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
export IPSC_ETHERMINT_ADDRESS
echo "IPSC_ETHERMINT_ADDRESS : ${IPSC_ETHERMINT_ADDRESS}"

if [ -z "${IPSC_ETHERMINT_ADDRESS}" ]; then
  echo "Failed to instantiate IPSC Ethermint"
  exit 1
fi

echo "Ethereum IPSC instantiation result"
TM_IPSC_ETHEREUM_INST_RESULT=$(wasmd query tx "${TM_IPSC_ETHEREUM_INST_TX_HASH}" --output json --node "$NODE")
export TM_IPSC_ETHEREUM_INST_RESULT
echo "TM_IPSC_ETHEREUM_INST_RESULT : ${TM_IPSC_ETHEREUM_INST_RESULT}"
IPSC_ETHEREUM_ADDRESS=$(echo "${TM_IPSC_ETHEREUM_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
export IPSC_ETHEREUM_ADDRESS
echo "IPSC_ETHEREUM_ADDRESS : ${IPSC_ETHEREUM_ADDRESS}"

if [ -z "${IPSC_ETHEREUM_ADDRESS}" ]; then
  echo "Failed to instantiate IPSC Ethereum"
  exit 1
fi

# Instantiate the ASC smart contracts using addresses of the IPSC above
# Always allow all connectors' addresses to answer even if we might be in centralized case
echo "Instantiating ASCs"
echo "Instantiating threshold ASC debug"
ASC_INST_DEBUG_TX_HASH=$(echo $KEYRING_PASSWORD | wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": true, "verify_proof_contract_addr": "dummy", "csc_address": "'"${CSC_ADDRESS}"'", "allowlists":{"generate": ["'"${CONNECTOR_ADDRESS_1}"'"], "response": ["'"${CONNECTOR_ADDRESS_1}"'","'"${CONNECTOR_ADDRESS_2}"'","'"${CONNECTOR_ADDRESS_3}"'","'"${CONNECTOR_ADDRESS_4}"'"], "admin": ["'"${CONNECTOR_ADDRESS_1}"'"]} }' --label "debug-asc" --from validator --output json --node "$NODE" --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3  | jq -r '.txhash')
sleep 6

echo "Instantiating threshold ASC Ethermint"
ASC_INST_ETHERMINT_TX_HASH=$(echo $KEYRING_PASSWORD | NODE="$NODE" wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": false, "verify_proof_contract_addr": "'"${IPSC_ETHERMINT_ADDRESS}"'", "csc_address": "'"${CSC_ADDRESS}"'", "allowlists":{"generate": ["'"${CONNECTOR_ADDRESS_1}"'"], "response": ["'"${CONNECTOR_ADDRESS_1}"'","'"${CONNECTOR_ADDRESS_2}"'","'"${CONNECTOR_ADDRESS_3}"'","'"${CONNECTOR_ADDRESS_4}"'"], "admin": ["'"${CONNECTOR_ADDRESS_1}"'"]} }' --label "tendermint-asc" --from validator --output json --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3  |  jq -r '.txhash')
sleep 6

echo "Instantiating threshold ASC Ethereum"
ASC_INST_ETHEREUM_TX_HASH=$(echo $KEYRING_PASSWORD | NODE="$NODE" wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": false, "verify_proof_contract_addr": "'"${IPSC_ETHEREUM_ADDRESS}"'", "csc_address": "'"${CSC_ADDRESS}"'", "allowlists":{"generate": ["'"${CONNECTOR_ADDRESS_1}"'"], "response": ["'"${CONNECTOR_ADDRESS_1}"'","'"${CONNECTOR_ADDRESS_2}"'","'"${CONNECTOR_ADDRESS_3}"'","'"${CONNECTOR_ADDRESS_4}"'"], "admin": ["'"${CONNECTOR_ADDRESS_1}"'"]} }' --label "ethereum-asc" --from validator --output json --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3  | jq -r '.txhash')
sleep 6

export ASC_INST_DEBUG_TX_HASH
echo "ASC_INST_DEBUG_TX_HASH: ${ASC_INST_DEBUG_TX_HASH}"
export ASC_INST_ETHERMINT_TX_HASH
echo "ASC_INST_ETHERMINT_TX_HASH: ${ASC_INST_ETHERMINT_TX_HASH}"
export ASC_INST_ETHEREUM_TX_HASH
echo "ASC_INST_ETHEREUM_TX_HASH: ${ASC_INST_ETHEREUM_TX_HASH}"

# Wait for the transaction to be included in a block
echo "Waiting for ASC transactions to be mined..."
sleep 10

echo "ASC Debug instantiation result"
ASC_DEBUG_INST_RESULT=$(NODE="$NODE" wasmd query tx "${ASC_INST_DEBUG_TX_HASH}" --output json)
export ASC_DEBUG_INST_RESULT
echo "${ASC_DEBUG_INST_RESULT}"
ASC_DEBUG_ADDRESS=$(echo "${ASC_DEBUG_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
export ASC_DEBUG_ADDRESS

if [ -z "${ASC_DEBUG_ADDRESS}" ]; then
  echo "Failed to instantiate ASC Debug"
  exit 1
fi

echo "ASC Ethermint instantiation result"
ASC_ETHERMINT_INST_RESULT=$(NODE="$NODE" wasmd query tx "${ASC_INST_ETHERMINT_TX_HASH}" --output json)
export ASC_ETHERMINT_INST_RESULT
echo "${ASC_ETHERMINT_INST_RESULT}"
ASC_ETHERMINT_ADDRESS=$(echo "${ASC_ETHERMINT_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
export ASC_ETHERMINT_ADDRESS

if [ -z "${ASC_ETHERMINT_ADDRESS}" ]; then
  echo "Failed to instantiate ASC Ethermint"
  exit 1
fi

echo "ASC Ethereum instantiation result"
ASC_ETHEREUM_INST_RESULT=$(NODE="$NODE" wasmd query tx "${ASC_INST_ETHEREUM_TX_HASH}" --output json)
export ASC_ETHEREUM_INST_RESULT
echo "${ASC_ETHEREUM_INST_RESULT}"
ASC_ETHEREUM_ADDRESS=$(echo "${ASC_ETHEREUM_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
export ASC_ETHEREUM_ADDRESS

if [ -z "${ASC_ETHEREUM_ADDRESS}" ]; then
  echo "Failed to instantiate ASC Ethereum"
  exit 1
fi

# Instantiate the BSC smart contracts using addresses of the CSC and IPSC above
echo "Instantiating BSC"
BSC_INST_TX_HASH=$(echo $KEYRING_PASSWORD | wasmd tx wasm instantiate "${BSC_CODE_ID}" '{"csc_address": "'"${CSC_ADDRESS}"'", "allowlists":{"generate": ["'"${CONNECTOR_ADDRESS_1}"'"], "response": ["'"${CONNECTOR_ADDRESS_1}"'"], "admin": ["'"${CONNECTOR_ADDRESS_1}"'"]} }' --label "bsc" --from validator --output json --node "$NODE" --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3  | jq -r '.txhash')
sleep 6

export BSC_INST_TX_HASH
echo "BSC_INST_TX_HASH: ${BSC_INST_TX_HASH}"

# Wait for the transaction to be included in a block
echo "Waiting for BSC instantiation to be mined..."
sleep 10

echo "BSC instantiation result"
BSC_INST_RESULT=$(NODE="$NODE" wasmd query tx "${BSC_INST_TX_HASH}" --output json)
export BSC_INST_RESULT
echo "${BSC_INST_RESULT}"

BSC_ADDRESS=$(echo "${BSC_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
export BSC_ADDRESS
if [ -z "${BSC_ADDRESS}" ]; then
  echo "Failed to instantiate BSC"
  exit 1
fi

echo "Summary of all the addresses:"
echo "CSC_ADDRESS : ${CSC_ADDRESS}"
echo "IPSC_ETHERMINT_ADDRESS : ${IPSC_ETHERMINT_ADDRESS}"
echo "IPSC_ETHEREUM_ADDRESS : ${IPSC_ETHEREUM_ADDRESS}"
echo "ASC_DEBUG_ADDRESS : ${ASC_DEBUG_ADDRESS}"
echo "ASC_ETHERMINT_ADDRESS : ${ASC_ETHERMINT_ADDRESS}"
echo "ASC_ETHEREUM_ADDRESS : ${ASC_ETHEREUM_ADDRESS}"
echo "BSC_ADDRESS : ${BSC_ADDRESS}"

echo ""
echo "+++++++++++++++++++++++++++"
echo "Contracts setups successful"
echo "+++++++++++++++++++++++++++"
echo ""
