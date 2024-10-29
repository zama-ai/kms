#!/bin/sh

# TODO: fail script if some command fails

ulimit unlimited

export PASSWORD="1234567890"

#############################
#         Genesis           #
#############################

# Setup the genesis accounts
# echo $PASSWORD | /opt/setup_wasmd.sh cosmos1pkptre7fdkl6gfrzlesjjvhxhlc3r4gmmk8rs6 wasm1z6rlvnjrm5nktcvt75x9yera4gu48jflhy2ysv wasm1flmuthp6yx0w6qt6078fucffrdkqlz4j5cw26n wasm1s50rdsxjuw8wnnk4qva5j20vfcrjuut0z2wxu4 wasm1k4c4wk2qjlf2vm303t936qaell4dcdmqx4umdf wasm1a9rs6gue7th8grjcudfkgzcphlx3fas7dtv5ka
echo "Setting up genesis accounts"
chmod +x /app/setup_wasmd.sh
echo $PASSWORD | /app/setup_wasmd.sh wasm1z6rlvnjrm5nktcvt75x9yera4gu48jflhy2ysv wasm1a9rs6gue7th8grjcudfkgzcphlx3fas7dtv5ka

echo "DONE WITH SETUP-WASMD script"

# Configure the KMS full node
sed -i -re 's/^(enabled-unsafe-cors =.*)$.*/enabled-unsafe-cors = true/g' /root/.wasmd/config/app.toml
sed -i -re 's/^(address = "localhost:9090")$.*/address = "0.0.0.0:9090"/g' /root/.wasmd/config/app.toml
sed -i -re 's/^(minimum-gas-prices =.*)$.*/minimum-gas-prices = "0.01ucosm"/g' /root/.wasmd/config/config.toml
sed -i -re 's/^(cors_allowed_origins =.*)$.*/cors_allowed_origins = \[\"*\"\]/g' /root/.wasmd/config/config.toml
sed -i -re 's/^(timeout_commit =.*)$.*/timeout_commit = "500ms"/g' /root/.wasmd/config/config.toml

# Start the KMS full node
# /opt/run_wasmd.sh
nohup /opt/run_wasmd.sh > /dev/null 2>&1 &
sleep 6

#############################
#         Wallets           #
#############################

# TODO: Create multiple accounts

# Add Connector account
PUB_KEY_KMS_CONN='{"@type":"/cosmos.crypto.secp256k1.PubKey","key":"A/ZoCPf+L7Uxf3snWT+RU5+ivCmT8XR+NFpuhjm5cTP2"}'
PUB_KEY_KMS_GATEWAY='{"@type":"/cosmos.crypto.secp256k1.PubKey","key":"AqAodaWg+3JUxIz6CeH0hKN8rxUzuBgQ67SR0KemoDnp"}'

# Add accounts
echo $PASSWORD |wasmd keys add connector --pubkey "$PUB_KEY_KMS_CONN"
echo $PASSWORD |wasmd keys add gateway --pubkey "$PUB_KEY_KMS_GATEWAY"

sleep 6

# Get addresses
CONN_ADDRESS=$(echo $PASSWORD | wasmd keys show connector --output json |jq -r '.address')
GATEWAY_ADDRESS=$(echo $PASSWORD | wasmd keys show gateway --output json |jq -r '.address')
VALIDATOR_ADDRESS=$(echo $PASSWORD | wasmd keys show validator --output json |jq -r '.address')

# TODO: Have one account per connector instead of a shared one
# TODO: Add to the faucet account too

# Send tokens to connector and gateway accounts
echo "Sending tokens from validator to connector and gateway accounts"
# The validator has 1000000000ucosm (setup_wasmd.sh)
echo $PASSWORD | wasmd tx bank multi-send "$VALIDATOR_ADDRESS" "$CONN_ADDRESS" "$GATEWAY_ADDRESS" "450000000ucosm" -y --chain-id testing

#############################
#         Contracts         #
#############################

# Deploy and instantiate the ASC and IPSC smart contracts
# We deploy:
# - A debug ASC with no proof verification
# - A pair (ASC,IPSC) meant for Ethereum
# - A pair (ASC,IPSC) meant for Ethermint (Tendermint?)
#
# NOTE: To deploy the ASC we first need to know the address of the IPSC
#

sleep 6

# Upload ASC
echo "Uploading ASC"
ASC_UPLOAD_TX=$(echo $PASSWORD | wasmd tx wasm store /app/asc.wasm --from validator --chain-id testing --node tcp://localhost:26657 --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json)
export ASC_UPLOAD_TX
echo "ASC_UPLOAD_TX: ${ASC_UPLOAD_TX}"

sleep 6

# Upload IPSC Ethermint (Tendermint?) 
echo "Uploading IPSC Ethermint"
TM_IPSC_ETHERMINT_UPLOAD_TX=$(echo $PASSWORD | wasmd tx wasm store /app/tendermint_ipsc.wasm --from validator --chain-id testing --node tcp://localhost:26657 --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json)
export TM_IPSC_ETHERMINT_UPLOAD_TX
echo "TM_IPSC_ETHERMINT_UPLOAD_TX: ${TM_IPSC_ETHERMINT_UPLOAD_TX}"

sleep 6

# Upload IPSC Ethereum  
echo "Uploading IPSC Ethereum"
TM_IPSC_ETHEREUM_UPLOAD_TX=$(echo $PASSWORD | wasmd tx wasm store /app/ethereum_ipsc.wasm --from validator --chain-id testing --node tcp://localhost:26657 --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json)
export TM_IPSC_ETHEREUM_UPLOAD_TX
echo "TM_IPSC_ETHERMINT_UPLOAD_TX: ${TM_IPSC_ETHEREUM_UPLOAD_TX}"

sleep 6

# Extract the transaction hash
ASC_TX_HASH=$(echo "${ASC_UPLOAD_TX}" | jq -r '.txhash')
export ASC_TX_HASH
TM_IPSC_ETHERMINT_TX_HASH=$(echo "${TM_IPSC_ETHERMINT_UPLOAD_TX}" | jq -r '.txhash')
export TM_IPSC_ETHERMINT_TX_HASH
TM_IPSC_ETHEREUM_TX_HASH=$(echo "${TM_IPSC_ETHEREUM_UPLOAD_TX}" | jq -r '.txhash')
export TM_IPSC_ETHEREUM_TX_HASH

echo "ASC_TX_HASH: ${ASC_TX_HASH}"
echo "TM_IPSC_ETHERMINT_TX_HASH: ${TM_IPSC_ETHERMINT_TX_HASH}"
echo "TM_IPSC_ETHEREUM_TX_HASH: ${TM_IPSC_ETHEREUM_TX_HASH}"

if [ -z "${ASC_TX_HASH}" ]; then
  echo "Failed to upload ASC"
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
ASC_CODE_ID=$(wasmd query tx --output json "${ASC_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
export ASC_CODE_ID
TM_IPSC_ETHERMINT_CODE_ID=$(wasmd query tx --output json "${TM_IPSC_ETHERMINT_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
export TM_IPSC_ETHERMINT_CODE_ID
TM_IPSC_ETHEREUM_CODE_ID=$(wasmd query tx --output json "${TM_IPSC_ETHEREUM_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
export TM_IPSC_ETHEREUM_CODE_ID

if [ -z "${ASC_CODE_ID}" ]; then
  echo "Failed to retrieve ASC code ID"
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

echo "ASC code ID: ${ASC_CODE_ID}"
echo "Ethermint IPSC code ID: ${TM_IPSC_ETHERMINT_CODE_ID}"
echo "Ethereum IPSC code ID: ${TM_IPSC_ETHEREUM_CODE_ID}"

# Instantiate the IPSC smart contracts
echo "Instantiating IPSC Ethermint"
TM_IPSC_ETHERMINT_INST_TX_HASH=$(echo $PASSWORD | wasmd tx wasm instantiate "${TM_IPSC_ETHERMINT_CODE_ID}" '{}' --label "tendermint-ipsc" --from validator --output json --chain-id testing --node tcp://localhost:26657 -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')
export TM_IPSC_ETHERMINT_INST_TX_HASH
echo "TM_IPSC_ETHERMINT_INST_TX_HASH: ${TM_IPSC_ETHERMINT_INST_TX_HASH}"

sleep 6

echo "Instantiating IPSC Ethereum"
TM_IPSC_ETHEREUM_INST_TX_HASH=$(echo $PASSWORD | wasmd tx wasm instantiate "${TM_IPSC_ETHEREUM_CODE_ID}" '{}' --label "ethereum-ipsc" --from validator --output json --chain-id testing --node tcp://localhost:26657 -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')
export TM_IPSC_ETHEREUM_INST_TX_HASH
echo "TM_IPSC_ETHEREUM_INST_TX_HASH: ${TM_IPSC_ETHEREUM_INST_TX_HASH}"

sleep 6

# Wait for the transaction to be included in a block to retrieve corresponding addresses
# to be able to instantiate the ASCs
echo "Waiting for IPSC instantiate transactions to be mined..."
sleep 10

echo "Ethermint IPSC instantiation result"
TM_IPSC_ETHERMINT_INST_RESULT=$(wasmd query tx "${TM_IPSC_ETHERMINT_INST_TX_HASH}" --output json)
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
TM_IPSC_ETHEREUM_INST_RESULT=$(wasmd query tx "${TM_IPSC_ETHEREUM_INST_TX_HASH}" --output json)
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
echo "Instantiating ASCs"
if [ "$MODE" = "threshold" ]; then
  # run in threshold mode
  echo "Instantiating threshold ASC debug"
  ASC_INST_DEBUG_TX_HASH=$(echo $PASSWORD | wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": true, "verify_proof_contract_addr": "dummy",  "kms_core_conf": { "parties":[{"party_id": "01", "address": ""}, {"party_id": "02", "address": ""}, {"party_id": "03", "address": ""}, {"party_id": "04", "address": ""}], "response_count_for_majority_vote": 3, "response_count_for_reconstruction": 3, "degree_for_reconstruction": 1, "param_choice": "test"}, "allow_list_conf":{"allow_list": ["'"${CONN_ADDRESS}"'"]} }' --label "asc" --from validator --output json --chain-id testing --node tcp://localhost:26657 -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')

  sleep 6

  echo "Instantiating threshold ASC Ethermint"
  ASC_INST_ETHERMINT_TX_HASH=$(echo $PASSWORD | wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": false, "verify_proof_contract_addr": "'${IPSC_ETHERMINT_ADDRESS}'",  "kms_core_conf": { "parties":[{"party_id": "01", "address": ""}, {"party_id": "02", "address": ""}, {"party_id": "03", "address": ""}, {"party_id": "04", "address": ""}], "response_count_for_majority_vote": 3, "response_count_for_reconstruction": 3, "degree_for_reconstruction": 1, "param_choice": "test"}, "allow_list_conf":{"allow_list": ["'"${CONN_ADDRESS}"'"]} }' --label "asc" --from validator --output json --chain-id testing --node tcp://localhost:26657 -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')

  sleep 6

  echo "Instantiating threshold ASC Ethereum"
  ASC_INST_ETHEREUM_TX_HASH=$(echo $PASSWORD | wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": false, "verify_proof_contract_addr": "'${IPSC_ETHEREUM_ADDRESS}'",  "kms_core_conf": { "parties":[{"party_id": "01", "address": ""}, {"party_id": "02", "address": ""}, {"party_id": "03", "address": ""}, {"party_id": "04", "address": ""}], "response_count_for_majority_vote": 3, "response_count_for_reconstruction": 3, "degree_for_reconstruction": 1, "param_choice": "test"}, "allow_list_conf":{"allow_list": ["'"${CONN_ADDRESS}"'"]} }' --label "asc" --from validator --output json --chain-id testing --node tcp://localhost:26657 -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')

  sleep 6

elif [ "$MODE" = "centralized" ]; then
  # run in centralized mode
  echo "Instantiating centralized ASC debug"
  ASC_INST_DEBUG_TX_HASH=$(echo $PASSWORD | wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": true, "verify_proof_contract_addr": "dummy", "kms_core_conf": { "parties":[{"party_id": "01", "address": ""}], "response_count_for_majority_vote": 1, "response_count_for_reconstruction": 1, "degree_for_reconstruction": 0, "param_choice": "default"}, "allow_list_conf":{"allow_list": ["'"${CONN_ADDRESS}"'"]} }' --label "asc" --from validator --output json --chain-id testing --node tcp://localhost:26657 -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')

  sleep 6

  echo "Instantiating centralized ASC Ethermint"
  ASC_INST_ETHERMINT_TX_HASH=$(echo $PASSWORD | wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": false, "verify_proof_contract_addr": "'${IPSC_ETHERMINT_ADDRESS}'", "kms_core_conf": { "parties":[{"party_id": "01", "address": ""}], "response_count_for_majority_vote": 1, "response_count_for_reconstruction": 1, "degree_for_reconstruction": 0, "param_choice": "default"}, "allow_list_conf":{"allow_list": ["'"${CONN_ADDRESS}"'"]} }' --label "asc" --from validator --output json --chain-id testing --node tcp://localhost:26657 -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')

  sleep 6

  echo "Instantiating centralized ASC Ethereum"
  ASC_INST_ETHEREUM_TX_HASH=$(echo $PASSWORD | wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": false, "verify_proof_contract_addr": "'${IPSC_ETHEREUM_ADDRESS}'", "kms_core_conf": { "parties":[{"party_id": "01", "address": ""}], "response_count_for_majority_vote": 1, "response_count_for_reconstruction": 1, "degree_for_reconstruction": 0, "param_choice": "default"}, "allow_list_conf":{"allow_list": ["'"${CONN_ADDRESS}"'"]} }' --label "asc" --from validator --output json --chain-id testing --node tcp://localhost:26657 -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')

  sleep 6
else
    ASC_INST_TX_HASH="NONE"
    echo "MODE is ${MODE} which is neither 'threshold' nor 'centralized', can't instantiate smart contract"
fi

export ASC_INST_DEBUG_TX_HASH
echo "ASC_INST_DEBUG_TX_HASH: ${ASC_INST_DEBUG_TX_HASH}"
export ASC_INST_ETHERMINT_TX_HASH
echo "ASC_INST_ETHERMINT_TX_HASH: ${ASC_INST_ETHERMINT_TX_HASH}"
export ASC_INST_ETHEREUM_TX_HASH
echo "ASC_INST_ETHEREUM_TX_HASH: ${ASC_INST_ETHEREUM_TX_HASH}"

# Wait for the transaction to be included in a block
echo "Waiting for ASC transactions to be mined..."
sleep 10

# TODO: add a check -> raise an error if some upload failed

echo "ASC Debug instantiation result"
ASC_DEBUG_INST_RESULT=$(wasmd query tx "${ASC_INST_DEBUG_TX_HASH}" --output json)
export ASC_DEBUG_INST_RESULT
echo "${ASC_DEBUG_INST_RESULT}"
ASC_DEBUG_ADDRESS=$(echo "${ASC_DEBUG_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
export ASC_DEBUG_ADDRESS

if [ -z "${ASC_DEBUG_ADDRESS}" ]; then
  echo "Failed to instantiate ASC Debug"
  exit 1
fi

echo "ASC Ethermint instantiation result"
ASC_ETHERMINT_INST_RESULT=$(wasmd query tx "${ASC_INST_ETHERMINT_TX_HASH}" --output json)
export ASC_ETHERMINT_INST_RESULT
echo "${ASC_ETHERMINT_INST_RESULT}"
ASC_ETHERMINT_ADDRESS=$(echo "${ASC_ETHERMINT_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
export ASC_ETHERMINT_ADDRESS

if [ -z "${ASC_ETHERMINT_ADDRESS}" ]; then
  echo "Failed to instantiate ASC Ethermint"
  exit 1
fi

echo "ASC Ethereum instantiation result"
ASC_ETHEREUM_INST_RESULT=$(wasmd query tx "${ASC_INST_ETHEREUM_TX_HASH}" --output json)
export ASC_ETHEREUM_INST_RESULT
echo "${ASC_ETHEREUM_INST_RESULT}"
ASC_ETHEREUM_ADDRESS=$(echo "${ASC_ETHEREUM_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
export ASC_ETHEREUM_ADDRESS

if [ -z "${ASC_ETHEREUM_ADDRESS}" ]; then
  echo "Failed to instantiate ASC Ethereum"
  exit 1
fi


echo "Summary of all the addresses:"
echo "IPSC_ETHERMINT_ADDRESS : ${IPSC_ETHERMINT_ADDRESS}"
echo "IPSC_ETHEREUM_ADDRESS : ${IPSC_ETHEREUM_ADDRESS}"
echo "ASC_DEBUG_ADDRESS : ${ASC_DEBUG_ADDRESS}"
echo "ASC_ETHERMINT_ADDRESS : ${ASC_ETHERMINT_ADDRESS}"
echo "ASC_ETHEREUM_ADDRESS : ${ASC_ETHEREUM_ADDRESS}"

echo "Done bootstrapping. Now simply running the validator node ..."

# keep the container running
tail -f /dev/null
