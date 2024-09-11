#!/bin/sh

export PASSWORD="1234567890"
# Setup the genesis accounts
# echo $PASSWORD | /opt/setup_wasmd.sh cosmos1pkptre7fdkl6gfrzlesjjvhxhlc3r4gmmk8rs6 wasm1z6rlvnjrm5nktcvt75x9yera4gu48jflhy2ysv wasm1flmuthp6yx0w6qt6078fucffrdkqlz4j5cw26n wasm1s50rdsxjuw8wnnk4qva5j20vfcrjuut0z2wxu4 wasm1k4c4wk2qjlf2vm303t936qaell4dcdmqx4umdf wasm1a9rs6gue7th8grjcudfkgzcphlx3fas7dtv5ka
echo $PASSWORD | /opt/setup_wasmd.sh wasm1z6rlvnjrm5nktcvt75x9yera4gu48jflhy2ysv wasm1a9rs6gue7th8grjcudfkgzcphlx3fas7dtv5ka

# Configure the KMS full node
sed -i -re 's/^(enabled-unsafe-cors =.*)$.*/enabled-unsafe-cors = true/g' /root/.wasmd/config/app.toml
sed -i -re 's/^(address = "localhost:9090")$.*/address = "0.0.0.0:9090"/g' /root/.wasmd/config/app.toml
sed -i -re 's/^(minimum-gas-prices =.*)$.*/minimum-gas-prices = "0.01ucosm"/g' /root/.wasmd/config/config.toml
sed -i -re 's/^(cors_allowed_origins =.*)$.*/cors_allowed_origins = \[\"*\"\]/g' /root/.wasmd/config/config.toml
sed -i -re 's/^(timeout_commit =.*)$.*/timeout_commit = "500ms"/g' /root/.wasmd/config/config.toml

# Start the KMS full node
# /opt/run_wasmd.sh
nohup /opt/run_wasmd.sh > /dev/null 2>&1 &
sleep 5

# Add Connector account
PUB_KEY_KMS_CONN='{"@type":"/cosmos.crypto.secp256k1.PubKey","key":"A/ZoCPf+L7Uxf3snWT+RU5+ivCmT8XR+NFpuhjm5cTP2"}'
echo $PASSWORD |wasmd keys add connector --pubkey "$PUB_KEY_KMS_CONN"
CONN_ADD=$(echo $PASSWORD |wasmd keys show connector --output json |jq -r '.address')

# Add Gateway account
PUB_KEY_KMS_GATEWAY='{"@type":"/cosmos.crypto.secp256k1.PubKey","key":"AqAodaWg+3JUxIz6CeH0hKN8rxUzuBgQ67SR0KemoDnp"}'
echo $PASSWORD |wasmd keys add gateway --pubkey "$PUB_KEY_KMS_GATEWAY"
GATEWAY_ADD=$(echo $PASSWORD |wasmd keys show gateway --output json |jq -r '.address')

# Send tokens to connector and gateway accounts
echo $PASSWORD |wasmd tx bank multi-send validator "$CONN_ADD" "$GATEWAY_ADD" "100000000ucosm" -y --chain-id testing


# Deploy and instantiate the ASC smart contract
sleep 1
echo $PASSWORD | wasmd tx wasm upload /app/asc.wasm --from validator --chain-id testing --node tcp://localhost:26657 --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json

# Deploy and instantiate the Tendermint smart contract
sleep 1
echo $PASSWORD | wasmd tx wasm upload /app/tendermint_ipsc.wasm --from validator --chain-id testing --node tcp://localhost:26657 --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json


# Instantiate the ASC smart contract
# run in threshold mode
# sleep 10
# echo $PASSWORD | wasmd tx wasm instantiate 1 '{"proof_type": "debug", "kms_core_conf": { "threshold": { "parties": [], "response_count_for_majority_vote": 3, "response_count_for_reconstruction": 3, "degree_for_reconstruction": 1, "param_choice": "default" }  }}' --label "configuration_0" --from validator --output json --chain-id testing --node tcp://kms-full-node:26657 -y --no-admin
# run in centralized mode
sleep 10
echo $PASSWORD | wasmd tx wasm instantiate 1 '{"debug_proof": true, "kms_core_conf": { "centralized": "default" }}' --label "asc" --from validator --output json --chain-id testing --node tcp://localhost:26657 -y --no-admin

sleep 10
echo $PASSWORD | wasmd tx wasm instantiate 2 '{}' --label "tendermint-ipsc" --from validator --output json --chain-id testing --node tcp://localhost:26657 -y --no-admin

echo "Done bootstrapping. Now simply running the validator node ..."

# keep the container running
tail -f /dev/null
