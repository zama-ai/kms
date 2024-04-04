#!/bin/bash

set -Eeuo pipefail

# in /config folder

ETHERMINT_NETWORK_KEYS_PATH=/root/.ethermintd/zama/keys/network-fhe-keys
KMS_NETWORK_KEY_PATH=/config/temp


# generate keys and copy them to ETHERMINT_NETWORK_KEYS_PATH
./prepare_fhe_keys.sh /usr/local/bin $ETHERMINT_NETWORK_KEYS_PATH

# init node
./setup.sh

# TODO make the key path parametrized
# Needed for first version of KMS
# Kms expect cks.bin at /config/temp because kms-server binary is located at /config
mkdir -p $KMS_NETWORK_KEY_PATH
cp $ETHERMINT_NETWORK_KEYS_PATH/cks $KMS_NETWORK_KEY_PATH/cks.bin


# run kms
./kms-server &

# start the node
TRACE=""
LOGLEVEL="info"

ETHERMINTD="ethermintd"

# Start the node (remove the --pruning=nothing flag if historical queries are not needed)
$ETHERMINTD start --pruning=nothing $TRACE --log_level $LOGLEVEL \
        --minimum-gas-prices=0.0001aphoton \
        --json-rpc.gas-cap=50000000 \
        --json-rpc.api eth,txpool,personal,net,debug,web3,miner \
        --api.enable \
        --rpc.laddr tcp://0.0.0.0:26657
