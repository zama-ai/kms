#!/bin/bash



CHAIN_ID="my-chain"
TXFLAG="--chain-id $CHAIN_ID --gas-prices 0.025stake --gas auto --gas-adjustment 1.3"


wasmd init my-node --chain-id $CHAIN_ID
wasmd keys --keyring-backend test add main
wasmd keys --keyring-backend test add validator
wasmd genesis add-genesis-account $(wasmd keys --keyring-backend test show main -a) 100000000stake
wasmd genesis add-genesis-account $(wasmd keys --keyring-backend test show validator -a) 100000000stake
wasmd genesis gentx --keyring-backend test validator 100000000stake --chain-id $CHAIN_ID
wasmd genesis collect-gentxs
wasmd genesis validate
wasmd start --pruning=nothing

