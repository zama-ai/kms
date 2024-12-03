# ASC

The application smart contract which is the main entry-point of the KMS blockchain.

# Deploying the ASC code

An ASC needs to be bound to an IPSC specific to the blockchain. An example can be found in [`deploy_contracts.sh`](../../scripts/deploy_contracts.sh). In this document, we use ethereum-ips as an example.

## Prerequisites

1. [Install rust](https://www.rust-lang.org/tools/install) and enable wasm target.

   ```
   rustup target add wasm32-unknown-unknown
   ```

2. Install [binaryen](https://github.com/WebAssembly/binaryen). We would use
   `wasm-opt` included in it for optimizing the wasm binary.

## Building the ethereum-ipsc smart contract

These steps are similar to what is done in the [ci.dockerfile](../../operations/docker/ci.dockerfile).

1. Clone kms-core repository and checkout the branch corresponding to the version to be deployed.

2. Change directory to root of ethereum-ipsc crate.

   ```
   cd blockchain/contracts/ethereum-ipsc
   ```

3. Set the environment variable to point to wasm

   ```
   ETHEREUM_IPSC_WASMFILE=../../../target/wasm32-unknown-unknown/release/ethereum_ipsc.wasm
   ```

4. Compile the contract

   ```
   cargo build --release --target wasm32-unknown-unknown
   ```

5. Optimize the contract binary

   ```
   wasm-opt $ETHEREUM_IPSC_WASMFILE -o $ETHEREUM_IPSC_WASMFILE --strip-debug -Oz
   ```

## Building the asc smart contract

Steps are similar to that of ethereum-ipsc smart contract, with only differences
in directory and environment variable names.

```
cd blockchain/contracts/asc
ASC_WASMFILE=../../../target/wasm32-unknown-unknown/release/asc.wasm
cargo build --release --target wasm32-unknown-unknown
wasm-opt $ASC_WASMFILE -o $ASC_WASMFILE --strip-debug -Oz
```

## Upload and instantiate the contracts.

1.  Set environment variables

a. `NODE_URL`: URL for accessing the tendermint node.

```
export NODE_URL=http://localhost:26657
```

b. `ADMIN_ADDRESS`: Will be allowed to make admin level calls to the contract:
add/remove members to allowed lists, migrate the contract from one version to
another.

c. `CONFIGURATOR_ADDRESS`: Will be allowed to update the config in the contract.

d. `FHE_GENERATOR_ADDRESS`: Will be allowed to trigger generation of FHE
paramters: key generation and crs generation.

e. `RESPONDER_ADDRESS`: Will be allowed be submit result of operations (such as
decrypt, crs gen) to the contract. Usually this will be the KMS connector.

For simplicity, we could use address of connector for all of the above addresses.

```
export KMS_CONNECTOR_ADDRESS=$(wasmd keys show connector -a)
export ADMIN_ADDRESS=$KMS_CONNECTOR_ADDRESS
export CONFIGURATOR_ADDRESS=$KMS_CONNECTOR_ADDRESS
export FHE_GENERATOR_ADDRESS=$KMS_CONNECTOR_ADDRESS
export RESPONDER_ADDRESS=$KMS_CONNECTOR_ADDRESS
```

2. Upload ethereum smart contract and fetch code_id.

   ```
   IPSC_ETHEREUM_UPLOAD_TX=$(echo $PASSWORD | wasmd tx wasm store $ETHEREUM_IPSC_WASMFILE --from validator --chain-id testing --node $NODE_URL --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json)
   ```

   ```
   IPSC_ETHEREUM_TX_HASH=$(echo "${IPSC_ETHEREUM_UPLOAD_TX}" | jq -r '.txhash')
   ```

   ```
   IPSC_ETHEREUM_CODE_ID=$(wasmd query tx --output json --node $NODE_URL "${IPSC_ETHEREUM_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
   ```

3. Upload asc smart contract and fetch code_id.

   ```
   ASC_UPLOAD_TX=$(echo $PASSWORD | wasmd tx wasm store $ASC_WASMFILE --from validator --chain-id testing --node $NODE_URL --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json)
   ```

   ```
   ASC_TX_HASH=$(echo "${ASC_UPLOAD_TX}" | jq -r '.txhash')
   ```

   ```
   ASC_CODE_ID=$(wasmd query tx --output json --node $NODE_URL "${ASC_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
   ```

4. Instantiate ethereum ipsc smart contract and fetch the address

   ```
   IPSC_ETHEREUM_INST_TX_HASH=$(echo $PASSWORD | wasmd tx wasm instantiate "${IPSC_ETHEREUM_CODE_ID}" '{}' --label "ethereum-ipsc" --from validator --output json --chain-id testing --node $NODE_URL -y --admin $ADMIN_ADDRESS | jq -r '.txhash')
   ```

   ```
   IPSC_ETHEREUM_INST_RESULT=$(wasmd query tx "${IPSC_ETHEREUM_INST_TX_HASH}" --output json --node $NODE_URL)
   ```

   ```
   IPSC_ETHEREUM_ADDRESS=$(echo "${IPSC_ETHEREUM_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
   ```

5. Deploy the Configuration Smart Contract (CSC)
Follow the [CSC readme](../csc/README.md) for more details. Steps are similar to the above, with the difference that it can be instantiated in either threshold or centralized mode. Retrieve the CSC's address: `CSC_ADDRESS`

6. Instantiate asc
  ```
   ASC_INST_ETHEREUM_TX_HASH=$(echo $KEYRING_PASSWORD | NODE="$NODE" wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": false, "verify_proof_contract_addr": "'"${IPSC_ETHEREUM_ADDRESS}"'", "csc_address": "'"${CSC_ADDRESS}"'", "allowlists":{"generate": ["'"${CONNECTOR_ADDRESS}"'"], "response": ["'"${CONNECTOR_ADDRESS}"'"], "admin": ["'"${CONNECTOR_ADDRESS}"'"]} }' --label "ethereum-asc" --from validator --output json --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3  | jq -r '.txhash')
  ```

7. Get the asc address

   ```
   ASC_ETHERMINT_ADDRESS=$(echo "${ASC_ETHERMINT_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
   ```

8. Print the addresses

   ```
   echo "IPSC_ETHEREUM_ADDRESS : ${IPSC_ETHEREUM_ADDRESS}"
   echo "ASC_ETHEREUM_ADDRESS : ${ASC_ETHEREUM_ADDRESS}"
   ```

# Migration: Upgrade the ASC code

Migration allows to upgrade the ASC code without changing its address and state.
There are different strategies to do so and we chose to directly use CosmWasm's migration feature.
This is because it has the advantage of not having to implement a custom proxy contract ourselves while
being easy to use.

See the [common readme](../common/README.md) for more details.