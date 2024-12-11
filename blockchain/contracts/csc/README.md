# CSC

The Configuration Smart Contract (CSC) is the point of truth for configuring the KMS.

# Deploying the CSC code

An example of CSC deployment can be found in [`deploy_contracts.sh`](../../scripts/deploy_contracts.sh).

## Prerequisites

1. [Install rust](https://www.rust-lang.org/tools/install) and enable wasm target.

   ```
   rustup target add wasm32-unknown-unknown
   ```

2. Install [binaryen](https://github.com/WebAssembly/binaryen). We would use
   `wasm-opt` included in it for optimizing the wasm binary.

## Building the csc smart contract

These steps are similar to what is done in the [ci.dockerfile](../../operations/docker/ci.dockerfile).

1. Clone kms-core repository and checkout the branch corresponding to the version to be deployed.

2. Change directory to root of `csc` crate.

   ```
   cd blockchain/contracts/csc
   ```

3. Set the environment variable to point to wasm

   ```
   CSC_WASMFILE=../../../target/wasm32-unknown-unknown/release/csc.wasm
   ```

4. Compile the contract

   ```
   cargo build --release --target wasm32-unknown-unknown
   ```

5. Optimize the contract binary

   ```
   wasm-opt $CSC_WASMFILE -o $CSC_WASMFILE --strip-debug -Oz
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

c. `CONFIGURATOR_ADDRESS`: Will be allowed to update the configuration of the KMS.


For simplicity, we could use address of connector for all of the above addresses.

```
export KMS_CONNECTOR_ADDRESS=$(wasmd keys show connector -a)
export ADMIN_ADDRESS=$KMS_CONNECTOR_ADDRESS
export CONFIGURATOR_ADDRESS=$KMS_CONNECTOR_ADDRESS
```

2. Upload the CSC and fetch code_id.

   ```
   CSC_UPLOAD_TX=$(echo $KEYRING_PASSWORD | wasmd tx wasm store /app/csc.wasm --from validator --chain-id testing --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json --node "$NODE")
   ```

   ```
   CSC_TX_HASH=$(echo "${CSC_UPLOAD_TX}" | jq -r '.txhash')
   ```

   ```
   CSC_CODE_ID=$(wasmd query tx --output json --node "$NODE" "${CSC_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
   ```


3. Instantiate the CSC
   - in threshold mode :

   ```
   CSC_INST_TX_HASH=$(echo $KEYRING_PASSWORD | wasmd tx wasm instantiate "${CSC_CODE_ID}" '{ "parties":[{"party_id": "01", "address": ""}, {"party_id": "02", "address": ""}, {"party_id": "03", "address": ""}, {"party_id": "04", "address": ""}], "response_count_for_majority_vote": 3, "response_count_for_reconstruction": 3, "degree_for_reconstruction": 1, "param_choice": "default", "storage_base_urls": ["'"${STORAGE_BASE_URL}"'"], "allowlists":{"admin": ["'"${CONNECTOR_ADDRESS}"'"], "configure": ["'"${CONNECTOR_ADDRESS}"'"]} }' --label "csc-threshold" --from validator --output json --node "$NODE" --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')
   ```

   - in centralized mode :
   ```
   CSC_INST_TX_HASH=$(echo $KEYRING_PASSWORD | wasmd tx wasm instantiate "${CSC_CODE_ID}" '{ "parties":[{"party_id": "01", "address": ""}], "response_count_for_majority_vote": 1, "response_count_for_reconstruction": 1, "degree_for_reconstruction": 0, "param_choice": "default", "storage_base_urls": ["'"${STORAGE_BASE_URL}"'"], "allowlists":{"admin": ["'"${CONNECTOR_ADDRESS}"'"], "configure": ["'"${CONNECTOR_ADDRESS}"'"]} }' --label "csc-centralized" --from validator --output json --node "$NODE" --chain-id testing -y --admin "${VALIDATOR_ADDRESS}" | jq -r '.txhash')

   ```

4. Fetch the CSC address

   ```
   CSC_INST_RESULT=$(wasmd query tx "${CSC_INST_TX_HASH}" --output json --node "$NODE")
   ```

   ```
   CSC_ADDRESS=$(echo "${CSC_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
   ```

# Migration: Upgrade the CSC code

Migration allows to upgrade the CSC code without changing its address and state.
There are different strategies to do so and we chose to directly use CosmWasm's migration feature.
This is because it has the advantage of not having to implement a custom proxy contract ourselves while
being easy to use.

See the [common readme](../common/README.md) for more details.