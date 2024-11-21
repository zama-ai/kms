# ASC

The application smart contract which is the main entry-point of the KMS blockchain.

# Deploying the ASC code

An ASC needs to be bound to an IPSC specific to the blockchain. In this
document, we use ethereum-ips as an example.

## Prerequisites

1. [Install rust](https://www.rust-lang.org/tools/install) and enable wasm target.

   ```
   rustup target add wasm32-unknown-unknown
   ```

2. Install [binaryen](https://github.com/WebAssembly/binaryen). We would use
   `wasm-opt` included in it for optimizing the wasm binary.

## Building the ethereum-ipsc smart contract

1. Clone kms-core repository and checkout the branch correspondig to the version to be deployed.

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

5. Instatiate asc in centralized or threshold mode

- Centralized mode

  ```
  ASC_INST_ETHEREUM_TX_HASH=$(echo $KEYRING_PASSWORD | NODE="$NODE" wasmd tx- wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": false, "verify_proof_contract_addr": "'"${IPSC_ETHEREUM_ADDRESS}"'", "kms_core_conf": { "parties":[{"party_id": "01", "address": ""}], "response_count_for_majority_vote": 1, "response_count_for_reconstruction": 1, "degree_for_reconstruction": 0, "param_choice": "default" }, "allowed_addresses":{"allowed_to_gen": ["'"${FHE_GENERATOR_ADDRESS}"'"], "allowed_to_response": ["'"${RESPONDER_ADDRESS}"'"], "admins": ["'"${CONFIGURATOR_ADDRESS}"'"], "super_admins": ["'"${ADMIN_ADDRESS}"'"]} }' --label "ethereum-asc" --from validator --output json --chain-id testing -y --admin "${ADMIN_ADDRESS}" --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 | jq -r '.txhash')
  ```

- Threshold mode

  ```
  ASC_INST_ETHEREUM_TX_HASH=$(echo $KEYRING_PASSWORD | NODE="$NODE" wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": false, "verify_proof_contract_addr": "'"${IPSC_ETHEREUM_ADDRESS}"'",  "kms_core_conf": { "parties":[{"party_id": "01", "address": ""}, {"party_id": "02", "address": ""}, {"party_id": "03", "address": ""}, {"party_id": "04", "address": ""}], "response_count_for_majority_vote": 3, "response_count_for_reconstruction": 3, "degree_for_reconstruction": 1, "param_choice": "default"}, "allowed_addresses":{"allowed_to_gen": ["'"${FHE_GENERATOR_ADDRESS}"'"], "allowed_to_response": ["'"${RESPONDER_ADDRESS}"'"], "admins": ["'"${CONFIGURATOR_ADDRESS}"'"], "super_admins": ["'"${ADMIN_ADDRESS}"'"]} }' --label "ethereum-asc" --from validator --output json --chain-id testing -y --admin "${ADMIN_ADDRESS}" --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3  | jq -r '.txhash')
  ```

6. Get the asc address

   ```
   ASC_ETHERMINT_ADDRESS=$(echo "${ASC_ETHERMINT_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
   ```

7. Print the addresses

   ```
   echo "IPSC_ETHEREUM_ADDRESS : ${IPSC_ETHEREUM_ADDRESS}"
   echo "ASC_ETHEREUM_ADDRESS : ${ASC_ETHEREUM_ADDRESS}"
   ```

# Migration: Upgrade the ASC code

Migration allows to upgrade the ASC code without changing its address and state.
There are different strategies to do so and we chose to directly use CosmWasm's migration feature.
This is because it has the advantage of not having to implement a custom proxy contract ourselves while
being easy to use.

## Steps

Whenever the ASC code is updated of the address changes, the ASC needs to be migrated using the following steps:

1. If code in [`contract.rs`](src/contract.rs) have been updated:
   1. Make sure no function have been removed
   2. If needed, update the `migrate` entrypoint with a new signature and or logic. Note that this entrypoint is generally only used to update the contract's state. In our case, that might not be necessary thanks to state versioning.
2. Compile the new contract to wasm (steps from [`ci.dockerfile`](../../contracts/operations/docker/ci.dockerfile))
3. Upload the new contract (full command in [`bootstrap_asc.sh`](../../scripts/bootstrap_asc.sh)):

```
wasmd tx wasm store <asc_wasm_path>
```

4. Get the new contract's code ID:

```
`wasmd query tx --output json <new_asc_tx_hash> | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value'`
```

- `<new_asc_tx_hash>`: the transaction hash of the new ASC. Take example from the instantiation step in [`bootstrap_asc.sh`](../../scripts/bootstrap_asc.sh) if needed.

5. **IMPORTANT:** Do not instantiate the contract ❌
6. Migrate the contract (additional arguments might be needed, see [wasm CLI doc](https://docs.cosmwasm.com/wasmd/getting-started/cli)):

```
wasmd tx wasm migrate <asc_contract_address> <new_asc_code_id> <migration_args> --from <admin_address>
```

- `<asc_contract_address>`: the (persistent) ASC contract address.
- `<new_asc_code_id>`: the new ASC code ID retrieved in step 4.
- `<migration_args>`: the contract's migration entrypoint arguments. Currently, there are none: `'{}'`. Take example from the instantiation step in [`bootstrap_asc.sh`](../../scripts/bootstrap_asc.sh) if needed.
- `<admin_address>`: the contract's current admin address. See below for how to get ot change it.

## Admin management for migration

**IMPORTANT:** Migration can only be performed by the _admin_ of the contract, the `validator` account (initially).

Admin management is directly handled by an internal proxy contract from CosmWasm. It is possible to get or even change this admin. At in instantiation, in [`bootstrap_asc.sh`](../../scripts/bootstrap_asc.sh), the admin is set to the `validator` account.

### Get the contract's current admin

```
wasmd query wasm contract <asc_contract_address> --output json | jq -r '.contract_info.admin'
```

### Change the contract's admin

The following command can only be performed by the contract's current admin.

```
wasmd tx wasm set-contract-admin <asc_contract_address> <new_admin_address>
```

- `<asc_contract_address>`: the (persistent) ASC contract address.
- `<new_admin_address>`: the new admin address.

## Links

- [wasm CLI doc](https://docs.cosmwasm.com/wasmd/getting-started/cli)
- [wasm CLI source](https://github.com/CosmWasm/wasmd/blob/main/x/wasm/client/cli/new_tx.go)
- [wasmd example script](https://github.com/CosmWasm/wasmd/blob/main/scripts/contrib/local/02-contracts.sh#L81)
- [CosmWasm migration doc](https://book.cosmwasm.com/actor-model/contract-as-actor.html#migrations)
