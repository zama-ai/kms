# Application Smart Contract (ASC)

The Application Smart Contract (ASC) processes several types of requests such as decryption, reencryption, key generation and CRS generation requests. It can interact with designated Inclusion Proof Smart Contracts (IPSC).

# Deploying the ASC code

An ASC needs to be bound to an IPSC specific to the blockchain. An example can be found in [`deploy_contracts.sh`](../../scripts/deploy_contracts.sh). In this document, we use Ethereum-IPSC as an example.

## Prerequisites

1. Install [Rust](https://www.rust-lang.org/tools/install) and enable wasm target.

   ```bash
   rustup target add wasm32-unknown-unknown
   ```

2. Install [binaryen](https://github.com/WebAssembly/binaryen). We would use
   `wasm-opt` included in it for optimizing the wasm binary.

## Building the Ethereum-IPSC

These steps are similar to what is done in the [ci.dockerfile](../../../docker/blockchain/contracts/ci.dockerfile).

1. Clone kms-core repository and checkout the branch corresponding to the version to be deployed.

2. Move to the `ethereum-ipsc` crate directory.
   ```bash
   cd blockchain/contracts/ethereum-ipsc
   ```

3. Set the environment variable that points to the final compiled and optimized wasm file after steps 4 and 5.
   ```bash
   ETHEREUM_IPSC_WASMFILE=../../../target/wasm32-unknown-unknown/wasm/ethereum_ipsc.wasm
   ```

4. Compile the contract
   ```bash
   cargo build --target wasm32-unknown-unknown --profile wasm
   ```

5. Optimize the contract binary
   ```bash
   wasm-opt $ETHEREUM_IPSC_WASMFILE -o $ETHEREUM_IPSC_WASMFILE --strip-debug -Oz
   ```

## Building the ASC

Steps are similar to that of Ethereum-IPSC, with only differences in directory and environment variable names.

1. Set the environment variable that points to compiled and optimized wasm
   ```bash
   ASC_WASMFILE=../../../target/wasm32-unknown-unknown/wasm/asc.wasm
   ```

2. Compile the contract
   ```bash
   cargo build --target wasm32-unknown-unknown --profile wasm
   ```

3. Optimize the contract binary
   ```bash
   wasm-opt $ASC_WASMFILE -o $ASC_WASMFILE --strip-debug -Oz
   ```

## Upload and instantiate the contracts.

### Docker Setup
This [docker compose file](../../../docker-compose-kms-base.yml) deploys the `dev-kms-blockchain-asc-deploy` service, which executes the [`setup_wallets`](../../scripts/setup_wallets.sh) and [`deploy_contracts`](../../scripts/deploy_contracts.sh) scripts.

To deploy the service, follow these steps from the project root directory:

1. Ensure Docker is installed and running on your system.
2. Navigate to the project root directory.
3. Run the following command to start the Docker Compose service:

    ```bash
    docker compose -f docker-compose-kms-base.yml run --build dev-kms-blockchain-asc-deploy
    ```

This will build and start the `dev-kms-blockchain-asc-deploy` service and execute the necessary scripts to set up wallets and deploy contracts.

### Local Setup

#### 1. Run the Wasmd node:

```
wasmd init local-dev-node --chain-id local-dev-chain
wasmd keys add connector
wasmd keys add validator
wasmd genesis add-genesis-account $(wasmd keys show validator -a) 1000000000stake,1000000000ucosm
wasmd genesis gentx validator 1000000000stake --chain-id local-dev-chain
wasmd genesis collect-gentxs
wasmd genesis validate
wasmd start
```

A clean-up from the previous Wasmd node setup can be done by completely removing the `~/.wasmd` directory:
```bash
rm -rf ~/.wasmd
```

#### 2. Set environment variables:

a. `NODE_URL`: URL for accessing the Wasmd node.

```bash
export NODE_URL=http://localhost:26657 # Port by default
```

b. `ADMIN_ADDRESS`: Will be allowed to make admin level calls to the contract:
add/remove members to the allowlist, migrate the contract from one version to
another, etc. Also, will be allowed to submit any kind of operations to the contract (such as
decryption, CRS generation, etc.). Usually this will be the KMS connector.

For simplicity, we could use the connector's address for the address above.

```bash
export ADMIN_ADDRESS=$(wasmd keys show connector -a)
```

#### 3. Upload the Ethereum-IPSC and fetch its Code ID:

   ```bash
   IPSC_ETHEREUM_UPLOAD_TX=$(wasmd tx wasm store $ETHEREUM_IPSC_WASMFILE --from validator --chain-id local-dev-chain --node $NODE_URL --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json)
   ```

   ```bash
   IPSC_ETHEREUM_TX_HASH=$(echo "${IPSC_ETHEREUM_UPLOAD_TX}" | jq -r '.txhash')
   ```

   ```bash
   IPSC_ETHEREUM_CODE_ID=$(wasmd query tx --output json --node $NODE_URL "${IPSC_ETHEREUM_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
   ```

#### 4. Upload the ASC and fetch its Code ID:

   ```bash
   ASC_UPLOAD_TX=$(wasmd tx wasm store $ASC_WASMFILE --from validator --chain-id local-dev-chain --node $NODE_URL --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json)
   ```

   ```bash
   ASC_TX_HASH=$(echo "${ASC_UPLOAD_TX}" | jq -r '.txhash')
   ```

   ```bash
   ASC_CODE_ID=$(wasmd query tx --output json --node $NODE_URL "${ASC_TX_HASH}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
   ```

#### 5. Deploy the Configuration Smart Contract (CSC)

Follow the [CSC readme](../csc/README.md) for more details. Steps are similar to the above, with the difference that it can be instantiated in either threshold or centralized mode. Retrieve the CSC's address: `CSC_ADDRESS`

#### 6. Deploy the Backend Smart Contract (BSC)

Follow the [BSC readme](../bsc/README.md) for more details. Retrieve the BSC's address: `BSC_ADDRESS`

#### 7. Instantiate the Ethereum-IPSC and fetch its address

   ```bash
   IPSC_ETHEREUM_INST_TX_HASH=$(wasmd tx wasm instantiate "${IPSC_ETHEREUM_CODE_ID}" '{}' --label "ethereum-ipsc" --from validator --output json --chain-id local-dev-chain --node $NODE_URL -y --admin $ADMIN_ADDRESS | jq -r '.txhash')
   ```

   ```bash
   IPSC_ETHEREUM_INST_RESULT=$(wasmd query tx "${IPSC_ETHEREUM_INST_TX_HASH}" --output json --node $NODE_URL)
   ```

   ```bash
   IPSC_ETHEREUM_ADDRESS=$(echo "${IPSC_ETHEREUM_INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
   ```

#### 9. Instantiate the ASC and fetch its address

   ```bash
   ASC_ETHEREUM_TX_HASH=$(NODE="$NODE" wasmd tx wasm instantiate "${ASC_CODE_ID}" '{"debug_proof": false, "verify_proof_contract_addr": "'"${IPSC_ETHEREUM_ADDRESS}"'", "csc_address": "'"${CSC_ADDRESS}"'", "bsc_address": "'"${BSC_ADDRESS}"'", "allowlists":{"generate": ["'"${ADMIN_ADDRESS}"'"], "response": ["'"${ADMIN_ADDRESS}"'"], "admin": ["'"${ADMIN_ADDRESS}"'"]} }' --label "ethereum-asc" --from validator --output json --chain-id local-dev-chain -y --admin "${VALIDATOR_ADDRESS}" --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3  | jq -r '.txhash')
   ```

   ```bash
   ASC_ETHEREUM_INST_RESULT=$(wasmd query tx $ASC_ETHEREUM_TX_HASH --output json --node $NODE_URL)
   ```

   ```bash
   ASC_ETHEREUM_ADDRESS=$(echo $ASC_ETHEREUM_INST_RESULT | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
   ```

# Migration: Upgrade the ASC code

Migration allows to upgrade the ASC code without changing its address and state.
There are different strategies to do so and we chose to directly use CosmWasm's migration feature.
This is because it has the advantage of not having to implement a custom proxy contract ourselves while
being easy to use.

See the [common readme](../common/README.md) for more details.
