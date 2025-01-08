# Configuration Smart Contract (CSC)

The Configuration Smart Contract (CSC) serves as the single source of truth for parameterizing the KMS.

# Deploying the CSC code

An example of CSC deployment can be found in [`deploy_contracts.sh`](../../scripts/deploy_contracts.sh). Note that the CSC requires for the party identities at instantiation stage.

## Prerequisites

1. Install [Rust](https://www.rust-lang.org/tools/install) and enable wasm target:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```

2. Install [binaryen](https://github.com/WebAssembly/binaryen). We would use
   `wasm-opt` included in it for optimizing the wasm binary.

3. Install [Wasmd](https://github.com/CosmWasm/wasmd) which is used for smart contracts uploading:
   - Install [Go](https://go.dev/dl/) (if not installed already)
   - Clone Wasmd reporitory: ```git clone https://github.com/CosmWasm/wasmd.git```
   - Compile the Wasmd binary: ```cd wasmd && make build```
   - Optionally, move the binary to a directory in your PATH (e.g., ```sudo mv ./build/wasmd /usr/local/bin/wasmd```)

## Building the CSC

These steps are similar to what is done in the [ci.dockerfile](../../operations/docker/ci.dockerfile).

1. Clone the [kms-core](https://github.com/zama-ai/kms-core) repository and checkout the branch corresponding to the version to be deployed.

2. Move to the `csc` crate directory.

   ```bash
   cd blockchain/contracts/csc
   ```

3. Set the environment variable that points to the final compiled and optimized wasm file after steps 4 and 5.

   ```bash
   CSC_WASMFILE=../../../target/wasm32-unknown-unknown/wasm/csc.wasm
   ```

4. Compile the contract

   ```bash
   cargo build --target wasm32-unknown-unknown --profile wasm
   ```

5. Optimize the contract binary

   ```bash
   wasm-opt -Oz $CSC_WASMFILE -o $CSC_WASMFILE
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

b. `STORAGE_BASE_URL`: URL for storing the public key materials

```bash
export STORAGE_BASE_URL=https://dummy-storage-base-url.example.com
```

c. `ADMIN_ADDRESS`: Will be allowed to make admin level calls to the contract:
add/remove members to allowed lists, migrate the contract from one version to
another. Also, will be allowed to update the KMS configuration parameters.

For simplicity, we could use the connector's address for the address above.

```bash
export ADMIN_ADDRESS=$(wasmd keys show connector -a)
```

#### 3. Upload the CSC and fetch its Code ID:

   ```bash
   CSC_UPLOAD_TX=$(wasmd tx wasm store $CSC_WASMFILE --from validator --chain-id local-dev-chain --node $NODE_URL --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json)
   ```

   ```bash
   CSC_TX_HASH=$(echo "${CSC_UPLOAD_TX}" | jq -r '.txhash')
   ```

   ```bash
   CSC_CODE_ID=$(wasmd query tx --output json --node $NODE_URL $CSC_TX_HASH | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
   ```


#### 5. Instantiate the CSC and fetch its address

   - For threshold mode:
   ```bash
   CSC_INST_TX_HASH=$(wasmd tx wasm instantiate $CSC_CODE_ID '{ "parties":[{"party_id": "01", "address": ""}, {"party_id": "02", "address": ""}, {"party_id": "03", "address": ""}, {"party_id": "04", "address": ""}], "response_count_for_majority_vote": 3, "response_count_for_reconstruction": 3, "degree_for_reconstruction": 1, "fhe_parameter": "default", "storage_base_urls": ["'$STORAGE_BASE_URL'"], "allowlists":{"admin": ["'$ADMIN_ADDRESS'"], "configure": ["'$ADMIN_ADDRESS'"]} }' --label "csc-threshold" --from validator --output json --node $NODE_URL --chain-id local-dev-chain -y --admin $ADMIN_ADDRESS --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 | jq -r '.txhash')
   ```

   - For centralized mode:
   ```bash
   CSC_INST_TX_HASH=$(wasmd tx wasm instantiate $CSC_CODE_ID '{ "parties":[{"party_id": "01", "address": ""}], "response_count_for_majority_vote": 1, "response_count_for_reconstruction": 1, "degree_for_reconstruction": 0, "fhe_parameter": "default", "storage_base_urls": ["'$STORAGE_BASE_URL'"], "allowlists":{"admin": ["'$ADMIN_ADDRESS'"], "configure": ["'$ADMIN_ADDRESS'"]} }' --label "csc-centralized" --from validator --output json --node $NODE_URL --chain-id local-dev-chain -y --admin $ADMIN_ADDRESS --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 | jq -r '.txhash')
   ```

Then fetch the CSC address:

   ```bash
   CSC_INST_RESULT=$(wasmd query tx $CSC_INST_TX_HASH --output json --node $NODE_URL)
   ```

   ```bash
   CSC_ADDRESS=$(echo $CSC_INST_RESULT | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
   ```

# Migration: Upgrade the CSC code

Migration allows to upgrade the CSC code without changing its address and state.
There are different strategies to do so and we chose to directly use CosmWasm's migration feature.
This is because it has the advantage of not having to implement a custom proxy contract ourselves while
being easy to use.

See the [common readme](../common/README.md) for more details.