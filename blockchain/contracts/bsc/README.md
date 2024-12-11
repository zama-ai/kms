# Backend Smart Contract (BSC)

The Backend Smart Contract (BSC) is the main entry point for interacting with the KMS. It provides functions for key and CRS generation, decryption, and reencryption.

# Deploying the BSC code

An example of BSC deployment can be found in [`deploy_contracts.sh`](../../scripts/deploy_contracts.sh). Note that the BSC needs to be bounded to a Configuration Smart Contract (CSC).

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

## Building the BSC

These steps are similar to what is done in the [ci.dockerfile](../operations/docker/ci.dockerfile).

1. Clone the [kms-core](https://github.com/zama-ai/kms-core) repository and checkout the branch corresponding to the version to be deployed.

2. Move to the `bsc` crate directory.

   ```bash
   cd blockchain/contracts/bsc
   ```

3. Set the environment variable that points to the final compiled and optimized wasm file after steps 3 and 4.

   ```bash
   BSC_WASMFILE=../../../target/wasm32-unknown-unknown/wasm/bsc.wasm
   ```

4. Compile the contract

   ```bash
   cargo build --target wasm32-unknown-unknown --profile wasm
   ```

5. Optimize the contract binary

   ```bash
   wasm-opt -Oz $BSC_WASMFILE -o $BSC_WASMFILE
   ```

## Upload and instantiate the contracts.

### Docker Setup
This [docker compose file](../../../docker-compose-kms-base.yml) deploys the `dev-kms-blockchain-asc-deploy` service, which executes the [`setup_wallets`](../../scripts/setup_wallets.sh) and [`deploy_contracts`](../../scripts/deploy_contracts.sh) scripts.

To deploy the service, follow these steps from the project root directory:

1. Ensure Docker is installed and running on your system.
2. Navigate to the project root directory.
3. Run the following command to start the Docker Compose service:

    ```bash
    docker compose -f docker-compose-kms-base.yml up
    ```

This will start the `dev-kms-blockchain-asc-deploy` service and execute the necessary scripts to set up wallets and deploy contracts.

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

For simplicity, we will use the same address (`ADMIN_ADDRESS`) for all the smart contract instantiations.

```bash
export ADMIN_ADDRESS=$(wasmd keys show connector -a)
```

#### 3. Upload the BSC and fetch its Code ID:

   ```bash
   BSC_UPLOAD_TX=$(wasmd tx wasm store $BSC_WASMFILE --from validator --chain-id local-dev-chain --node $NODE_URL --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3 -y --output json)
   ```

   ```bash
   BSC_TX_HASH=$(echo "${BSC_UPLOAD_TX}" | jq -r '.txhash')
   ```

   ```bash
   BSC_CODE_ID=$(wasmd query tx --output json --node $NODE_URL $BSC_TX_HASH | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
   ```

#### 4. Deploy the Configuration Smart Contract (CSC)
Follow the [CSC readme](../csc/README.md) for more details. Steps are similar to the above, with the difference that it can be instantiated in either threshold or centralized mode. Retrieve the CSC's address: `CSC_ADDRESS`

#### 5. Instantiate the BSC and fetch its address
   ```bash
   BSC_TX_HASH=$(NODE=$NODE wasmd tx wasm instantiate $BSC_CODE_ID '{"csc_address": "'$CSC_ADDRESS'", "allowlists":{"generate": ["'$ADMIN_ADDRESS'"], "response": ["'$ADMIN_ADDRESS'"], "admin": ["'$ADMIN_ADDRESS'"]} }' --label "bsc" --from validator --output json --chain-id local-dev-chain -y --admin $ADMIN_ADDRESS --gas-prices 0.25ucosm --gas auto --gas-adjustment 1.3  | jq -r '.txhash')
   ```

   ```bash
   BSC_INST_RESULT=$(wasmd query tx $BSC_TX_HASH --output json --node $NODE_URL)
   ```

   ```bash
   BSC_ADDRESS=$(echo $BSC_INST_RESULT | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value')
   ```

#### 6. Print the addresses

   ```bash
   echo "BSC_ADDRESS: $BSC_ADDRESS"
   ```

# Migration: Upgrade the BSC code

Migration allows to upgrade the BSC code without changing its address and state. There are different strategies to do so and we chose to directly use CosmWasm's migration feature. This is because it has the advantage of not having to implement a custom proxy contract ourselves while being easy to use.

See the [common readme](../common/README.md) for more details.
