# KMS Connector Emulation Test Guide

This guide describes the procedures for testing the KMS Connector using the emulation environment. The emulation simulates a Layer 2 blockchain network (like Arbitrum) and tests the interaction between the KMS Connector, mock contract, and KMS Core.

## Currently Supported Tests

- Load Test
- Decrypt Test

## Load Test

This test focuses on evaluating the system's performance under load conditions.

### TLDR

Execute `./kms-connector/emulation/artifacts/load_test/start-emulation.sh` to start the emulation environment and test the KMS Connector.

### 1. Interface Compatibility Check

First, run the interface compatibility tests:

```bash
cargo test -p kms-connector interface_compatibility
```

If these tests fail, you need to rebuild both the tests and emulation components.

### 2. Rebuild Contract (If Needed)

If interface compatibility tests fail, rebuild the contract artifacts:

```bash
solc --base-path . --abi --bin artifacts/load_test/MockDecryptionManager.sol --overwrite -o artifacts
```

This generates fresh ABI and bytecode files that match your current contract implementation.

Print bytes of `MockDecryptionManager.bin` by executing: `cat ./artifacts/load_test/MockDecryptionManager.bin`

Paste them into `/kms-connector/bin/mock-events.rs` at the `bytecode` field.

### 3. Start Local Blockchain

Start Anvil with a 0.25 second block time to simulate Arbitrum's environment:

```bash
anvil --block-time 0.25
```

### 4. Start Test Components

Open three separate terminal windows and run the following components in order:

#### Terminal 1: Mock Events

Start the mock event emitter:

```bash
RUST_LOG=info cargo run --bin mock-events
```

This will deploy the mock contract and emit both public and user decryption events every 500ms.

#### Terminal 2: Mock KMS Core

Start the mock KMS Core service:

```bash
RUST_LOG=info cargo run --bin mock-core
```

This simulates the KMS Core service that processes decryption requests.

#### Terminal 3: KMS Connector

Start the KMS Connector with the test configuration:

```bash
RUST_LOG=info cargo run --bin kms-connector start -c kms-connector/emulation/test-config.toml
```

### Expected Load Test Behavior

When all components are running:

1. The mock contract will emit events every 500ms
2. The KMS Connector will pick up these events
3. Events will be forwarded to the mock KMS Core
4. KMS Core will process the events and forward the responses back to the KMS Connector
5. KMS Connector will process the responses and forward the results back to the mock contract as a transaction to envoke respective mock smart contract functions.

### Load Test Notes

- The 500ms event interval is chosen to balance between testing throughput and system stability given current implementation specifics.
- The 0.25s block time simulates Arbitrum's environment for more realistic testing

## Decrypt Test

This test focuses on evaluating the decryption functionality with a threshold setup using real KMS Core instances.

### Test Procedure

#### Step 1: Configure FHE Parameters

Navigate to `/kms-core/core-client/config/client_local_threshold.toml` and ensure `fhe_params = "Default"` is set.

#### Step 2: Start KMS Connectors

Launch 4 KMS-Connector instances in separate terminals:

```bash
RUST_LOG=info cargo run --bin kms-connector start -c kms-connector/config/environments/config-1.toml
RUST_LOG=info cargo run --bin kms-connector start -c kms-connector/config/environments/config-2.toml
RUST_LOG=info cargo run --bin kms-connector start -c kms-connector/config/environments/config-3.toml
RUST_LOG=info cargo run --bin kms-connector start -c kms-connector/config/environments/config-4.toml
```

#### Step 3: Start Local Blockchain

Launch Anvil to simulate the Layer 2 blockchain in a separate terminal:

```bash
anvil
```

#### Step 4: Start KMS Core Instances

Launch 4 KMS-Core instances in threshold mode using Docker Compose in a separate terminal:

```bash
docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml up
```

#### Step 5: Generate Insecure Keys and CRS

Generate the necessary cryptographic materials and obtain a keyID in a separate terminal:

```bash
cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml insecure-key-gen
```

#### Step 6: Generate Ciphertext Samples

Create test ciphertexts using the keyID obtained in the previous step:

```bash
./core-client/generate_test_ciphertexts.sh [keyID]
```

Replace `[keyID]` with the actual keyID identifier from Step 5.

#### Step 7: Initiate Decryption Events

Start issuing smart contract events for the KMS Connector to process:

```bash
cargo run --bin mock-decrypt [keyID]
```

Replace `[keyID]` with the same key identifier used in Step 6.

#### Step 8: Monitor System Behavior

Examine the logs of various running components to observe:

1. KMS Connector listening for blockchain events
2. Events being sent to KMS Core for processing
3. Decryption results being retrieved from KMS Core
4. Results being embedded as Layer 2 transactions

### Expected Behavior

When all components are running properly:

1. The mock-decrypt tool will issue smart contract events
2. KMS Connectors will detect these events and forward decryption requests to KMS Core
3. KMS Core instances will collaborate in threshold mode to decrypt the ciphertexts
4. Decryption results will be returned to KMS Connectors
5. KMS Connectors will submit the results as transactions to the Layer 2 blockchain

### Notes

- The threshold setup requires at least 3 out of 4 KMS Core instances to be operational for successful decryption
- This test validates the end-to-end decryption flow in a distributed environment
