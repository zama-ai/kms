# KMS Connector Emulation Test Guide

This guide describes the procedure for testing the KMS Connector using the emulation environment. The emulation simulates a Layer 2 blockchain network (like Arbitrum) and tests the interaction between the KMS Connector, mock contract, and KMS Core.

## Test Setup and Execution

### TLDR

Execute `start-emulation.sh` to start the emulation environment and test the KMS Connector.

### 1. Interface Compatibility Check

First, run the interface compatibility tests:

```bash
cargo test -p kms-connector interface_compatibility
```

If these tests fail, you need to rebuild both the tests and emulation components.

### 2. Rebuild Contract (If Needed)

If interface compatibility tests fail, rebuild the contract artifacts:

```bash
solc --base-path . --abi --bin artifacts/MockDecryptionManager.sol --overwrite -o artifacts
```

This generates fresh ABI and bytecode files that match your current contract implementation.

Print bytes of `MockDecryptionManager.bin` by executing: `cat ./artifacts/MockDecryptionManager.bin`

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

## Expected Behavior

When all components are running:

1. The mock contract will emit events every 500ms
2. The KMS Connector will pick up these events
3. Events will be forwarded to the mock KMS Core
4. KMS Core will process the events and forward the responses back to the KMS Connector
5. KMS Connector will process the responses and forward the results back to the mock contract as a transaction to envoke respective mock smart contract functions.

## Notes

- The 500ms event interval is chosen to balance between testing throughput and system stability given current implementation specifics.
- The 0.25s block time simulates Arbitrum's environment for more realistic testing
