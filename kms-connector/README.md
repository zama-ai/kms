# KMS Connector

KMS Connector is a Rust-based service that connects the KMS Core with the HTTPZ Gateway  (Arbitrum) smart contracts, handling decryption requests and key management operations.

## Features

- Event-driven architecture with MPSC orchestration
- Support for public/user decryption operations
- Key generation with extended finality support
- CRS generation and management
- Operation status notifications
- Arbitrum-specific finality rules
- CLI interface for configuration management and validation

## CLI Usage

The KMS Connector provides a command-line interface with the following commands:

### Start a Connector Instance

```bash
# Start with a specific config file
kms-connector start -c config/environments/config-1.toml

# Start with a custom service name
kms-connector start -c config/environments/config-1.toml -n "my-connector"

# Use custom config directory (via environment variable)
KMS_CONNECTOR_CONFIG_DIR=/path/to/configs kms-connector start -c config-1.toml
```

### List Available Configurations

```bash
# List configuration filenames
kms-connector list

# List full configuration paths
kms-connector list --full-path
```

### Validate Configuration

```bash
# Validate a specific configuration file
kms-connector validate -c config/environments/config-1.toml
```

### Environment Variables

- `KMS_CONNECTOR_CONFIG_DIR`: Override the default config directory location

### Configuration Structure

Configuration files use TOML format with the following structure:

```toml
# Service name for tracing (optional, default: "kms-connector")
service_name = "my-connector"

# KMS Core endpoint (required)
kms_core_endpoint = "http://localhost:50052"

# GateWay L2 WebSocket RPC URL endpoint (required)
gwl2_url = "ws://localhost:8757"

# Chain ID (required)
chain_id = 1337

# Decryption manager contract address (required)
decryption_manager_address = "0x..."

# HTTPZ contract address (required)
httpz_address = "0x..."

# Size of the event processing channel (optional)
channel_size = 1000
```

## Configuration

The KMS Connector supports flexible configuration through both TOML files and environment variables. You can use either method or combine them, with environment variables taking precedence over file-based configuration.

### Configuration Methods

1. **Environment Variables Only**

   ```bash
   # Set required configuration
   export KMS_CONNECTOR_GWL2_URL="ws://localhost:8547"
   export KMS_CONNECTOR_KMS_CORE_ENDPOINT="http://localhost:50052"
   export KMS_CONNECTOR_MNEMONIC="your mnemonic here"
   export KMS_CONNECTOR_CHAIN_ID="31337"
   export KMS_CONNECTOR_DECRYPTION_MANAGER_ADDRESS="0x..."
   export KMS_CONNECTOR_HTTPZ_ADDRESS="0x..."

   # Optional configuration with defaults
   export KMS_CONNECTOR_CHANNEL_SIZE="1000"
   export KMS_CONNECTOR_SERVICE_NAME="kms-connector"
   export KMS_CONNECTOR_DECRYPTION_TIMEOUT_SECS="300"
   export KMS_CONNECTOR_REENCRYPTION_TIMEOUT_SECS="300"
   export KMS_CONNECTOR_RETRY_INTERVAL_SECS="5"

   # Start the connector without a config file
   cargo run --bin kms-connector start
   ```

2. **Config File Only**

   ```bash
   # Use a TOML config file
   cargo run --bin kms-connector start --config ./config/environments/config-base.toml
   ```

3. **Combined Configuration**

   ```bash
   # Set specific overrides
   export KMS_CONNECTOR_GWL2_URL="ws://localhost:8547"
   export KMS_CONNECTOR_CHAIN_ID="31337"

   # Use config file for other values
   cargo run --bin kms-connector start --config ./config/environments/config-base.toml
   ```

### Configuration Precedence

The configuration values are loaded in the following order, with later sources overriding earlier ones:

1. Default values (lowest priority)
2. TOML config file (if provided)
3. Environment variables (highest priority)

### Default Values

When neither environment variables nor config file values are provided, the following defaults are used:

```toml
gwl2_url = "ws://localhost:8545"
kms_core_endpoint = "http://[::1]:50052"
chain_id = 31337
decryption_manager_address = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
httpz_address = "0x0000000000000000000000000000000000000001"
channel_size = 1000
service_name = "kms-connector"
decryption_timeout_secs = 300
reencryption_timeout_secs = 300
retry_interval_secs = 5
```

### List Of Environment Variables

All environment variables are prefixed with `KMS_CONNECTOR_`. Here's the complete list:

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `KMS_CONNECTOR_GWL2_URL` | Gateway L2 WebSocket URL | ws://localhost:8545 |
| `KMS_CONNECTOR_KMS_CORE_ENDPOINT` | KMS Core service endpoint | http://[::1]:50052 |
| `KMS_CONNECTOR_MNEMONIC` | Wallet mnemonic phrase | (required) |
| `KMS_CONNECTOR_CHAIN_ID` | Blockchain network chain ID | 31337 |
| `KMS_CONNECTOR_DECRYPTION_MANAGER_ADDRESS` | Address of the Decryption Manager contract | 0x5fbdb2315678afecb367f032d93f642f64180aa3 |
| `KMS_CONNECTOR_HTTPZ_ADDRESS` | Address of the HTTPZ contract | 0x0000000000000000000000000000000000000001 |
| `KMS_CONNECTOR_CHANNEL_SIZE` | Size of the event processing channel | 1000 |
| `KMS_CONNECTOR_SERVICE_NAME` | Name of the KMS connector instance | kms-connector |
| `KMS_CONNECTOR_DECRYPTION_TIMEOUT_SECS` | Timeout for decryption operations | 300 |
| `KMS_CONNECTOR_REENCRYPTION_TIMEOUT_SECS` | Timeout for re-encryption operations | 300 |
| `KMS_CONNECTOR_RETRY_INTERVAL_SECS` | Interval between retry attempts | 5 |

### Best Practices

1. Use a config file for development and testing environments where values change infrequently
2. Use environment variables for production deployments and when values need to be changed dynamically
3. Store sensitive information (like mnemonics) as environment variables rather than in config files

## Architecture: Adapter-Provider Pattern

The connector uses a two-layer architecture to separate L2 chain interaction from business logic:

```diagram
┌────────────────────┐     ┌────────────────┐
│  DecryptionAdapter │     │  HTTPZAdapter  │
│    <Domain Logic>  │     │ <Domain Logic> │
└────────┬───────────┘     └───────┬────────┘
         │                         │
         │      implements         │
         │          ▼              │
         │    ┌──────────┐         │
         └────┤ Provider ◄─────────┘
              │ Interface│
              └────┬─────┘
                   │      implements
                   ▼
         ┌─────────────────────┐
         │  ArbitrumProvider   │
         │ <L2 Communication>  │
         └─────────┬───────────┘
                   │
                   ▼
        [Arbitrum L2 Contracts]
        DecryptionManager, HTTPZ
```

### 1. Provider (Infrastructure Layer)

```rust
// Provider handles raw L2 interaction
trait Provider {
    async fn send_transaction(&self, to: Address, data: Vec<u8>) -> Result<()>;
    fn decryption_manager_address(&self) -> Address;
    fn httpz_address(&self) -> Address;
}
```

### 2. Adapters (Domain Layer)

```rust
// Adapters implement specific contract logic
struct DecryptionAdapter<P: Provider> {
    provider: P,
    event_tx: Sender<EventFilter>,
}

impl<P: Provider> DecryptionAdapter<P> {
    async fn handle_public_decryption(
        &self,
        id: U256,
        result: Vec<u8>
    ) -> Result<()> {
        // 1. Prepare contract data
        let response = PublicDecryptionResponse {
            id,
            result: result.into()
        };

        // 2. Encode for L2
        let mut data = Vec::new();
        response.encode_data_to(&mut data);

        // 3. Send via provider
        self.provider
            .send_transaction(
                self.provider.decryption_manager_address(),
                data
            )
            .await
    }
}

## Key Points

1. **Provider**
   - Single responsibility: L2 communication
   - Knows addresses but not contract logic
   - Generic transaction sending
   - No business rules

2. **Adapters**
   - Contract-specific logic
   - Event encoding/decoding
   - Business rule validation
   - Uses provider for L2 access

3. **Benefits**
   - Clean separation of L2 access and business logic
   - Easy to mock provider for testing
   - Type-safe contract interaction
   - Reusable L2 connection layer

## Current Status

See [CHANGELOG.md](./changelog.md) for current implementation status.

## Development

### Prerequisites

- Rust 1.85+
- Access to Arbitrum L2 node
- KMS Core instance

### Building

```bash
cargo build
```

### Testing

```bash
cargo test
