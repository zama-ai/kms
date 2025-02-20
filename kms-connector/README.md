# KMS Connector

KMS Connector is a Rust-based service that connects the KMS Core with Gateway L2 (Arbitrum) smart contracts, handling decryption requests and key management operations.

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

- Rust 1.84+
- Access to Arbitrum L2 node
- KMS Core instance

### Building

```bash
cargo build
```

### Testing

```bash
cargo test
