# KMS Connector

The KMS Connector is a Rust-based service that bridges the KMS Core with the Gateway L2 (Arbitrum) blockchain. It handles decryption requests, key management operations, and secure communication between the KMS Core service and the blockchain smart contracts.

## Overview

The KMS Connector follows an event-driven architecture with a Multiple Producer, Single Consumer (MPSC) pattern for orchestrating operations. It subscribes to events from the Gateway L2 blockchain, processes them, and communicates with the KMS Core service to fulfill decryption and key management requests.

## Key Features

- **Event-Driven Architecture**: Subscribes to and processes blockchain events in real-time
- **High-Frequency Processing**: Optimized for processing decryption requests at 500ms intervals
- **Secure Wallet Management**: Supports both mnemonic-based and signing key file-based wallet configurations
- **Efficient S3 Integration**: Retrieves ciphertexts from S3 storage with optimized performance
- **Automatic Reconnection**: Gracefully handles network disruptions with intelligent retry mechanisms
- **Comprehensive Error Handling**: Implements robust error handling throughout the system

## Components

### Core Components

#### KmsCoreConnector

The central component that orchestrates all interactions with the L2 blockchain. It initializes other components, manages event processing, and handles the lifecycle of the connector.

```rust
pub struct KmsCoreConnector<P: Provider + Clone> {
    events: EventsAdapter,
    event_processor: EventProcessor<P>,
    kms_client: Arc<KmsServiceImpl>,
    shutdown: Option<broadcast::Receiver<()>>,
    config: Config,
}
```

Key methods:

- `new()`: Creates a new connector instance
- `start()`: Initializes and starts the connector
- `stop()`: Gracefully shuts down the connector

#### Config

Handles configuration from environment variables and TOML files. Manages all configurable aspects of the connector including:

- Blockchain connection details
- KMS Core endpoint
- Wallet configuration
- S3 storage settings
- Timeout and retry parameters

#### KmsWallet

Manages wallet operations for signing decryption responses. Supports:

- Creation from mnemonic phrases
- Creation from signing key files
- Message and hash signing

#### S3CiphertextClient

Handles efficient retrieval of ciphertexts from AWS S3 storage:

- Supports multiple S3 URL formats
- Implements optimized timeout and retry settings
- Caches S3 bucket URLs for improved performance
- Extracts region and bucket information from URLs

### Adapters

#### EventsAdapter

Subscribes to and processes blockchain events:

- Establishes WebSocket connections to the blockchain
- Subscribes to events from DecryptionManager and fhevm contracts
- Handles connection failures with automatic reconnection
- Forwards events to the event processor

#### DecryptionAdapter

Handles sending decryption responses to the blockchain:

- Sends public decryption responses
- Sends user-specific decryption responses
- Manages transaction creation and submission

#### KmsServiceImpl

Interfaces with the KMS Core service via gRPC:

- Establishes and maintains connections to KMS Core
- Sends public/user decryption requests
- Polls for operation results with configurable timeouts
- Handles reconnection on service disruptions

### Event Processing

#### EventProcessor

Processes events from the L2 blockchain:

- Handles public decryption requests
- Handles user-specific decryption requests
- Retrieves ciphertext materials from S3
- Coordinates with the DecryptionHandler

#### DecryptionHandler

Processes decryption requests and responses:

- Extracts request parameters
- Communicates with KMS Core for decryption operations
- Prepares and signs responses
- Sends responses back to the blockchain

## S3 URL Processing

The KMS Connector implements a robust and non-failable S3 URL processing system optimized for high-frequency operations (500ms intervals). It supports multiple URL formats and provides graceful fallbacks when URL parsing fails.

### Supported URL Formats

- **Virtual-hosted style**: `https://bucket-name.s3.region.amazonaws.com`
- **Path-style**: `https://s3.region.amazonaws.com/bucket-name`
- **Custom endpoints with region in path**: `https://custom-endpoint.com/s3/region/bucket`
- **Simple URLs**: `http://localhost:9000/bucket-name`
- **URLs with trailing slashes**: `https://endpoint:9000/bucket/`

### Key Features of S3 URL Processing

- **Complete URL Parsing**: Extracts region, endpoint URL, and bucket name directly from the URL
- **Non-failable Design**: Returns `Option<(String, String, String)>` instead of `Result` to handle URL parsing failures gracefully
- **Improved Logging**: Uses warning logs instead of error logs for non-critical issues
- **Two-level Fallback Strategy**:
  - First attempts to retrieve S3 URLs from all specified coprocessors
  - Only falls back to configured S3 bucket when all coprocessor retrievals fail
- **Robust URL Handling**: Filters empty path segments and handles URLs with trailing slashes
- **Continuous Operation**: Maintains the 500ms processing cycle even when URL parsing issues occur

### S3 Client Configuration

The S3 client is optimized for high-frequency operations with the following settings:

- Operation timeout: 1s
- Operation attempt timeout: 750ms
- Retry attempts: Limited to 2 with minimal backoff (50ms)
- Direct endpoint URL configuration

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

   # Start the connector without a config file
   kms-connector start
   ```

2. **Config File Only**

   ```bash
   # Use a TOML config file
   kms-connector start --config ./config/environments/config-base.toml
   ```

3. **Combined Configuration**

   ```bash
   # Set specific overrides
   export KMS_CONNECTOR_GWL2_URL="ws://localhost:8547"
   export KMS_CONNECTOR_CHAIN_ID="31337"

   # Use config file for other values
   kms-connector start --config ./config/environments/config-base.toml
   ```

### Configuration Precedence

The configuration values are loaded in the following order, with later sources overriding earlier ones:

1. Default values (lowest priority)
2. TOML config file (if provided)
3. Environment variables (highest priority)

### Environment Variables

All environment variables are prefixed with `KMS_CONNECTOR_`. Here's the complete list:

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `KMS_CONNECTOR_GWL2_URL` | Gateway L2 WebSocket URL | ws://localhost:8545 |
| `KMS_CONNECTOR_KMS_CORE_ENDPOINT` | KMS Core service endpoint | http://[::1]:50052 |
| `KMS_CONNECTOR_MNEMONIC` | Wallet mnemonic phrase | (required if signing_key_path not provided) |
| `KMS_CONNECTOR_SIGNING_KEY_PATH` | Path to a serialized signing key file | (required if mnemonic not provided) |
| `KMS_CONNECTOR_CHAIN_ID` | Blockchain network chain ID | 31337 |
| `KMS_CONNECTOR_DECRYPTION_MANAGER_ADDRESS` | Address of the Decryption Manager contract | 0x5fbdb2315678afecb367f032d93f642f64180aa3 |
| `KMS_CONNECTOR_HTTPZ_ADDRESS` | Address of the fhevm contract | 0x0000000000000000000000000000000000000001 |
| `KMS_CONNECTOR_CHANNEL_SIZE` | Size of the event processing channel | 1000 |
| `KMS_CONNECTOR_SERVICE_NAME` | Name of the KMS connector instance | kms-connector |
| `KMS_CONNECTOR_ACCOUNT_INDEX` | Account index for the wallet | 0 |
| `KMS_CONNECTOR_PUBLIC_DECRYPTION_TIMEOUT_SECS` | Timeout for decryption operations | 300 |
| `KMS_CONNECTOR_USER_DECRYPTION_TIMEOUT_SECS` | Timeout for user decryption operations | 300 |
| `KMS_CONNECTOR_RETRY_INTERVAL_SECS` | Interval between retry attempts | 5 |
| `KMS_CONNECTOR_DECRYPTION_MANAGER_DOMAIN_NAME` | EIP-712 domain name for DecryptionManager contract | DecryptionManager |
| `KMS_CONNECTOR_DECRYPTION_MANAGER_DOMAIN_VERSION` | EIP-712 domain version for DecryptionManager contract | 1 |
| `KMS_CONNECTOR_HTTPZ_DOMAIN_NAME` | EIP-712 domain name for fhevm contract | fhevm |
| `KMS_CONNECTOR_HTTPZ_DOMAIN_VERSION` | EIP-712 domain version for fhevm contract | 1 |
| `KMS_CONNECTOR_PRIVATE_KEY` | Private key as a hex string | (optional) |
| `KMS_CONNECTOR_VERIFY_COPROCESSORS` | Whether to verify coprocessors against fhevm contract | false |
| `KMS_CONNECTOR_S3_CONFIG__REGION` | AWS S3 region for ciphertext storage | (optional) |
| `KMS_CONNECTOR_S3_CONFIG__BUCKET` | AWS S3 bucket name for ciphertext storage | (optional) |
| `KMS_CONNECTOR_S3_CONFIG__ENDPOINT` | AWS S3 endpoint URL for ciphertext storage | (optional) |

> **Note on Nested Configuration**: For nested configuration structures like `s3_config`, use double underscores (`__`) in environment variables to represent the nesting. For example, `s3_config.region` in TOML becomes `KMS_CONNECTOR_S3_CONFIG__REGION` as an environment variable.

## Deployment Scenarios

The KMS Connector can be deployed in various scenarios, each with its own configuration requirements.

### Local Development

For local development and testing, you can run the KMS Connector directly from the source code:

```bash
# Clone the repository
git clone https://github.com/zama-ai/kms-core.git
cd kms-core/kms-connector

# Build the connector
cargo build --release

# Run with a local configuration
./target/release/kms-connector start --config ./config/environments/local.toml
```

### Docker Deployment

For containerized deployment, you can use the provided Dockerfile:

```bash
# Build the Docker image
docker build -t kms-connector .

# Run the container with environment variables
docker run -d \
  --name kms-connector \
  -e KMS_CONNECTOR_GWL2_URL="ws://gateway-l2:8547" \
  -e KMS_CONNECTOR_KMS_CORE_ENDPOINT="http://kms-core:50052" \
  -e KMS_CONNECTOR_MNEMONIC="your mnemonic here" \
  -e KMS_CONNECTOR_CHAIN_ID="31337" \
  -e KMS_CONNECTOR_DECRYPTION_MANAGER_ADDRESS="0x..." \
  -e KMS_CONNECTOR_HTTPZ_ADDRESS="0x..." \
  kms-connector
```

### Kubernetes Deployment

For production deployment in Kubernetes, you can use a ConfigMap and Secret for configuration:

```yaml
# kms-connector-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kms-connector-config
data:
  KMS_CONNECTOR_GWL2_URL: "ws://gateway-l2-service:8547"
  KMS_CONNECTOR_KMS_CORE_ENDPOINT: "http://kms-core-service:50052"
  KMS_CONNECTOR_CHAIN_ID: "31337"
  KMS_CONNECTOR_DECRYPTION_MANAGER_ADDRESS: "0x..."
  KMS_CONNECTOR_HTTPZ_ADDRESS: "0x..."
  KMS_CONNECTOR_S3_CONFIG__REGION: "us-east-1"
  KMS_CONNECTOR_S3_CONFIG__BUCKET: "my-ciphertext-bucket"
```

```yaml
# kms-connector-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: kms-connector-secret
type: Opaque
data:
  KMS_CONNECTOR_MNEMONIC: "base64-encoded-mnemonic"
```

```yaml
# kms-connector-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kms-connector
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kms-connector
  template:
    metadata:
      labels:
        app: kms-connector
    spec:
      containers:
      - name: kms-connector
        image: kms-connector:latest
        envFrom:
        - configMapRef:
            name: kms-connector-config
        - secretRef:
            name: kms-connector-secret
```

## Advanced Troubleshooting

### S3 Ciphertext Retrieval Issues

#### URL Parsing Failures

If you see warnings like "Failed to parse S3 bucket URL" in the logs:

1. Check the S3 bucket URL format in the fhevm contract
2. Ensure the URL follows one of the supported formats
3. Verify that the URL is accessible from the KMS Connector's network

#### Region Extraction Failures

If you see warnings about region extraction:

1. Ensure the S3 bucket URL contains a valid region
2. Provide a fallback region using the `KMS_CONNECTOR_S3_CONFIG__REGION` environment variable

#### Ciphertext Not Found

If the connector fails to retrieve ciphertexts:

1. Verify that the ciphertext digest is correct
2. Check S3 bucket permissions
3. Ensure the ciphertext is stored with the correct key (SHA-256 digest)
4. Try accessing the ciphertext directly using the AWS CLI:

   ```bash
   aws s3 cp s3://bucket-name/digest-hex local-file.bin --region us-east-1
   ```

### Connection Issues

#### Gateway L2 Connection Failures

If the connector fails to connect to the Gateway L2 blockchain:

1. Verify that the WebSocket URL is correct and accessible
2. Check network connectivity between the connector and the Gateway L2 node
3. Ensure the Gateway L2 node is running and accepting WebSocket connections

#### KMS Core Connection Failures

If the connector fails to connect to the KMS Core service:

1. Verify that the gRPC endpoint is correct and accessible
2. Check network connectivity between the connector and the KMS Core service
3. Ensure the KMS Core service is running and accepting gRPC connections

### Event Processing Issues

If the connector fails to process events:

1. Check the event subscription logs for errors
2. Verify that the contract addresses are correct
3. Ensure the connector's wallet has sufficient funds for sending transactions
4. Check for any rate limiting or network congestion issues

### Wallet Issues

If the connector fails to sign transactions:

1. Verify that either the mnemonic or signing key file is correctly configured
2. Ensure the wallet has sufficient funds for gas
3. Check that the chain ID is correct for the target network

## Performance Tuning

For high-frequency operation, consider the following performance optimizations:

1. **Increase Channel Size**: Set `KMS_CONNECTOR_CHANNEL_SIZE` to a higher value (e.g., 5000) for handling more concurrent events
2. **Optimize Timeouts**: Adjust `KMS_CONNECTOR_PUBLIC_DECRYPTION_TIMEOUT_SECS` and `KMS_CONNECTOR_USER_DECRYPTION_TIMEOUT_SECS` based on your network latency
3. **Use Direct S3 Endpoints**: Configure `KMS_CONNECTOR_S3_CONFIG__ENDPOINT` to point to the closest S3 endpoint
4. **Deploy Close to Services**: Minimize network latency by deploying the connector close to both the KMS Core service and the Gateway L2 node

## API Reference

### KMS Core gRPC API

The connector communicates with the KMS Core service using the following gRPC methods:

- `public_decrypt`: Sends a public decryption request
- `get_public_decryption_result`: Retrieves the public result of a decryption operation
- `user_decrypt`: Sends a user decryption request
- `get_user_decryption_result`: Retrieves the result of a user decryption operation

### Gateway L2 Contract Events

The connector subscribes to the following events:

- `PublicDecryptionRequest`: Request for public decryption
- `UserDecryptionRequest`: Request for user-specific decryption
- `PreprocessKeygenRequest`: Request for key preprocessing
- `KeygenRequest`: Request for key generation
- `CrsgenRequest`: Request for CRS generation
- `KskgenRequest`: Request for KSK generation

## Development

### Building from Source

```bash
cargo build --release
```

### Running Tests

```bash
cargo test
```

### Contributing

Contributions to the KMS Connector are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

[License information]
