# KMS Health Check Tool

Health monitoring tool for Zama KMS deployments. Validates configurations, checks connectivity, and verifies key material for both centralized and threshold KMS instances.

## Features

- **Config Validation**: Parse and validate KMS configuration files using actual KMS server validation logic
- **Connectivity Check**: Test gRPC endpoint connectivity and latency
- **Key Material Check**: Display actual key IDs for FHE keys, CRS keys, and preprocessing material
- **Peer Health**: Check connectivity to all threshold peers with detailed key information
- **JSON Output**: Machine-readable output for CI/CD integration

## Usage

```bash
# Install
cargo build --release -p kms-health-check

# Validate config only
kms-health-check config --file /path/to/config.toml

# Check running instance
kms-health-check live --endpoint localhost:50100

# Full check (config + running instance)
kms-health-check full --config /path/to/config.toml --endpoint localhost:50100

# JSON output for monitoring
kms-health-check full --config /path/to/config.toml --endpoint localhost:50100 --format json

# Using custom timeout configuration
kms-health-check live --endpoint localhost:50100 --health-config health-check.toml

# Using environment variables for timeouts (note the double underscore separator)
HEALTH_CHECK__CONNECTION_TIMEOUT_SECS=10 HEALTH_CHECK__REQUEST_TIMEOUT_SECS=30 kms-health-check live --endpoint localhost:50100
```

## Configuration

The health check tool supports configurable timeouts through a dedicated configuration file and environment variables.

### Health Check Configuration File

Create a `health-check.toml` file to configure timeout settings:

```toml
# Health Check Tool Configuration
# Connection timeout in seconds (default: 5)
connection_timeout_secs = 5

# Request timeout in seconds (default: 10)  
request_timeout_secs = 10
```

Use the configuration file with the `--health-config` flag:

```bash
kms-health-check live --endpoint localhost:50100 --health-config health-check.toml
```

### Environment Variables

All configuration settings can be overridden with environment variables using the `HEALTH_CHECK_` prefix:

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `HEALTH_CHECK__CONNECTION_TIMEOUT_SECS` | Connection timeout in seconds | 5 |
| `HEALTH_CHECK__REQUEST_TIMEOUT_SECS` | Request timeout in seconds | 10 |

Examples:

```bash
# Set custom timeouts via environment variables (note the double underscore separator)
export HEALTH_CHECK__CONNECTION_TIMEOUT_SECS=10
export HEALTH_CHECK__REQUEST_TIMEOUT_SECS=30
kms-health-check live --endpoint localhost:50100

# Or inline
HEALTH_CHECK__CONNECTION_TIMEOUT_SECS=15 kms-health-check live --endpoint localhost:50100
```

### Configuration Precedence

Configuration values are applied in the following order (highest precedence first):

1. Environment variables (`HEALTH_CHECK__*`)
2. Configuration file (`--health-config`)
3. Default values

```

## Example Output

```
[INFO]:
  [OK] Valid threshold config
  [OK] Storage: file
  [OK] Listen address: dev-kms-core-3:50003
  [OK] Threshold: 1 (requires 3 of 4 nodes for MPC)
  [OK] 4 peers configured:
      - Peer 1 at dev-kms-core-1:50001
      - Peer 2 at dev-kms-core-2:50002
      - Peer 3 at dev-kms-core-3:50003
      - Peer 4 at dev-kms-core-4:50004

[KMS HEALTH CHECK REPORT]
==================================================

[OK] Overall Status: Healthy

[NODE INFO]:
  Type: threshold
  Party ID: 3
  Threshold: 1 required
  Nodes Reachable: 4

[CONFIG]:
  [OK] Valid threshold config
  [OK] Storage: file

[CONNECTIVITY]:
  [OK] Reachable (latency: 1ms)

[KEY MATERIAL]:
  [OK] FHE Keys: 1
       - a178eec2319d082f82f844ee2d07f2357ab643511786f116ecf7afba74f28ffe
  [OK] CRS Keys: 0
  [OK] Preprocessing: 1
       - b289ffd3420e193g93g955ff3e18g3468bc754622897g227fdf8bgcb85g39ggg
  [OK] Storage: Threshold KMS - file storage with root_path '/app/kms/core/service/keys/PRIV-p3'

[OPERATOR KEY]:
  [FAIL] Not available: status: Unimplemented, message: "Backup vault does not support operator public key retrieval", details: [], metadata: MetadataMap { headers: {"content-type": "application/grpc", "date": "Tue, 02 Sep 2025 12:39:48 GMT"} }

[PEER STATUS]:
  3 of 3 peers reachable
  [OK] Party 1 @ http://dev-kms-core-1:50100 (1ms)
       FHE Keys: 1
         - a178eec2319d082f82f844ee2d07f2357ab643511786f116ecf7afba74f28ffe
       CRS Keys: 0
       Preprocessing: 1
         - b289ffd3420e193g93g955ff3e18g3468bc754622897g227fdf8bgcb85g39ggg
       Storage: Threshold KMS - file storage with root_path '/app/kms/core/service/keys/PRIV-p1'
  [OK] Party 2 @ http://dev-kms-core-2:50200 (41ms)
       FHE Keys: 1
         - a178eec2319d082f82f844ee2d07f2357ab643511786f116ecf7afba74f28ffe
       CRS Keys: 0
       Preprocessing: 1
         - b289ffd3420e193g93g955ff3e18g3468bc754622897g227fdf8bgcb85g39ggg
       Storage: Threshold KMS - file storage with root_path '/app/kms/core/service/keys/PRIV-p2'
  [OK] Party 4 @ http://dev-kms-core-4:50400 (10ms)
       FHE Keys: 1
         - a178eec2319d082f82f844ee2d07f2357ab643511786f116ecf7afba74f28ffe
       CRS Keys: 0
       Preprocessing: 1
         - b289ffd3420e193g93g955ff3e18g3468bc754622897g227fdf8bgcb85g39ggg
       Storage: Threshold KMS - file storage with root_path '/app/kms/core/service/keys/PRIV-p4'

[INFO]:
  All health checks passed

==================================================
```

## Health Status Levels

- **Healthy**: All checks passed, keys present, all peers reachable
- **Degraded**: Service operational but with issues (missing keys, operator key unavailable, or protocol/configuration warnings)
- **Unhealthy**: Critical issues (cannot connect, invalid config, insufficient nodes for threshold)

## Output Format

Default is text with colors. Use `--format json` for machine-readable output.

## gRPC Health Endpoints

The KMS exposes two complementary gRPC endpoints for health monitoring and key material inspection:

```mermaid
graph TD
    A[Health Check Tool] --> B[GetHealthStatus on Self]
    
    B --> C[Self KMS Core]
    C --> D[Query own storage]
    C --> E[GetKeyMaterialAvailability on each Peer]
    
    D --> F[Own key counts]
    E --> G[Peer key IDs + connectivity]
    
    F --> H[HealthStatusResponse]
    G --> H
    
    H --> I[Display: Self + Peer key details]
    
    style A fill:#e1f5fe
    style C fill:#f3e5f5
    style I fill:#e8f5e8
```

### Endpoint
- **Service**: `kms.v1.CoreService`
- **Method**: `GetHealthStatus(Empty) -> HealthStatusResponse`
- **Additional**: `GetKeyMaterialAvailability(Empty) -> KeyMaterialAvailabilityResponse`
- **Ports**: 50100 (default KMS port)

### Response Structure

```protobuf
// Health status levels
enum HealthStatus {
  HEALTH_STATUS_UNSPECIFIED = 0;
  HEALTH_STATUS_HEALTHY = 1;
  HEALTH_STATUS_DEGRADED = 2;
  HEALTH_STATUS_UNHEALTHY = 3;
}

// Node type for KMS deployment
enum NodeType {
  NODE_TYPE_UNSPECIFIED = 0;
  NODE_TYPE_CENTRALIZED = 1;
  NODE_TYPE_THRESHOLD = 2;
}

message HealthStatusResponse {
  // Overall health status
  HealthStatus status = 1;
  
  // Peer health information (threshold mode only)
  repeated PeerHealth peers = 2;
  
  // Self key material IDs
  repeated string my_fhe_key_ids = 3;
  repeated string my_crs_ids = 4;
  repeated string my_preprocessing_key_ids = 5;
  string my_storage_info = 6;
  
  // Runtime configuration
  NodeType node_type = 7;
  uint32 my_party_id = 8;         // Only for threshold mode
  uint32 threshold_required = 9;   // Minimum nodes needed
  uint32 nodes_reachable = 10;    // Currently reachable nodes
}

message PeerHealth {
  uint32 peer_id = 1;
  string endpoint = 2;
  bool reachable = 3;
  uint32 latency_ms = 4;
  uint32 fhe_keys = 5;
  uint32 crs_keys = 6;
  uint32 preprocessing_keys = 7;
  string storage_info = 8;
  string error = 9;              // Error if unreachable
}
```

### Key Material Availability Response

The health check tool now uses the `GetKeyMaterialAvailability` endpoint to display actual key IDs:

```protobuf
message KeyMaterialAvailabilityResponse {
  repeated string fhe_key_ids = 1;
  repeated string crs_ids = 2;
  repeated string preprocessing_ids = 3;
  string storage_info = 4;
}
```

### Usage Example

```bash
# Using grpcurl
grpcurl -plaintext localhost:50100 kms.v1.CoreService/GetHealthStatus
grpcurl -plaintext localhost:50100 kms.v1.CoreService/GetKeyMaterialAvailability

# Using the health check tool (which calls both endpoints internally)
kms-health-check live --endpoint localhost:50100
```

## Integration

### Kubernetes
```yaml
readinessProbe:
  exec:
    command: ["/usr/local/bin/kms-health-check", "live", "--endpoint", "localhost:50100"]
  periodSeconds: 30
```

### CI/CD
```bash
kms-health-check config --file config.toml || exit 1
```

## Exit Codes

- `0` - Healthy status
- `1` - Degraded or Unhealthy status
- `2` - Tool execution error

## Known Limitations

- **Operator Key**: In threshold mode, only available if backup vault uses `SecretSharing` keychain
- **Docker Resolution**: Automatically translates Docker service names to localhost when needed
