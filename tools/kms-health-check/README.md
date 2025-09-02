# KMS Health Check Tool

Health monitoring tool for Zama KMS deployments. Validates configurations, checks connectivity, and verifies key material for both centralized and threshold KMS instances.

## Features

- **Config Validation**: Parse and validate KMS configuration files
- **Connectivity Check**: Test gRPC endpoint connectivity and latency
- **Key Material Check**: Verify FHE keys, CRS keys, and preprocessing material
- **Peer Health**: Check connectivity to all threshold peers (threshold mode only)
- **JSON Output**: Machine-readable output for CI/CD integration

## Usage

```bash
# Install
cargo build --release -p kms-health-check

# Validate config only
kms-health-check config --file /path/to/config.toml

# Check running instance
kms-health-check live --endpoint localhost:9091

# Full check (config + running instance)
kms-health-check full --config /path/to/config.toml --endpoint localhost:9091

# JSON output for monitoring
kms-health-check full --config /path/to/config.toml --endpoint localhost:9091 --format json
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
  [OK] CRS Keys: 0
  [OK] Preprocessing: 1
  [OK] Storage: Threshold KMS - file storage with root_path '/app/kms/core/service/keys/PRIV-p3'

[OPERATOR KEY]:
  [FAIL] Not available: status: Unimplemented, message: "Backup vault does not support operator public key retrieval", details: [], metadata: MetadataMap { headers: {"content-type": "application/grpc", "date": "Tue, 02 Sep 2025 12:39:48 GMT"} }

[PEER STATUS]:
  3 of 3 peers reachable
  [OK] Party 1 @ http://dev-kms-core-1:50100 (latency: 0ms, FHE: 1, CRS: 0, Preprocessing: 1)
       Storage: Threshold KMS - file storage with root_path '/app/kms/core/service/keys/PRIV-p1'
  [OK] Party 2 @ http://dev-kms-core-2:50200 (latency: 41ms, FHE: 1, CRS: 0, Preprocessing: 1)
       Storage: Threshold KMS - file storage with root_path '/app/kms/core/service/keys/PRIV-p2'
  [OK] Party 4 @ http://dev-kms-core-4:50400 (latency: 0ms, FHE: 1, CRS: 0, Preprocessing: 1)
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
