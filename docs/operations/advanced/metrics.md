# KMS Metrics, Monitoring & Alerting

**Comprehensive monitoring setup with health checks, Prometheus metrics, Grafana dashboards, and alerting rules for production KMS deployments.**

> **Basic Monitoring**: See [Monitoring & Metrics](../monitoring.md) for standard health check commands and essential monitoring setup.

## Advanced Health Check Configuration

### Custom Health Check Timeouts

**Timeout Configuration**:
- **Connection timeout**: Default 5 seconds, configurable via `health-check.toml` or environment variables
- **Request timeout**: Default 10 seconds, configurable via `health-check.toml` or environment variables
- **Environment variables**: Use `HEALTH_CHECK__CONNECTION_TIMEOUT_SECS` and `HEALTH_CHECK__REQUEST_TIMEOUT_SECS`

**Configuration Reference**: See [kms-health-check README](../../../tools/kms-health-check/README.md) for complete timeout configuration options.

### 13-Party Network Health Status

| Status | Description (13-party network, t=4) | Action Required |
|--------|-------------------------------------|-----------------|
| **Optimal** | All 13 parties reachable | Normal operations |
| **Healthy** | 9+ parties reachable | Monitor offline parties |
| **Degraded** | 5-8 parties reachable | Check connectivity issues |
| **Unhealthy** | < 5 parties reachable | Cannot perform threshold operations |

## KMS Core Metrics

KMS exposes metrics via Prometheus format on the configured metrics endpoint (default: `:9646/metrics`). This document lists and describes metrics supported by KMS services to help operators monitor these services, configure alarms based on the metrics, and act on those in case of issues.

**Metric Naming**: All metrics use the configurable prefix (default: `kms`) followed by the metric type. The actual metric names will be `{prefix}_{metric_type}` (e.g., `kms_operations`, `kms_operation_errors`).

## kms-core

### Core Service Operations

#### Metric Name: `kms_operations` 
- **Type**: Counter
- **Description**: Total number of operations processed by the KMS core service.
- **Alarm**: If the counter is a flat line over a period of time for critical operations.

**Operation Types**:

*Key Generation Operations*:
- `keygen_request` - Key generation requests
- `keygen_result` - Key generation result retrievals
- `keygen_preproc_request` - Key generation preprocessing requests
- `keygen_preproc_result` - Key generation preprocessing results
- `keygen` - Direct key generation operations
- `decompression_keygen` - Decompression key generation

*Decryption Operations*:
- `user_decrypt_request` - User decryption requests
- `user_decrypt_result` - User decryption result retrievals
- `user_decrypt_inner` - Individual user decryption operations
- `public_decrypt_request` - Public decryption requests
- `public_decrypt_result` - Public decryption result retrievals
- `public_decrypt_inner` - Individual public decryption operations

*CRS Operations*:
- `crs_gen_request` - CRS generation requests
- `crs_gen_result` - CRS generation result retrievals

*System Operations*:
- `init` - PRSS initialization operations
- `new_kms_context` - KMS context creation
- `destroy_kms_context` - KMS context destruction

*Custodian Operations*:
- `new_custodian_context` - Custodian context creation
- `destroy_custodian_context` - Custodian context destruction
- `custodian_backup_recovery` - Backup recovery operations
- `custodian_recovery_init` - Recovery initialization
- `restore_from_backup` - Backup restoration operations

*Resharing Operations*:
- `initiate_resharing` - Resharing initiation operations
- `get_initiate_resharing_result` - Resharing result retrievals

*Other Operations*:
- `fetch_pk` - Public key fetching operations

#### Metric Name: `kms_operation_errors`
- **Type**: Counter
- **Description**: Total number of operation errors encountered by the KMS core service.
- **Alarm**: If the counter increases over a period of time.

**Common Error Types**:
- `rate_limit_exceeded` - Rate limiting triggered
- `key_already_exists` - Key already exists error
- `key_not_found` - Requested key not available
- `public_decryption_failed` - Public decryption operation failed
- `user_decryption_failed` - User decryption operation failed
- `preproc_failed` - Preprocessing operation failed
- `preproc_not_found` - Preprocessing material not found
- `keygen_failed` - Key generation operation failed
- `verification_failed` - Verification operation failed
- `crs_gen_failed` - CRS generation failed
- `meta_storage_error` - Metadata storage error
- `invalid_request` - Malformed or invalid request
- `cancelled` - Operation cancelled
- `invalid_argument` - Invalid argument provided
- `aborted` - Operation aborted
- `already_exists` - Resource already exists
- `not_found` - Resource not found
- `internal_error` - Internal service error
- `unavailable` - Service temporarily unavailable
- `other` - Other unspecified errors

### Network Metrics

#### Metric Name: `kms_network_rx_bytes`
- **Type**: Counter
- **Description**: Total number of bytes received over the network by KMS.
- **Alarm**: If the counter stops increasing during expected traffic periods.

#### Metric Name: `kms_network_tx_bytes`
- **Type**: Counter
- **Description**: Total number of bytes sent over the network by KMS.
- **Alarm**: If the counter stops increasing during expected traffic periods.

### Performance Metrics

#### Metric Name: `kms_operation_duration_ms`
- **Type**: Histogram
- **Description**: Duration of KMS operations in milliseconds.
- **Alarm**: If P95 latency exceeds acceptable thresholds for critical operations.

#### Metric Name: `kms_payload_size_bytes`
- **Type**: Histogram
- **Description**: Size of KMS operation payloads in bytes.
- **Alarm**: If payload sizes exceed expected ranges, indicating potential issues.

### System Resource Metrics

#### Metric Name: `kms_cpu_load`
- **Type**: Gauge
- **Description**: CPU load for KMS (averaged over all CPUs) as a percentage.
- **Alarm**: If CPU load exceeds 80% for extended periods.

#### Metric Name: `kms_memory_usage`
- **Type**: Gauge
- **Description**: Memory used by KMS in bytes.
- **Alarm**: If memory usage exceeds 85% of available memory.

#### Metric Name: `kms_gauge`
- **Type**: Gauge
- **Description**: General-purpose gauge for tracking active operations and other values.
- **Alarm**: If active operations exceed capacity thresholds.

### Insecure Operations (Development Only)

#### Metric Name: `kms_operations` (Insecure Mode)
- **Type**: Counter
- **Description**: Operations available only in insecure/development mode.
- **Insecure Operation Types**:
  - `insecure_keygen_request` - Insecure key generation requests
  - `insecure_keygen_result` - Insecure key generation results
  - `insecure_keygen` - Direct insecure key generation
  - `insecure_decompression_keygen` - Insecure decompression key generation
  - `insecure_crs_gen_request` - Insecure CRS generation requests
  - `insecure_crs_gen_result` - Insecure CRS generation results
- **Alarm**: These should NEVER appear in production environments.

## Health Check Integration

### Health Status Metrics

The KMS health check system provides additional operational metrics through the health endpoints:

#### Health Check Operations
- **Endpoint**: `GetHealthStatus` - Provides comprehensive health information
- **Endpoint**: `GetKeyMaterialAvailability` - Reports available key material

#### Health Status Levels
- **Optimal**: All nodes online and reachable (threshold mode)
- **Healthy**: Sufficient 2/3 majority but not all nodes online
- **Degraded**: Above minimum threshold but below 2/3 majority  
- **Unhealthy**: Insufficient nodes for operations

### Key Material Monitoring

#### Available Key Types
- **FHE Keys**: Fully homomorphic encryption keys
- **CRS Keys**: Common reference string keys
- **Preprocessing Material**: PRSS preprocessing data (threshold mode only)

## Monitoring Integration

### Health Endpoints

```bash
# Metrics endpoint
curl http://localhost:9646/metrics

# Health endpoints
curl http://localhost:9646/health    # Returns "ok"
curl http://localhost:9646/ready     # Readiness check
curl http://localhost:9646/live      # Liveness check

# Health check tool integration
kms-health-check live --endpoint localhost:<GRPC_PORT>
```

## Prometheus Integration

### Metrics Collection

KMS exposes Prometheus-compatible metrics on the configured endpoint (default: `:9646/metrics`).

**Key Configuration Points**:
- **Metrics Endpoint**: `/metrics` on the configured metrics port
- **Scrape Interval**: Recommended 30 seconds for KMS operations
- **Service Discovery**: Use Kubernetes pod discovery for dynamic environments
- **Target Labels**: Filter by `app=kms-core` label for KMS pods

### Configuration References

- **Prometheus Documentation**: [Configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
- **Kubernetes Discovery**: [Kubernetes SD Config](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#kubernetes_sd_config)
- **Helm Chart Integration**: See KMS Helm chart ServiceMonitor configuration

## Alerting Integration

### Alert Configuration

KMS metrics support comprehensive alerting for operational monitoring. Key alert categories include:

- **Error Rate Monitoring**: Track `kms_operation_errors` vs `kms_operations` ratios
- **Performance Alerts**: Monitor latency percentiles from `kms_operation_duration_ms`
- **Resource Alerts**: CPU and memory usage from `kms_cpu_load` and `kms_memory_usage`
- **Network Health**: Peer connectivity and network traffic patterns
- **Threshold Mode**: Multi-party network health and PRSS initialization status

### Alerting References

- **Prometheus Alerting**: [Alerting Rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
- **Alertmanager**: [Configuration](https://prometheus.io/docs/alerting/latest/configuration/)
- **Best Practices**: [Alerting Best Practices](https://prometheus.io/docs/practices/alerting/)

## Grafana Dashboard Integration

### Dashboard Configuration

KMS metrics can be visualized using Grafana dashboards. Key dashboard components should include:

- **Operation Rates**: Monitor `kms_operations` metrics by operation type
- **Error Tracking**: Visualize `kms_operation_errors` with operation and error breakdowns  
- **Performance Metrics**: Display latency percentiles from `kms_operation_duration_ms` histograms
- **System Resources**: Track `kms_cpu_load` and `kms_memory_usage` gauges
- **Network Traffic**: Monitor `kms_network_rx_bytes` and `kms_network_tx_bytes` rates

### Dashboard References

- **Grafana Documentation**: [Creating Dashboards](https://grafana.com/docs/grafana/latest/dashboards/)
- **Prometheus Integration**: [Prometheus Data Source](https://grafana.com/docs/grafana/latest/datasources/prometheus/)
- **Best Practices**: [Dashboard Best Practices](https://grafana.com/docs/grafana/latest/best-practices/)



## Related Documentation

- [Health Check Tool](../../../tools/kms-health-check/README.md) - Comprehensive health monitoring
- [Monitoring & Metrics](../monitoring.md) - Standard health check procedures
- [Troubleshooting Guide](troubleshooting.md) - Detailed problem resolution
- [Configuration Guide](../configuration.md) - Metrics configuration options
