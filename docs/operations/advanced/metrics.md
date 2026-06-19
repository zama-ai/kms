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

KMS exposes metrics via Prometheus format on the configured metrics endpoint (default: `:<METRICS_PORT>/metrics` where `<METRICS_PORT>` defaults to `9646`). This document lists and describes metrics supported by KMS services to help operators monitor these services, configure alarms based on the metrics, and act on those in case of issues.

**Metric Naming**: All metrics use the configurable prefix (default: `kms`) followed by the metric type. The actual metric names will be `{prefix}_{metric_type}` (e.g., `kms_operations_total`, `kms_operation_errors_total`).

## kms-core

### Core Service Operations

#### Metric Name: `kms_operations_total` 
- **Type**: Counter
- **Description**: Total number of operations processed by the KMS core service.
- **Alarm**: If the counter is a flat line over a period of time for critical operations.

**Operation Types** (values of the `operation` label; values marked *(duration only)* appear on `kms_operation_duration_ms` — and some of them on `kms_operation_errors_total` when they fail — but not on this counter):

*Key Generation Operations*:
- `keygen_request` - Key generation requests
- `keygen_result` - Key generation result retrievals
- `keygen_abort` - Key generation aborts
- `keygen_preproc_request` - Key generation preprocessing requests
- `keygen_preproc_result` - Key generation preprocessing results
- `standard_keygen` - Standard (uncompressed) key generation
- `standard_compressed_keygen` - Compressed key generation
- `decompression_keygen` - Decompression key generation

*Decryption Operations*:
- `user_decrypt_request` - User decryption requests
- `user_decrypt_result` - User decryption result retrievals
- `user_decrypt_inner` - Individual user decryption operations *(duration only)*
- `public_decrypt_request` - Public decryption requests
- `public_decrypt_result` - Public decryption result retrievals
- `public_decrypt_inner` - Individual public decryption operations *(duration only)*

*CRS Operations*:
- `crs_gen_request` - CRS generation requests
- `crs_gen_result` - CRS generation result retrievals
- `crs_gen_abort` - CRS generation aborts

*System Operations*:
- `system_startup` - Metrics-system sanity check, incremented once by every process at startup
- `new_mpc_context` - MPC context creation
- `destroy_mpc_context` - MPC context destruction

*Custodian Operations*:
- `new_custodian_context` - Custodian context creation
- `destroy_custodian_context` - Custodian context destruction
- `custodian_backup_recovery` - Backup recovery operations
- `custodian_recovery_init` - Recovery initialization
- `restore_from_backup` - Backup restoration operations
- `key_material_availability` - Key material availability checks

*Epoch Operations*:
- `new_mpc_epoch` - MPC epoch creation
- `destroy_mpc_epoch` - MPC epoch destruction
- `get_mpc_epoch_result` - MPC epoch result retrievals

*Other Operations*:
- `fetch_pk` - Public key fetching operations

#### Metric Name: `kms_operation_errors_total`
- **Type**: Counter
- **Description**: Total number of operation errors encountered by the KMS core service.
- **Alarm**: If the counter increases over a period of time.

**Common Error Types** (the `error` label; gRPC status codes are mapped to these via `map_tonic_code_to_metric_err_tag`):
- `failed_precondition` - Precondition not met (tonic `FailedPrecondition`)
- `resource_exhausted` - Resource limit hit, e.g. rate limiting (tonic `ResourceExhausted`)
- `cancelled` - Operation cancelled (tonic `Cancelled`)
- `invalid_argument` - Invalid argument provided (tonic `InvalidArgument`)
- `aborted` - Operation aborted (tonic `Aborted`)
- `already_exists` - Resource already exists (tonic `AlreadyExists`)
- `not_found` - Resource not found (tonic `NotFound`)
- `internal_error` - Internal service error (tonic `Internal`)
- `unavailable` - Service temporarily unavailable (tonic `Unavailable`)
- `other` - Any other / unmapped gRPC status code
- `async_call_error` - Failure in an async worker thread, after the gRPC call already returned

#### Metric Name: `kms_backup_errors_total`
- **Type**: Counter
- **Description**: Total number of backup errors, kept separate from `kms_operation_errors_total` because backup failures must never be drowned out by ordinary operation errors. Labels: `operation` (the operation whose backup-vault update failed, e.g. `boot` — service boot / PRSS initialization — `decompression_keygen`, or a custodian operation) and `error` (always `backup_error`).
- **Alarm**: Any increase warrants investigation.

### Network Metrics

#### Metric Name: `kms_network_rx_bytes_total`
- **Type**: Counter
- **Description**: Total number of bytes received over the network by KMS.
- **Alarm**: If the counter stops increasing during expected traffic periods.

#### Metric Name: `kms_network_tx_bytes_total`
- **Type**: Counter
- **Description**: Total number of bytes sent over the network by KMS.
- **Alarm**: If the counter stops increasing during expected traffic periods.

### Performance Metrics

#### Metric Name: `kms_operation_duration_ms`
- **Type**: Histogram
- **Description**: Duration of KMS operations in milliseconds. Uses explicit buckets (1 ms → 5 min) because Prometheus defaults are tuned for seconds and would put most KMS measurements in `+Inf` (making p50/p95 meaningless).
- **Tags**: The operation name is carried under `operation_type` (e.g. an `OP_*` constant value such as `keygen_request`) — named `operation_type` rather than `operation` for backward compatibility with existing dashboards — plus low-cardinality tags like `party_id`, `tfhe_type`, etc. High-cardinality tags (e.g. `key_id`, `request_id`) are intentionally not attached to this series.
- **Alarm**: If P95 latency exceeds acceptable thresholds for critical operations.

#### Metric Name: `kms_payload_size_bytes`
- **Type**: Histogram
- **Description**: Size of KMS operation payloads in bytes. Uses explicit buckets (1 KiB → 64 GiB) to cover large FHE key/keyset payloads.
- **Tags / NOTE**: Currently only the versioned storage write paths emit this metric (`safe_write_element_versioned` for file-backed vault, S3 `store_data_at_key`, and the in-memory `RamStorage`); there the `operation` label carries the element's type name (via the `Named` trait, e.g. a key or keyset type) so sizes of different persisted objects are distinguishable, and sizes are recorded only after the write succeeds. Call `observe_size` from other paths (e.g. RPC handlers, labelling with the operation name) when useful.
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

#### Other Gauges
- **Type**: Gauge
- **Description**: Point-in-time gauges (default `kms` prefix): `kms_active_sessions` / `kms_inactive_sessions`, `kms_tasks`, `kms_rate_limiter_usage`, `kms_meta_storage_{user,pub}_decryptions` and `..._in_store`, `kms_file_descriptors`, `kms_socat_file_descriptors` / `kms_socat_tasks`, `kms_total_cpus`, `kms_total_memory`, `kms_process_cpu_usage`, `kms_process_memory_usage`, and `kms_version` (build info; value always 1).
- **Alarm**: e.g. alert if `kms_rate_limiter_usage` saturates or `kms_active_sessions` looks abnormal.

### Metric Tags

**Common Metric Tag Keys**: All metrics include contextual tags for filtering and aggregation:

- `operation` - The operation name; label on the counters (`*_operations_total`, `*_operation_errors_total`) and the payload-size histogram
- `operation_type` - The operation name on the **duration** histogram; named `operation_type` (not `operation`) for backward compatibility with existing dashboards
- `error` - The error type for error metrics (see error types above)
- `party_id` - ID of the party performing the operation
- `tfhe_type` - Type of TFHE operation being performed
- `public_decryption_mode` - Mode for public decryption operations
- `user_decryption_mode` - Mode for user decryption operations

High-cardinality values such as `key_id` or `request_id` are not accepted as labels by any metric family — the duration histogram only records the fixed label keys above and ignores unknown keys with a warning. See the developer metrics guide for the low-cardinality guard and best practices.

**Static / Deployment Labels (const-labels)**: In addition to the variable tags above, every metric can carry static labels configured once at startup via the `KMS_METRICS_LABELS` environment variable (comma-separated `key=value` list). These are attached as Prometheus const-labels to *all* metrics for the process. This is the supported way to distinguish deployments: the kind CI overlay sets `deployment_profile=kind-ci`, so CI series stay separable from production in a shared Prometheus/Grafana. (The threshold and centralized kind matrices run in separate namespaces, `kms-test-threshold`/`kms-test-centralized`, so they are already distinguishable by the `namespace` label — not by a `deployment_type` const-label.)

- Malformed entries, empty keys, empty values, names starting with `__`, or names that collide with built-in labels (`operation`, `error`, `version`, `le`, the duration label keys, etc.) are skipped with a warning at startup. A bad configuration cannot crash metric registration.
- In Helm: set `kmsCore.metricsLabels` (e.g. `deployment_profile=kind-ci`); the chart renders it into the `KMS_METRICS_LABELS` env on the kms-server container.
- The `ci_` metric name prefix (for separating CI series) is applied via ServiceMonitor `metricRelabelings` when enabled.
- See the [developer metrics guide](../../developer/metrics.md#distinguishing-deployments-kind-ci-vs-production) for the full mechanism, examples, and the `labels()` accessor for runtime inspection.

**Operation Type Values**:
- `total` - Total operations across all sub-types
- `load_crs_pk` - Loading CRS public key operations
- `proof_verification` - Proof verification operations
- `ct_proof` - Ciphertext proof operations

### Insecure Operations (Development Only)

#### Metric Name: `kms_operations_total` (Insecure Mode)
- **Type**: Counter
- **Description**: Operations available only in insecure/development mode.
- **Insecure Operation Types**:
  - `insecure_keygen_request` - Insecure key generation requests
  - `insecure_keygen_result` - Insecure key generation results
  - `insecure_standard_keygen` - Insecure standard key generation
  - `insecure_standard_compressed_keygen` - Insecure compressed key generation
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
curl http://localhost:<METRICS_PORT>/metrics

# Health endpoints
curl http://localhost:<METRICS_PORT>/health    # Returns "ok"
curl http://localhost:<METRICS_PORT>/ready     # Readiness check
curl http://localhost:<METRICS_PORT>/live      # Liveness check

# Health check tool integration
kms-health-check live --endpoint localhost:<GRPC_PORT>
```

## Prometheus Integration

### Metrics Collection

KMS exposes Prometheus-compatible metrics on the configured endpoint (default: `:<METRICS_PORT>/metrics` where `<METRICS_PORT>` defaults to `9646`).

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

- **Error Rate Monitoring**: Track `kms_operation_errors_total` vs `kms_operations_total` ratios
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

- **Operation Rates**: Monitor `kms_operations_total` metrics by operation type
- **Error Tracking**: Visualize `kms_operation_errors_total` with operation and error breakdowns  
- **Performance Metrics**: Display latency percentiles from `kms_operation_duration_ms` histograms
- **System Resources**: Track `kms_cpu_load` and `kms_memory_usage` gauges
- **Network Traffic**: Monitor `kms_network_rx_bytes_total` and `kms_network_tx_bytes_total` rates

### Dashboard References

- **Grafana Documentation**: [Creating Dashboards](https://grafana.com/docs/grafana/latest/dashboards/)
- **Prometheus Integration**: [Prometheus Data Source](https://grafana.com/docs/grafana/latest/datasources/prometheus/)
- **Best Practices**: [Dashboard Best Practices](https://grafana.com/docs/grafana/latest/best-practices/)



## Related Documentation

- [Health Check Tool](../../../tools/kms-health-check/README.md) - Comprehensive health monitoring
- [Monitoring & Metrics](../monitoring.md) - Standard health check procedures
- [Troubleshooting Guide](troubleshooting.md) - Detailed problem resolution
- [Configuration Guide](../configuration.md) - Metrics configuration options
