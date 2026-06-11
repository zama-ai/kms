# KMS Core Metrics Guide

The KMS Core metrics system provides comprehensive observability through Prometheus metrics served on the `/metrics` endpoint. This guide explains the metric types, their usage patterns, and best practices.

## Metric Types and Naming

All metrics follow a consistent naming pattern with a configurable prefix (default: "kms"). The full metric name is constructed by combining the prefix with the metric-specific suffix. Metric names are defined as constants in the `metrics_names` module to ensure consistency and prevent typos.

### Operation Names
Standard operation names are defined as constants:
```rust
pub const OP_BOOT: &str = "boot";
pub const OP_SYSTEM_STARTUP: &str = "system_startup"; // sanity-check increment emitted once by every process at metrics init
// Preprocessing and generation related operations
pub const OP_KEYGEN_REQUEST: &str = "keygen_request";
pub const OP_KEYGEN_RESULT: &str = "keygen_result";
pub const OP_KEYGEN_ABORT: &str = "keygen_abort";
pub const OP_INSECURE_KEYGEN_REQUEST: &str = "insecure_keygen_request";
pub const OP_INSECURE_KEYGEN_RESULT: &str = "insecure_keygen_result";
pub const OP_KEYGEN_PREPROC_REQUEST: &str = "keygen_preproc_request";
pub const OP_KEYGEN_PREPROC_RESULT: &str = "keygen_preproc_result";
// More specific operation names for key generation, used on the request counter
// and the duration histogram
pub const OP_INSECURE_STANDARD_KEYGEN: &str = "insecure_standard_keygen";
pub const OP_INSECURE_COMPRESSED_KEYGEN: &str = "insecure_compressed_keygen";
pub const OP_INSECURE_DECOMPRESSION_KEYGEN: &str = "insecure_decompression_keygen";
pub const OP_STANDARD_KEYGEN: &str = "standard_keygen";
pub const OP_DECOMPRESSION_KEYGEN: &str = "decompression_keygen";
// the compressed versions of the above
pub const OP_INSECURE_STANDARD_COMPRESSED_KEYGEN: &str = "insecure_standard_compressed_keygen";
pub const OP_STANDARD_COMPRESSED_KEYGEN: &str = "standard_compressed_keygen";
pub const OP_DECOMPRESSION_COMPRESSED_KEYGEN: &str = "decompression_compressed_keygen";

// Public/User decryption Operations
// Corresponds to a request, a request may contain several ciphertexts
pub const OP_PUBLIC_DECRYPT_REQUEST: &str = "public_decrypt_request";
pub const OP_PUBLIC_DECRYPT_RESULT: &str = "public_decrypt_result";
pub const OP_USER_DECRYPT_REQUEST: &str = "user_decrypt_request";
pub const OP_USER_DECRYPT_RESULT: &str = "user_decrypt_result";
// Inner variants of the OP
// Corresponds to a single ciphertext
pub const OP_PUBLIC_DECRYPT_INNER: &str = "public_decrypt_inner";
pub const OP_USER_DECRYPT_INNER: &str = "user_decrypt_inner";

// CRS Operations
pub const OP_CRS_GEN_REQUEST: &str = "crs_gen_request";
pub const OP_CRS_GEN_RESULT: &str = "crs_gen_result";
pub const OP_CRS_GEN_ABORT: &str = "crs_gen_abort";
pub const OP_INSECURE_CRS_GEN_REQUEST: &str = "insecure_crs_gen_request";
pub const OP_INSECURE_CRS_GEN_RESULT: &str = "insecure_crs_gen_result";

// Context operations
pub const OP_NEW_MPC_CONTEXT: &str = "new_mpc_context";
pub const OP_DESTROY_MPC_CONTEXT: &str = "destroy_mpc_context";
pub const OP_NEW_CUSTODIAN_CONTEXT: &str = "new_custodian_context";
pub const OP_DESTROY_CUSTODIAN_CONTEXT: &str = "destroy_custodian_context";
pub const OP_CUSTODIAN_BACKUP_RECOVERY: &str = "custodian_backup_recovery";
pub const OP_CUSTODIAN_RECOVERY_INIT: &str = "custodian_recovery_init";
pub const OP_RESTORE_FROM_BACKUP: &str = "restore_from_backup";
pub const OP_KEY_MATERIAL_AVAILABILITY: &str = "key_material_availability";

// Epoch operations
pub const OP_NEW_EPOCH: &str = "new_mpc_epoch";
pub const OP_DESTROY_EPOCH: &str = "destroy_mpc_epoch";
pub const OP_GET_EPOCH_RESULT: &str = "get_mpc_epoch_result";

// PK fetch
pub const OP_FETCH_PK: &str = "fetch_pk";
```

### Error Types
Standard grpc error types are defined as constants:
```rust
pub const ERR_FAILED_PRECONDITION: &str = "failed_precondition";
pub const ERR_RESOURCE_EXHAUSTED: &str = "resource_exhausted";
pub const ERR_CANCELLED: &str = "cancelled";
pub const ERR_INVALID_ARGUMENT: &str = "invalid_argument";
pub const ERR_ABORTED: &str = "aborted";
pub const ERR_ALREADY_EXISTS: &str = "already_exists";
pub const ERR_NOT_FOUND: &str = "not_found";
pub const ERR_INTERNAL: &str = "internal_error";
pub const ERR_UNAVAILABLE: &str = "unavailable";
pub const ERR_OTHER: &str = "other";
```
Finally two more errors exist: one for problems happening in an async worker thread (i.e. after the initial grpc call has been returned) and one for backup errors:
```rust
pub const ERR_ASYNC: &str = "async_call_error";
pub const ERR_BACKUP: &str = "backup_error";
```

### Tag Keys
Standard metric tag keys are defined as constants:
```rust
// Common metric tag keys
pub const TAG_OPERATION: &str = "operation";
pub const TAG_ERROR: &str = "error";
pub const TAG_ALGORITHM: &str = "algorithm"; // TODO not used yet
pub const TAG_OPERATION_TYPE: &str = "operation_type";
pub const TAG_PARTY_ID: &str = "party_id";
pub const TAG_TFHE_TYPE: &str = "tfhe_type";
pub const TAG_PUBLIC_DECRYPTION_KIND: &str = "public_decryption_mode";
pub const TAG_USER_DECRYPTION_KIND: &str = "user_decryption_mode";
// Special tag used for the central party
pub const CENTRAL_TAG: &str = "central";
```

### Counters
Track values that only increase:
- `{prefix}_operations_total` - Total number of operations processed
  ```rust
  metrics.increment_request_counter(OP_KEYGEN_REQUEST);  // {prefix}_operations_total{operation="keygen_request"}
  ```
- `{prefix}_operation_errors_total` - Total number of operation errors
  ```rust
  metrics.increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, ERR_NOT_FOUND);  // {prefix}_operation_errors_total{operation="public_decrypt_request",error="not_found"}
  ```

### Histograms
Track the distribution of values:
- `{prefix}_operation_duration_ms` - Duration of operations in milliseconds
  ```rust
  let _timer = metrics.time_operation(OP_KEYGEN_REQUEST)
      .tag(TAG_OPERATION_TYPE, OP_TYPE_TOTAL)
      .start();  // {prefix}_operation_duration_ms{operation="keygen_request",operation_type="total"}
  ```
- `{prefix}_payload_size_bytes` - Size of operation payloads in bytes
  ```rust
  metrics.observe_size(OP_PUBLIC_DECRYPT_REQUEST, data.len() as f64);  // {prefix}_payload_size_bytes{operation="public_decrypt_request"}
  ```
NOTE: `{prefix}_payload_size_bytes` is emitted from the versioned-storage write paths
(`safe_write_element_versioned` for file storage, `S3Storage::store_data_at_key`, and `RamStorage`);
there its `operation` label carries the serialized element's **type name** (e.g. a key/keyset type),
not an operation name, and the size is recorded only after the write succeeds. Call `observe_size`
from other paths whenever a payload size is worth tracking.

Both histograms use **explicit buckets** tuned to KMS workloads (`kms_operation_duration_ms`: 1 ms →
5 min; `kms_payload_size_bytes`: 1 KiB → 64 GiB). Prometheus' default buckets top out at ~10 (tuned for
seconds), so our millisecond- and byte-valued observations would otherwise pile into `+Inf` and make
`histogram_quantile` (p50/p95) meaningless.

### Gauges
Track instantaneous values that can rise and fall. There is **no generic gauge API** — each gauge is a
dedicated metric set through its own `record_*` method (e.g. `METRICS.record_cpu_load(load)`). Names
assume the default `kms` prefix:

- System: `kms_cpu_load`, `kms_process_cpu_usage`, `kms_total_cpus`, `kms_memory_usage`,
  `kms_total_memory`, `kms_process_memory_usage`
- Process/runtime: `kms_file_descriptors`, `kms_socat_file_descriptors`, `kms_socat_tasks`,
  `kms_tasks`, `kms_rate_limiter_usage`
- Sessions: `kms_active_sessions`, `kms_inactive_sessions`
- Meta storage: `kms_meta_storage_{user,pub}_decryptions` (ongoing) and
  `kms_meta_storage_{user,pub}_decryptions_in_store` (total)
- Build info: `kms_version` (value is always 1; the version is carried as a const-label)

```rust
METRICS.record_cpu_load(0.75);      // kms_cpu_load 0.75
METRICS.record_tasks(num_workers);  // kms_tasks <n>
```

## Usage Examples

### Basic Usage

```rust
// Record operation counter
METRICS.increment_request_counter(OP_KEYGEN_REQUEST);  // kms_operations_total{operation="keygen_request"}

// Record error with context
METRICS.increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, ERR_NOT_FOUND);  // kms_operation_errors_total{operation="public_decrypt_request",error="not_found"}

// Record duration with tags
let _timer = METRICS
    .time_operation(OP_KEYGEN_REQUEST)
    .tag(TAG_OPERATION_TYPE, OP_TYPE_TOTAL)
    .start();  // kms_operation_duration_ms{operation="keygen_request",operation_type="total"}

// Record payload size (operation name on RPC paths; element type name on storage writes — see NOTE above)
METRICS.observe_size(OP_PUBLIC_DECRYPT_REQUEST, input.len() as f64);  // kms_payload_size_bytes{operation="public_decrypt_request"}

// Record a point-in-time gauge (each gauge has a dedicated record_* method)
METRICS.record_tasks(num_workers);  // kms_tasks <n>
```

### Using Custom Prefix

Only one `CoreMetrics` may be constructed per process: every instance registers into the
process-global default registry, including the fixed-name `kms_version` gauge, so a second
construction panics on duplicate registration. In KMS binaries that instance is the global
`METRICS` (built on first use) — a custom prefix is only an option for a separate binary that
never touches `METRICS`:

```rust
use observability::metrics::{CoreMetrics, MetricsConfig};

// In a binary that does not use the global METRICS instance:
let config = MetricsConfig {
    prefix: "app".to_string(),
    ..Default::default()
};
let metrics = CoreMetrics::with_config(config);

// Now metrics will use "app" prefix
metrics.increment_request_counter(OP_KEYGEN_REQUEST);  // app_operations_total{operation="keygen_request"}
```

### Duration Measurement with Tags

The preferred way to measure operation duration is an RAII guard that records on drop. Only the keys in
`DURATION_LABEL_KEYS` (`operation` plus `operation_type`, `party_id`, `tfhe_type`, `public_decryption_mode`,
`user_decryption_mode`) are recorded on this histogram — unknown keys are ignored with a warning, and
high-cardinality keys (e.g. `key_id`) must not be used.

```rust
fn run_keygen(party_id: usize) -> Result<(), Error> {
    // Records on drop; the operation name fills the `operation` label.
    let _timer = METRICS.time_operation(OP_KEYGEN_REQUEST)
        .tag(TAG_OPERATION_TYPE, OP_TYPE_TOTAL)
        .tag(TAG_PARTY_ID, party_id.to_string())
        .start();  // kms_operation_duration_ms{operation="keygen_request",operation_type="total",party_id="..."}

    process_data()?;
    Ok(())
}
```

Manual recording, when you need the elapsed value or must record before the guard drops:
```rust
fn explicit_timing() -> Result<(), Error> {
    let guard = METRICS.time_operation(OP_KEYGEN_REQUEST)
        .tag(TAG_OPERATION_TYPE, OP_TYPE_TOTAL)
        .start();

    do_work()?;

    let duration = guard.record_now();  // force recording, returns the elapsed Duration
    tracing::info!("keygen took {:?}", duration);
    Ok(())
}
```

### Error Recording

```rust
use observability::metrics::METRICS;

fn handle_request(request: Request) -> Result<(), Error> {
    let _timer = METRICS.time_operation(OP_KEYGEN_REQUEST)
        .tag(TAG_OPERATION_TYPE, OP_TYPE_TOTAL)
        .start();

    METRICS.increment_request_counter(OP_KEYGEN_REQUEST);
    match validate_data(request) {
        Ok(()) => process_valid_data(request),
        Err(e) => {
            // kms_operation_errors_total{operation="keygen_request",error="invalid_argument"}
            METRICS.increment_error_counter(OP_KEYGEN_REQUEST, ERR_INVALID_ARGUMENT);
            Err(e.into())
        }
    }
}
```

## Distinguishing Deployments (kind-CI vs production)

Every metric can carry **static labels** that identify the deployment it came from, so a single
Prometheus/Grafana can tell e.g. kind-CI integration-test metrics apart from production ones.

These labels are read once at startup from the `KMS_METRICS_LABELS` environment variable — a
comma-separated `key=value` list — and applied as Prometheus *const-labels* to **every** metric. No
metric call site changes; the distinction is purely a deployment concern.

```bash
# The kind overlay sets one const-label (comma-separate more if you need them):
KMS_METRICS_LABELS="deployment_profile=kind-ci"
```

```promql
# In Grafana, scope a query to kind-CI runs only. In the kind-CI pipeline every
# metric name additionally carries the ci_ prefix (applied at scrape time by the
# ServiceMonitor), hence ci_kms_..., not kms_....
histogram_quantile(0.95, sum by (le) (rate(ci_kms_operation_duration_ms_bucket{deployment_profile="kind-ci"}[5m])))
```

Conventions:
- `deployment_profile=kind-ci` — the only const-label the kind overlay applies, marking every metric
  from the kind-cluster integration tests.
- The threshold and centralized matrices deploy to separate namespaces (`kms-test-threshold` /
  `kms-test-centralized`, from the CI `DEPLOYMENT_TYPE`), so their metrics are already told apart by
  Prometheus' `namespace` label — there is no `deployment_type` const-label. You could add one via
  `metricsLabels`, but keep any added labels **low-cardinality**.

In the Helm chart the value is set via `kmsCore.metricsLabels` (rendered into the `KMS_METRICS_LABELS`
env var on the kms-server container); the kind-CI overlay `ci/kube-testing/kms/values-kms-test.yaml`
sets only `deployment_profile=kind-ci`. (A per-run `ci_run_id` is also attached in kind — but as a
Prometheus *external label* from `GITHUB_RUN_ID`, not a KMS const-label.) Malformed, empty-valued,
invalidly-named, `__`-reserved, or colliding entries (names already used by a built-in metric label)
are skipped with a warning, so a typo never takes the server down. Unset/empty means no extra labels —
the default for production.

At runtime, `METRICS.labels()` returns the labels that were actually accepted and attached, and the
server logs them at startup so operators can confirm how a deployment is tagged.

## Best Practices

### 1. Operation Naming
- Use the `OP_*` constants from `metrics_names` — never raw strings
- Names mirror the gRPC method, with a phase suffix where a request and its result are tracked
  separately (`_request` / `_result`)
- Keep names short, meaningful, and consistent between logs and metrics
- Examples: `keygen_request`, `keygen_result`, `public_decrypt_request`, `user_decrypt_request`,
  `crs_gen_request`

### 2. Error Recording
- Use predefined error type constants from `metrics_names` module
- These should match gRPC errors along with any special cases indicating other ways a request could fail than at the grpc level. Today that means `ERR_ASYNC` (an error in the async worker thread, after the gRPC call already returned) and `ERR_BACKUP` (backup failures, recorded on the separate `kms_backup_errors_total` counter).

### 3. Tag Usage
- Use tag keys that match parameter names when possible
- Keep tag keys short and consistent
- Common tags from `metrics_names`:
  - `operation`: matches the gRPC method name
  - `error`: standardized error type
  - `party_id`: identifies the MPC party
  - `operation_type`: type of the operation (e.g., "total")
- Avoid introducing new tag keys without adding them to `metrics_names`.
- Also to _not_ use tags that will have high cardinality. E.g. using `RequestId` as tag would not be acceptable.

### 4. Duration Measurement
- Use the `observe_duration_with_tags` method with proper operation name constants
- Include operation type tags for all duration measurements
- Keep measurements consistent across similar operations

### 5. Metric Consistency
- Always import metric names from the `metrics_names` module
- Use the same operation names in logs and metrics
- Follow the established naming patterns when adding new metrics

## Adding New Metrics

When adding new metrics:

1. Add new constants to `metrics_names.rs`:
   ```rust
   // Operation names
   pub const OP_NEW_OPERATION: &str = "new_operation";

   // Error types
   pub const ERR_NEW_ERROR: &str = "new_error_type";

   // Tag keys
   pub const TAG_NEW_TAG: &str = "new_tag";
   ```

2. Use the new constants in your code:
   ```rust
   use observability::metrics_names::{OP_NEW_OPERATION, TAG_NEW_TAG};

   METRICS.observe_duration_with_tags(
       OP_NEW_OPERATION,
       duration,
       &[(TAG_NEW_TAG, value.to_string())]
   );  // records `new_tag` only if it is also added to DURATION_LABEL_KEYS — see "New operation vs new metric family"
   ```

This ensures consistency and maintainability of the metrics system across the codebase.

### New operation vs new metric family

A **new operation** is cheap — define an `OP_*` constant and instrument the path. It's only a new
value of the `operation` label on the existing families, so the low-cardinality guard and the
`metric_families_match_allowlist` test need no changes. A **new metric family** (a new metric name)
additionally requires registering it in `CoreMetrics` and adding it to the
`metric_families_match_allowlist` allowlist (otherwise that test fails).

## Testing

```bash
# Run the observability (metrics) tests
cargo test -p observability
```
