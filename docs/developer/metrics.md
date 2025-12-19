# KMS Core Metrics Guide

The KMS Core metrics system provides comprehensive observability through OpenTelemetry. This guide explains the metric types, their usage patterns, and best practices.

## Metric Types and Naming

All metrics follow a consistent naming pattern with a configurable prefix (default: "kms"). The full metric name is constructed by combining the prefix with the metric-specific suffix. Metric names are defined as constants in the `metrics_names` module to ensure consistency and prevent typos.

### Operation Names
Standard operation names are defined as constants:
```rust
// Preprocessing and generation related operations
pub const OP_KEYGEN_REQUEST: &str = "keygen_request";
pub const OP_KEYGEN_RESULT: &str = "keygen_result";
pub const OP_INSECURE_KEYGEN_REQUEST: &str = "insecure_keygen_request";
pub const OP_INSECURE_KEYGEN_RESULT: &str = "insecure_keygen_result";
pub const OP_KEYGEN_PREPROC_REQUEST: &str = "keygen_preproc_request";
pub const OP_KEYGEN_PREPROC_RESULT: &str = "keygen_preproc_result";
// More specific metrics for key generation, only used with counters
pub const OP_INSECURE_STANDARD_KEYGEN: &str = "insecure_standard_keygen";
pub const OP_INSECURE_DECOMPRESSION_KEYGEN: &str = "insecure_decompression_keygen";
pub const OP_STANDARD_KEYGEN: &str = "standard_keygen";
pub const OP_DECOMPRESSION_KEYGEN: &str = "decompression_keygen";

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
pub const OP_INSECURE_CRS_GEN_REQUEST: &str = "insecure_crs_gen_request";
pub const OP_INSECURE_CRS_GEN_RESULT: &str = "insecure_crs_gen_result";

// PRSS init
pub const OP_INIT: &str = "init";

// Context operations
pub const OP_NEW_MPC_CONTEXT: &str = "new_mpc_context";
pub const OP_DESTROY_MPC_CONTEXT: &str = "destroy_mpc_context";
pub const OP_NEW_CUSTODIAN_CONTEXT: &str = "new_custodian_context";
pub const OP_DESTROY_CUSTODIAN_CONTEXT: &str = "destroy_custodian_context";
pub const OP_CUSTODIAN_BACKUP_RECOVERY: &str = "custodian_backup_recovery";
pub const OP_CUSTODIAN_RECOVERY_INIT: &str = "custodian_recovery_init";
pub const OP_RESTORE_FROM_BACKUP: &str = "restore_from_backup";

// Resharing
pub const OP_INITIATE_RESHARING: &str = "initiate_resharing";
pub const OP_GET_INITIATE_RESHARING_RESULT: &str = "get_initiate_resharing_result";

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
Finally another error is there for problems happening in an async worker thread. I.e. after the initial grpc call has been returned:
```rust
pub const ERR_ASYNC: &str = "async_call_error";
```

### Tag Keys
Standard metric tag keys are defined as constants:
```rust
// Common metric tag keys
pub const TAG_OPERATION: &str = "operation";
pub const TAG_ERROR: &str = "error";
pub const TAG_KEY_ID: &str = "key_id";
pub const TAG_CRS_ID: &str = "crs_id";
pub const TAG_CONTEXT_ID: &str = "context_id";
pub const TAG_EPOCH_ID: &str = "epoch_id";
pub const TAG_ALGORITHM: &str = "algorithm";
pub const TAG_OPERATION_TYPE: &str = "operation_type";
pub const TAG_PARTY_ID: &str = "party_id";
pub const TAG_TFHE_TYPE: &str = "tfhe_type";
pub const TAG_PUBLIC_DECRYPTION_KIND: &str = "public_decryption_mode";
pub const TAG_USER_DECRYPTION_KIND: &str = "user_decryption_mode";
```

### Counters
Track values that only increase:
- `{prefix}_operations_total` - Total number of operations processed
  ```rust
  metrics.increment_request_counter(OP_KEYGEN_REQUEST)?;  // {prefix}_operations_total{operation="keygen"}
  ```
- `{prefix}_operation_errors_total` - Total number of operation errors
  ```rust
  metrics.increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, ERR_KEY_NOT_FOUND)?;  // {prefix}_operation_errors_total{operation="public_decrypt_request",error="not_found"}
  ```

### Histograms
Track the distribution of values:
- `{prefix}_operation_duration_ms` - Duration of operations in milliseconds
  ```rust
  let _timer = metrics.time_operation(OP_KEYGEN_REQUEST)?
      .tag(TAG_OPERATION_TYPE, OP_TYPE_TOTAL.to_string())?
      .start();  // {prefix}_operation_duration_ms{operation="keygen_request",operation_type="total"}
  ```
- `{prefix}_payload_size_bytes` - Size of operation payloads in bytes
  ```rust
  metrics.observe_size(OP_DECRYPT, data.len() as f64)?;  // {prefix}_payload_size_bytes{operation="decrypt"}
  ```
NOTE: these are not fully implemented yet!

### Gauges
Track instantaneous values that can increase or decrease:
- `{prefix}_gauge` - General purpose gauge for recording independent values
  ```rust
    cpu_load_gauge: TaggedMetric<Gauge<f64>>, 
    memory_usage_gauge: TaggedMetric<Gauge<u64>>,
    file_descriptor_gauge: TaggedMetric<Gauge<u64>>, // Number of file descriptors of the KMS
    socat_file_descriptor_gauge: TaggedMetric<Gauge<u64>>, // Number of socat file descriptors
    socat_task_gauge: TaggedMetric<Gauge<u64>>,      // Number of socat file descriptors
    task_gauge: TaggedMetric<Gauge<u64>>,            // Numbers active child processes of the KMS
    // Internal system gauges
    rate_limiter_gauge: TaggedMetric<Gauge<u64>>, // Number tokens used in the rate limiter
    active_session_gauge: TaggedMetric<Gauge<u64>>, // Number of active sessions
    inactive_session_gauge: TaggedMetric<Gauge<u64>>, // Number of inactive sessions
    meta_storage_pub_dec_gauge: TaggedMetric<Gauge<u64>>, // Number of ongoing public decryptions in meta storage
    meta_storage_user_dec_gauge: TaggedMetric<Gauge<u64>>, // Number of ongoing user decryptions in meta storage
  ```

## Usage Examples

### Basic Usage

```rust
// Record operation counter
METRICS.increment_request_counter(OP_KEYGEN_REQUEST)?;  // kms_operations_total{operation="keygen_request"}

// Record error with context
METRICS.increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, ERR_NOT_FOUND)?;  // kms_operation_errors_total{operation="public_decrypt_request",error="not_found"}

// Record duration with tags
let _timer = METRICS.time_operation(OP_KEYGEN)?
    .tag(TAG_OPERATION_TYPE, OP_TYPE_TOTAL)?
    .start();  // kms_operation_duration_ms{operation="keygen",operation_type="total"}

// Record payload size
METRICS.observe_size(OP_DECRYPT, input.len() as f64)?;  // kms_payload_size_bytes{operation="decrypt"}

// Record current system state
METRICS.gauge("worker_count", num_workers)?;  // kms_gauge{operation="worker_count"}
```

### Using Custom Prefix

```rust
use observability::metrics::{CoreMetrics, MetricsConfig};

// Initialize with custom prefix
let config = MetricsConfig {
    prefix: "app".to_string(),
    default_unit: None,
};
let metrics = CoreMetrics::with_config(config)?;

// Now metrics will use "app" prefix
metrics.increment_request_counter(OP_KEYGEN_REQUEST)?;  // app_operations_total{operation="keygen_request"}
```

### Duration Measurement with Tags

The preferred way to measure operation duration is using RAII guards with optional tags:

```rust
fn process_key(key_id: &str, algorithm: &str) -> Result<(), Error> {
    // Basic timing with multiple tags
    let _timer = METRICS.time_operation(OP_KEYGEN_REQUEST)?
        .tag("key_id", key_id)?
        .tag("algorithm", algorithm)?
        .start();  // kms_operation_duration_ms{operation="keygen_requets",key_id="...",algorithm="..."}

    // Timer automatically records duration when dropped
    process_data()?;
    Ok(())
}
```
With tags:
```rust
fn handle_key_operation(key_id: &str) -> Result<(), Error> {
    // Add context through tags
    let _guard = METRICS.time_operation(OP_KEYGEN)?
        .tag("key_id", key_id)?
        .tag("operation_type", "encryption")?
        .start();  // kms_operation_duration_ms{operation="keygen",key_id="...",operation_type="encryption"}

    process_key()?;
    Ok(())
}
```

Manual duration recording:
```rust
fn explicit_timing() -> Result<(), Error> {
    let guard = METRICS.time_operation(OP_KEYGEN)?
        .tag("mode", "manual")?
        .start();  // kms_operation_duration_ms{operation="keygen",mode="manual"}

    do_work()?;

    // Get duration and force recording
    let duration = guard.record_now();
    log::info!("Operation took {:?}", duration);
    perform_other_work()?;
    Ok(())
}
```

### Error Recording

```rust
use observability::metrics::CoreMetrics; // or ::METRICS;

fn handle_request(request: Request) -> Result<(), Error> {
    let metrics = CoreMetrics::new()?;
    let _timer = metrics.time_operation(OP_KEYGEN_REQUEST)?
        .tag("size", data.len().to_string())?
        .start();  // kms_operation_duration_ms{operation="keygen_request",size="..."}

    metrics.increment_request_counter(OP_KEYGEN_REQUEST)?;
    match validate_data(request) {
        Ok(()) => {        
            process_valid_data(data)
        }
        Err(e) => {
            metrics.increment_error_counter(OP_KEYGEN_REQUEST, ERR_INVALID_ARGUMENT)?;  // kms_operation_errors_total{operation="keygen_request",error="invalid_argument"}
            Err(e.into())
        }
    }
}
```

## Best Practices

### 1. Operation Naming
- Use operation names that match gRPC method names (e.g., "keygen", "encrypt")
- Keep names short but meaningful
- Follow the same naming pattern as the gRPC API for consistency
- Examples: "keygen", "public_decrypt", "user_decrypt"

### 2. Error Recording
- Use predefined error type constants from `metrics_names` module
- These should match gRPC errors along with any special cases indicating other ways a request could fail than at the grpc level. For now this only means the `ERR_ASYNC` which is used in case of an error occuring in the async worker thread for a gRPC request. 

### 3. Tag Usage
- Use tag keys that match parameter names when possible
- Keep tag keys short and consistent
- Common tags from `metrics_names`:
  - `operation`: matches the gRPC method name
  - `error`: standardized error type
  - `key_id`: matches the key identifier parameter
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
   )?;  // kms_operation_duration_ms{operation="new_operation",new_tag="..."}
   ```

This ensures consistency and maintainability of the metrics system across the codebase.

## Testing

```bash
# Run metrics tests specifically
cargo test -p observability --features metrics_test
