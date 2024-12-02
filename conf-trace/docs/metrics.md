# KMS Core Metrics Guide

The KMS Core metrics system provides comprehensive observability through OpenTelemetry. This guide explains the metric types, their usage patterns, and best practices.

## Metric Types and Naming

All metrics follow a consistent naming pattern with a configurable prefix (default: "kms"). The full metric name is constructed by combining the prefix with the metric-specific suffix. Metric names are defined as constants in the `metrics_names` module to ensure consistency and prevent typos.

### Operation Names
Standard operation names are defined as constants:
```rust
OP_KEYGEN           // "keygen"
OP_KEYGEN_PREPROC   // "keygen_preproc"
OP_DECRYPT          // "decrypt"
OP_REENCRYPT        // "reencrypt"
OP_VERIFY_PROVEN_CT // "verify_proven_ct"
OP_CRS_GEN          // "crs_gen"
```

### Error Types
Standard error types are defined as constants:
```rust
ERR_RATE_LIMIT_EXCEEDED  // "rate_limit_exceeded"
ERR_KEY_EXISTS          // "key_already_exists"
ERR_KEY_NOT_FOUND       // "key_not_found"
ERR_DECRYPTION_FAILED   // "decryption_failed"
```

### Tag Keys
Standard metric tag keys are defined as constants:
```rust
TAG_OPERATION_TYPE  // "operation_type"
TAG_OPERATION       // "operation"
TAG_ERROR           // "error"
TAG_KEY_ID          // "key_id"
TAG_ALGORITHM       // "algorithm"
```

### Tag Values
Standard tag values are defined as constants:
```rust
OP_TYPE_TOTAL             // "total"
OP_TYPE_LOAD_CRS_PK       // "load_crs_pk"
OP_TYPE_PROOF_VERIFICATION // "proof_verification"
OP_TYPE_CT_PROOF          // "ct_proof"
```

### Counters
Track values that only increase:
- `{prefix}_operations_total` - Total number of operations processed
  ```rust
  metrics.increment_request_counter(OP_KEYGEN)?;  // {prefix}_operations_total{operation="keygen"}
  ```
- `{prefix}_operation_errors_total` - Total number of operation errors
  ```rust
  metrics.increment_error_counter(OP_DECRYPT, ERR_KEY_NOT_FOUND)?;  // {prefix}_operation_errors_total{operation="decrypt",error="key_not_found"}
  ```

### Histograms
Track the distribution of values:
- `{prefix}_operation_duration_ms` - Duration of operations in milliseconds
  ```rust
  let _timer = metrics.time_operation(OP_KEYGEN)?
      .tag(TAG_OPERATION_TYPE, OP_TYPE_TOTAL.to_string())?
      .start();  // {prefix}_operation_duration_ms{operation="keygen",operation_type="total"}
  ```
- `{prefix}_payload_size_bytes` - Size of operation payloads in bytes
  ```rust
  metrics.observe_size(OP_DECRYPT, data.len() as f64)?;  // {prefix}_payload_size_bytes{operation="decrypt"}
  ```

### Gauges
Track instantaneous values that can increase or decrease:
- `{prefix}_gauge` - General purpose gauge for recording independent values
  ```rust
  // Record current number of active connections
  metrics.gauge("active_connections", 42)?;  // {prefix}_gauge{operation="active_connections"}
  
  // Record current memory usage
  metrics.gauge("memory_usage_mb", memory_mb)?;  // {prefix}_gauge{operation="memory_usage_mb"}
  
  // Record queue depth
  metrics.gauge("queue_depth", queue.len() as i64)?;  // {prefix}_gauge{operation="queue_depth"}
  ```

## Usage Examples

### Basic Usage

```rust
use conf_trace::metrics::METRICS;
use conf_trace::metrics_names::{OP_KEYGEN, TAG_OPERATION_TYPE, OP_TYPE_TOTAL};

// Record operation counter
METRICS.increment_request_counter(OP_KEYGEN)?;  // kms_operations_total{operation="keygen"}

// Record error with context
METRICS.increment_error_counter(OP_DECRYPT, ERR_KEY_NOT_FOUND)?;  // kms_operation_errors_total{operation="decrypt",error="key_not_found"}

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
use conf_trace::metrics::{CoreMetrics, MetricsConfig};

// Initialize with custom prefix
let config = MetricsConfig {
    prefix: "app".to_string(),
    default_unit: None,
};
let metrics = CoreMetrics::with_config(config)?;

// Now metrics will use "app" prefix
metrics.increment_request_counter(OP_KEYGEN)?;  // app_operations_total{operation="keygen"}
```

### Duration Measurement with Tags

The preferred way to measure operation duration is using RAII guards with optional tags:

```rust
fn process_key(key_id: &str, algorithm: &str) -> Result<(), Error> {
    // Basic timing with multiple tags
    let _timer = METRICS.time_operation(OP_KEYGEN)?
        .tag("key_id", key_id)?
        .tag("algorithm", algorithm)?
        .start();  // kms_operation_duration_ms{operation="keygen",key_id="...",algorithm="..."}
    
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
use conf_trace::metrics::CoreMetrics; // or ::METRICS;

fn handle_request(data: &[u8]) -> Result<(), Error> {
    let metrics = CoreMetrics::new()?;
    let _timer = metrics.time_operation(OP_KEYGEN)?
        .tag("size", data.len().to_string())?
        .start();  // kms_operation_duration_ms{operation="keygen",size="..."}
    
    match validate_data(data) {
        Ok(()) => {
            metrics.increment_request_counter(OP_KEYGEN)?;
            process_valid_data(data)
        }
        Err(e) => {
            let error_type = match e {
                ValidationError::InvalidFormat => ERR_KEY_NOT_FOUND,
                ValidationError::TooLarge => ERR_RATE_LIMIT_EXCEEDED,
                _ => ERR_DECRYPTION_FAILED,
            };
            metrics.increment_error_counter(OP_KEYGEN, error_type)?;  // kms_operation_errors_total{operation="keygen",error="..."}
            Err(e.into())
        }
    }
}
```

## Best Practices

### 1. Operation Naming
- Use operation names that match gRPC method names (e.g., "keygen", "encrypt", "verify_proven_ct")
- Keep names short but meaningful
- Follow the same naming pattern as the gRPC API for consistency
- Examples: "keygen", "encrypt", "decrypt", "verify_proven_ct", "reencrypt"

### 2. Error Recording
- Use predefined error type constants from `metrics_names` module
- Keep error types consistent across similar operations
- If a new error type is needed, add it to the `metrics_names` module

### 3. Tag Usage
- Use tag keys that match parameter names when possible
- Keep tag keys short and consistent
- Common tags from `metrics_names`:
  - `operation`: matches the gRPC method name
  - `error`: standardized error type
  - `key_id`: matches the key identifier parameter
  - `operation_type`: type of the operation (e.g., "total")
- Avoid introducing new tag keys without adding them to `metrics_names`

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
   use conf_trace::metrics_names::{OP_NEW_OPERATION, TAG_NEW_TAG};
   
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
cargo test -p conf-trace --features metrics_test
