# Observability

`observability` is a library shared by multiple KMS services that provides configuration and tracing functionality. It offers robust telemetry, request tracing, and gRPC request handling capabilities.

## Features

- Configurable OpenTelemetry integration
- Async-first telemetry initialization
- Robust gRPC request handling with automatic request ID generation
- Flexible sampling and batching configuration
- Comprehensive error handling and retry mechanisms
- Performance monitoring with OpenTelemetry metrics
- RAII-based operation tracking

## Tracing Setup

```rust
use observability::{conf::Tracing, telemetry};

// Configure tracing with default settings
let config = Tracing::builder()
    .service_name("my-service")
    .build();

// Initialize tracing
tokio::runtime::Runtime::new()
    .unwrap()
    .block_on(async {
        telemetry::init_tracing(config).await?;
        Ok::<(), anyhow::Error>(())
    })?;

// Advanced configuration with custom settings
let config = Tracing::builder()
    .service_name("my-service")
    .endpoint(Some("http://localhost:4317".to_string()))
    .sampling_ratio(Some(50)) // 50% sampling
    .json_logs(Some(true))
    .batch(Some(BatchConf::builder()
        .max_queue_size(Some(1000))
        .max_export_batch_size(Some(100))
        .max_concurrent_exports(Some(2))
        .build()))
    .build();
```

### Making gRPC Requests

```rust
use observability::grpc::{build_request, RequestConfig};
use tracing::{info_span, Instrument};

// Basic request with automatic request ID
let request = build_request(
    payload,
    None,
    Some(RequestConfig {
        generate_request_id: true,
        include_timing: true,
        trace_payload: false,
    })
)?;

// Advanced request with custom span and timing
async fn process_request() -> Result<(), Error> {
    let span = info_span!("process_request", request_id = field::Empty);

    let request = build_request(
        payload,
        Some("custom-request-id"),
        Some(RequestConfig {
            generate_request_id: false,
            include_timing: true,
            trace_payload: true,
        })
    )?;

    // Execute the request within the span
    my_grpc_client.send_request(request)
        .instrument(span)
        .await
}
```

### Environment-based Configuration

```rust
use observability::conf::{Settings, ExecutionEnvironment};

// Load configuration based on environment
let settings = Settings::new(ExecutionEnvironment::Production);
let config: Tracing = settings.init_conf()?;

// Environment-specific tracing setup
match *ENVIRONMENT {
    ExecutionEnvironment::Local => {
        // Local development settings
        Tracing::builder()
            .service_name("dev-service")
            .json_logs(Some(false))
            .sampling_ratio(Some(100))
            .build()
    },
    ExecutionEnvironment::Production => {
        // Production settings
        Tracing::builder()
            .service_name("prod-service")
            .endpoint(Some("https://otel-collector.prod"))
            .json_logs(Some(true))
            .sampling_ratio(Some(10))
            .build()
    }
}
```

### Configuration Options

### Tracing Configuration
- `service_name`: Name of the service for identification (required)
- `endpoint`: OpenTelemetry endpoint URL (optional)
- `sampling_ratio`: Sampling rate from 0 to 100 (default: 10)
- `batch`: Batch processing configuration (optional)
- `json_logs`: Enable JSON format logging (default: false)
- `init_timeout_secs`: Initialization timeout in seconds (default: 10)
- `async_init`: Enable async initialization (default: true)

### Batch Configuration
- `max_queue_size`: Maximum queue size for spans (default: 8192)
- `max_export_batch_size`: Maximum batch size for exports (default: 2048)
- `max_concurrent_exports`: Maximum concurrent export operations (default: 4)
- `scheduled_delay`: Delay between exports (default: 500ms)
- `export_timeout`: Timeout for export operations (default: 5s)
- `retry_config`: Retry behavior configuration (optional)

### Retry Configuration
```rust
use observability::conf::RetryConfig;

let retry_config = RetryConfig::builder()
    .max_retries(3)
    .initial_delay(Duration::from_millis(100))
    .max_delay(Duration::from_secs(1))
    .build();
```

### Best Practices

1. **Async Initialization**
   - Always use async initialization when possible
   - Set appropriate timeouts based on your environment

2. **Sampling Configuration**
   - Use higher sampling rates in development (80-100%)
   - Lower sampling rates in production (10-20%)
   - Adjust based on traffic volume

3. **Request Tracing**
   - Always include request IDs for debugging
   - Use span hierarchies for complex operations
   - Add relevant context to spans

4. **Performance Optimization**
   - Monitor export queue sizes
   - Adjust batch settings based on load
   - Use appropriate concurrent export limits

5. **Error Handling**
   - Implement proper error handling for all operations
   - Use structured logging for errors
   - Include context in error messages

### Error Handling

The library provides comprehensive error handling:

```rust
use observability::telemetry;

// Handle initialization errors
if let Err(e) = telemetry::init_tracing(config).await {
    eprintln!("Failed to initialize tracing: {:?}", e);
    // Handle error appropriately
}

// Handle request errors with context
let result = build_request(payload, request_id, config)
    .context("Failed to create request")?;
```

### Testing

Test logging is handled by the `observability` crate's `test_config` module.
Call `observability::test_config::init_test_logging()` at the start of tests
that need logging output. The logging configuration supports repo-specific
controls for console/file logging via environment variables.

Filter resolution is "first match wins", per output:

1. Output-specific overrides:
   - Console: `KMS_TEST_LOG_CONSOLE_FILTER`
   - File: `KMS_TEST_LOG_FILE_FILTER`
2. Shared override: `KMS_TEST_LOG_FILTER`
3. `RUST_LOG`
4. Mode preset: `KMS_TEST_LOG_MODE` (`verbose` => info preset, otherwise warn preset)

`RUST_LOG` works as usual, but only when no higher-priority `KMS_TEST_LOG_*`
override is set for that output.

What "repo-specific override" means here:

- `KMS_TEST_LOG_CONSOLE_FILTER`, `KMS_TEST_LOG_FILE_FILTER`, and
  `KMS_TEST_LOG_FILTER` are workspace-specific test controls.
- They are intentionally checked before `RUST_LOG`, so CI/local shell defaults
  do not accidentally change test behavior.

Which one to use:

- Use `KMS_TEST_LOG_CONSOLE_FILTER` to tune only terminal/stderr output.
- Use `KMS_TEST_LOG_FILE_FILTER` to tune only persisted trace files.
- Use `KMS_TEST_LOG_FILTER` to apply one shared filter to both outputs.
- Use `RUST_LOG` only as a fallback when no `KMS_TEST_LOG_*` override is set.

Quick commands:

```bash
# Run all tests
cargo test

# Show stderr logs while debugging
KMS_TEST_LOG_MODE=verbose cargo test my_test -- --nocapture

# Fine-grained console filter (same directive syntax as RUST_LOG)
KMS_TEST_LOG_CONSOLE_FILTER='info,my_crate::module=debug' cargo test my_test -- --nocapture

# Persist trace logs for CI artifact collection
TRACE_PERSISTENCE=enabled cargo test my_test

# Control persisted file verbosity and max size
TRACE_PERSISTENCE=enabled KMS_TEST_LOG_FILE_FILTER='info,my_crate=debug' KMS_TEST_LOG_MAX_BYTES=4194304 cargo test my_test
```

`KMS_TEST_LOG_MODE` values:

| Value | Stderr output | Filter preset (when no override set) |
|---|---|---|
| `verbose` / `debug` / `trace` | on | info-level (all three are aliases) |
| `console` | on | warn-level |
| unset (default) | off | warn-level (file/capture outputs unaffected) |

For actual debug/trace granularity, use `KMS_TEST_LOG_CONSOLE_FILTER` with
explicit directives instead of relying on mode aliases.

## Metrics Overview

The metrics system provides several types of measurements:

### Counters
- `{prefix}_operations_total`: Total number of operations processed
- `{prefix}_operation_errors_total`: Total number of operation errors

### Histograms
- `{prefix}_operation_duration_ms`: Duration of operations in milliseconds
- `{prefix}_payload_size_bytes`: Size of operation payloads in bytes

### Gauges
- `{prefix}_gauge`: A general-purpose gauge for recording independent values. Unlike counters and histograms which track cumulative values or distributions, gauges record instantaneous values that can go up or down. They are useful for metrics like number of active connections, current memory usage, or any other point-in-time measurements.

For detailed metrics documentation and best practices, see [Metrics Guide](./metrics.md).
