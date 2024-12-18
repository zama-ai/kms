# Conf-trace

Conf-trace is a library shared by multiple KMS services that provides configuration and tracing functionality. It offers robust telemetry, request tracing, and gRPC request handling capabilities.

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
use conf_trace::{conf::Tracing, telemetry};

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
use conf_trace::grpc::{build_request, RequestConfig};
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
use conf_trace::conf::{Settings, ExecutionEnvironment};

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
use conf_trace::conf::RetryConfig;

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
use conf_trace::telemetry;

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

Run tests with different log levels:

```bash
# Run all tests
cargo test

# Run with trace logging
RUST_LOG=trace cargo test

# Run with JSON logging
RUST_LOG=info cargo test -- --nocapture

# Test specific features
cargo test --features "test-log"
```

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

For detailed metrics documentation and best practices, see [Metrics Guide](docs/metrics.md).
