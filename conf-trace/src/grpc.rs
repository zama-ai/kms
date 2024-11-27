use crate::telemetry::{TRACER_PARENT_SPAN_ID, TRACER_REQUEST_ID};
use opentelemetry::trace::TraceContextExt;
use std::time::Instant;
use tonic::Request;
use tracing::{error, trace, warn, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

/// Error type for gRPC request creation
#[derive(Debug, thiserror::Error)]
pub enum GrpcError {
    #[error("Failed to parse request header: {0}")]
    HeaderParse(#[from] tonic::metadata::errors::ToStrError),
    #[error("Failed to set metadata: {0}")]
    MetadataSet(#[from] tonic::metadata::errors::InvalidMetadataValue),
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Configuration for gRPC request creation
#[derive(Debug, Clone)]
pub struct RequestConfig {
    /// Whether to generate a request ID if none is provided
    pub generate_request_id: bool,
    /// Whether to include timing information in spans
    pub include_timing: bool,
    /// Whether to include request payload in traces (be careful with sensitive data)
    pub trace_payload: bool,
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            generate_request_id: true,
            include_timing: true,
            trace_payload: false,
        }
    }
}

/// Make GRPC request with configuration
///
/// This function is used to create a gRPC request that propagates a request ID through headers.
/// It will also try to get the current span ID and propagate it.
///
/// # Arguments
/// * `request` - The request payload
/// * `request_id` - Optional request ID to use
/// * `config` - Configuration for request creation
///
/// # Returns
/// Returns the created request with proper tracing context
pub fn make_request<T: std::fmt::Debug>(
    request: T,
    request_id: Option<String>,
    config: Option<RequestConfig>,
) -> Result<Request<T>, GrpcError> {
    let config = config.unwrap_or_default();
    let start_time = Instant::now();

    // Create span for request creation
    let span = tracing::span!(Level::DEBUG, "make_grpc_request", otel.kind = "client");
    let _guard = span.enter();

    // Generate or validate request ID
    let request_id = if let Some(id) = request_id {
        trace!("Using provided request ID: {}", id);
        id
    } else if config.generate_request_id {
        let id = Uuid::new_v4().to_string();
        trace!("Generated new request ID: {}", id);
        id
    } else {
        warn!("No request ID provided and generation disabled");
        return Err(GrpcError::Internal("No request ID available".to_string()));
    };

    // Create request with tracing context
    let mut request = Request::new(request);
    let parent_span = Span::current();

    // Get parent span context
    let parent_id = parent_span.id().map(|id| id.into_u64()).unwrap_or_else(|| {
        warn!("No parent span ID found, using 0");
        0
    });

    // Add tracing metadata
    let metadata = request.metadata_mut();
    metadata.insert(TRACER_REQUEST_ID, request_id.parse()?);
    metadata.insert(TRACER_PARENT_SPAN_ID, parent_id.into());

    // Add OpenTelemetry context
    let context = parent_span.context();
    if let Some(span_context) = context
        .span()
        .span_context()
        .is_valid()
        .then(|| context.span().span_context().clone())
    {
        // Format traceparent according to W3C trace context specification
        let trace_id = span_context.trace_id();
        let span_id = span_context.span_id();
        let trace_flags = span_context.trace_flags().to_u8();
        let traceparent = format!("00-{:032x}-{:016x}-{:02x}", trace_id, span_id, trace_flags);
        metadata.insert("traceparent", traceparent.parse()?);
    }

    // Log request details if configured
    if config.trace_payload {
        trace!(
            request.payload = ?request.get_ref(),
            "Created gRPC request"
        );
    }

    // Record timing if configured
    if config.include_timing {
        let duration = start_time.elapsed();
        trace!(
            duration_ms = duration.as_millis(),
            "Request preparation completed"
        );
    }

    Ok(request)
}

/// Helper function to extract request ID from gRPC request
pub fn extract_request_id<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get(TRACER_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Helper function to extract parent span ID from gRPC request
pub fn extract_parent_span_id<T>(request: &Request<T>) -> Option<u64> {
    request
        .metadata()
        .get(TRACER_PARENT_SPAN_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn test_make_request_with_id() {
        let payload = "test_payload";
        let request_id = "test_id".to_string();
        let result = make_request(payload, Some(request_id.clone()), None);
        assert!(result.is_ok());
        let request = result.unwrap();
        assert_eq!(extract_request_id(&request), Some(request_id));
    }

    #[test]
    #[traced_test]
    fn test_make_request_auto_generate_id() {
        let payload = "test_payload";
        let result = make_request(payload, None, None);
        assert!(result.is_ok());
        let request = result.unwrap();
        assert!(extract_request_id(&request).is_some());
    }

    #[test]
    #[traced_test]
    fn test_make_request_no_id_no_generate() {
        let payload = "test_payload";
        let config = RequestConfig {
            generate_request_id: false,
            ..Default::default()
        };
        let result = make_request(payload, None, Some(config));
        assert!(result.is_err());
    }
}
