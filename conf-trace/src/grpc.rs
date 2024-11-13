use crate::telemetry::{TRACER_PARENT_SPAN_ID, TRACER_REQUEST_ID};
use tonic::Request;
use tracing::Span;

/// Make GRPC request
///
/// This function is used to create a gprc-request that propagates a request ID through headers.
/// It will also try to get the current span ID and propagate it
pub fn make_request<T: std::fmt::Debug>(
    request: T,
    request_id: Option<String>,
) -> anyhow::Result<Request<T>> {
    let mut request = tonic::Request::new(request);
    let parent_id: u64 = match Span::current().id() {
        None => {
            tracing::warn!("Parent id found is None, defaulting to 0");
            0
        }
        Some(id) => id.into_u64(),
    };
    if let Some(request_id) = request_id {
        let request_header = request_id.parse()?;
        let metadata = request.metadata_mut();
        metadata.insert(TRACER_REQUEST_ID, request_header);
        metadata.insert(TRACER_PARENT_SPAN_ID, parent_id.into());
    } else {
        tracing::warn!("Request ID was none!");
    }
    Ok(request)
}
