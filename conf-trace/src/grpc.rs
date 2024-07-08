use crate::telemetry::TRACER_REQUEST_ID;
use tonic::Request;

/// This function is used to create a request with a request ID.
pub fn make_request<T>(request: T, request_id: Option<String>) -> anyhow::Result<Request<T>> {
    let mut request = tonic::Request::new(request);
    if let Some(request_id) = request_id {
        let request_header = request_id.parse()?;
        request
            .metadata_mut()
            .insert(TRACER_REQUEST_ID, request_header);
    }
    Ok(request)
}
