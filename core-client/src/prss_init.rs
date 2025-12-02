use kms_grpc::kms::v1::InitRequest;
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::{identifiers::EpochId, ContextId};
use std::collections::HashMap;
use tonic::transport::Channel;

/// Send the PRSS init request to the core endpoints for a given context and epoch.
pub(crate) async fn do_prss_init(
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    context_id: &ContextId,
    epoch_id: &EpochId,
) -> anyhow::Result<()> {
    let mut join_set = tokio::task::JoinSet::new();
    for (_party_id, client) in core_endpoints.iter() {
        let mut client = client.clone();
        let request = InitRequest {
            context_id: Some((*context_id).into()),
            request_id: Some((*epoch_id).into()),
        };
        join_set.spawn(async move { client.init(request).await });
    }

    let results = join_set.join_all().await;
    for result in results {
        // check that empty result is ok
        let _ = result?;
    }
    Ok(())
}
