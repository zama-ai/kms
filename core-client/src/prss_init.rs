use kms_grpc::kms::v1::NewMpcEpochRequest;
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::{identifiers::EpochId, ContextId};
use std::collections::HashMap;
use tonic::transport::Channel;

use crate::CoreConf;

/// Send the PRSS init request to the core endpoints for a given context and epoch.
pub(crate) async fn do_prss_init(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    context_id: &ContextId,
    epoch_id: &EpochId,
) -> anyhow::Result<()> {
    let mut join_set = tokio::task::JoinSet::new();
    for (_core_conf, client) in core_endpoints.iter() {
        let mut client = client.clone();
        let request = NewMpcEpochRequest {
            context_id: Some((*context_id).into()),
            epoch_id: Some((*epoch_id).into()),
            previous_context: None,
        };
        join_set.spawn(async move { client.new_mpc_epoch(request).await });
    }

    let results = join_set.join_all().await;
    for result in results {
        // check that empty result is ok
        let _ = result?;
    }
    Ok(())
}
