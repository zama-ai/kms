use core::future::Future;

use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, MAX_TRIES};
use kms_grpc::RequestId;
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use std::collections::HashMap;
use std::pin::Pin;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};

/// RequestIds as they are represented in the current version of the ProtoBuf API.
type ProtoRequestId = kms_grpc::kms::v1::RequestId;

// =============================================================================
// ISOLATED TEST HELPERS
// =============================================================================
// These helpers are used by isolated tests that use the consolidated testing
// module (kms_lib::testing). They provide simplified interfaces for common
// threshold operations without requiring the full test setup infrastructure.

/// Helper to generate threshold key using insecure mode.
///
/// This function sends insecure_key_gen requests to all clients and waits for
/// key generation to complete. It's designed for use with ThresholdTestEnv.
///
/// # Arguments
/// * `clients` - Map of party ID to gRPC client
/// * `request_id` - Unique identifier for this key generation request
/// * `params` - FHE parameters to use for key generation
///
/// # Returns
/// * `Ok(responses)` - per-party `(party_id, KeyGenResult)` for use with `verify_keygen_responses`
/// * `Err` if any party failed
pub async fn threshold_insecure_key_gen(
    clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    request_id: &kms_grpc::RequestId,
    params: kms_grpc::kms::v1::FheParameter,
) -> anyhow::Result<
    Vec<(
        u32,
        Result<tonic::Response<kms_grpc::kms::v1::KeyGenResult>, tonic::Status>,
    )>,
> {
    use crate::client::tests::common::default_isolated_extra_data;
    use crate::dummy_domain;
    use crate::engine::base::INSECURE_PREPROCESSING_ID;
    use crate::testing::helpers::domain_to_msg;
    use kms_grpc::kms::v1::KeyGenRequest;
    use tokio::task::JoinSet;

    let domain_msg = domain_to_msg(&dummy_domain());

    // Use insecure_key_gen endpoint which bypasses preprocessing validation
    let mut keygen_tasks = JoinSet::new();
    for client in clients.values() {
        let mut cur_client = client.clone();
        let keygen_req = KeyGenRequest {
            request_id: Some((*request_id).into()),
            params: Some(params as i32),
            preproc_id: Some((*INSECURE_PREPROCESSING_ID).into()),
            domain: Some(domain_msg.clone()),
            keyset_config: None,
            keyset_added_info: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: Some((*DEFAULT_EPOCH_ID).into()),
            extra_data: default_isolated_extra_data(),
        };
        keygen_tasks.spawn(async move {
            cur_client
                .insecure_key_gen(tonic::Request::new(keygen_req))
                .await
        });
    }

    while let Some(res) = keygen_tasks.join_next().await {
        res??;
    }

    // Wait for key generation to complete on all parties and collect responses
    let mut responses = Vec::new();
    for (party_id, client) in clients.iter() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_insecure_key_gen_result(tonic::Request::new((*request_id).into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_insecure_key_gen_result(tonic::Request::new((*request_id).into()))
                .await;
        }
        responses.push((*party_id, result));
    }

    Ok(responses)
}

/// Helper to generate threshold key using secure mode with preprocessing.
///
/// This function runs the full preprocessing + key generation flow using secure mode.
/// It's designed for use with ThresholdTestEnv when PRSS is enabled.
///
/// # Arguments
/// * `clients` - Map of party ID to gRPC client
/// * `preproc_id` - Unique identifier for preprocessing request
/// * `keygen_id` - Unique identifier for key generation request
/// * `params` - FHE parameters to use
///
/// # Returns
/// * `Ok(responses)` - per-party `(party_id, KeyGenResult)` for use with `verify_keygen_responses`
/// * `Err` if any party failed
#[cfg(feature = "slow_tests")]
#[expect(clippy::too_many_arguments)]
pub async fn threshold_key_gen_secure(
    clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    preproc_id: &kms_grpc::RequestId,
    keygen_id: &kms_grpc::RequestId,
    params: kms_grpc::kms::v1::FheParameter,
    keyset_config: Option<kms_grpc::kms::v1::KeySetConfig>,
    keyset_added_info: Option<kms_grpc::kms::v1::KeySetAddedInfo>,
    context_id: Option<kms_grpc::kms::v1::RequestId>,
    epoch_id: Option<kms_grpc::kms::v1::RequestId>,
) -> anyhow::Result<
    Vec<(
        u32,
        Result<tonic::Response<kms_grpc::kms::v1::KeyGenResult>, tonic::Status>,
    )>,
> {
    use crate::client::tests::common::default_isolated_extra_data;
    use crate::dummy_domain;
    use crate::testing::helpers::domain_to_msg;
    use kms_grpc::kms::v1::{KeyGenPreprocRequest, KeyGenRequest};
    use tokio::task::JoinSet;

    // Note: Isolated callers always use the default context/epoch; if that ever changes
    // we'd need to resolve `context_id` / `epoch_id` to concrete ids and rebuild
    // extra_data via `make_extra_data` so the signed bytes stay consistent.
    assert!(
        context_id.is_none() && epoch_id.is_none(),
        "threshold_key_gen_secure_isolated only supports default context/epoch ids"
    );
    let domain_msg = domain_to_msg(&dummy_domain());
    let extra_data = default_isolated_extra_data();

    // Step 1: Run preprocessing
    let mut preproc_tasks = JoinSet::new();
    for client in clients.values() {
        let mut cur_client = client.clone();
        let preproc_req = KeyGenPreprocRequest {
            request_id: Some((*preproc_id).into()),
            params: params as i32,
            domain: Some(domain_msg.clone()),
            keyset_config,
            context_id: context_id.clone(),
            epoch_id: epoch_id.clone(),
            extra_data: extra_data.clone(),
        };
        preproc_tasks.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(preproc_req))
                .await
        });
    }

    while let Some(res) = preproc_tasks.join_next().await {
        res??;
    }

    // Wait for preprocessing to complete
    for client in clients.values() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_preproc_result(tonic::Request::new((*preproc_id).into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_preproc_result(tonic::Request::new((*preproc_id).into()))
                .await;
        }
        result?;
    }

    // Step 2: Run key generation using the preprocessed material
    let mut keygen_tasks = JoinSet::new();
    for client in clients.values() {
        let mut cur_client = client.clone();
        let keygen_req = KeyGenRequest {
            request_id: Some((*keygen_id).into()),
            params: Some(params as i32),
            preproc_id: Some((*preproc_id).into()),
            domain: Some(domain_msg.clone()),
            keyset_config,
            keyset_added_info: keyset_added_info.clone(),
            context_id: context_id.clone(),
            epoch_id: epoch_id.clone(),
            extra_data: extra_data.clone(),
        };
        keygen_tasks
            .spawn(async move { cur_client.key_gen(tonic::Request::new(keygen_req)).await });
    }

    while let Some(res) = keygen_tasks.join_next().await {
        res??;
    }

    // Wait for key generation to complete and collect responses
    let mut responses = Vec::new();
    for (party_id, client) in clients.iter() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_result(tonic::Request::new((*keygen_id).into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_result(tonic::Request::new((*keygen_id).into()))
                .await;
        }
        responses.push((*party_id, result));
    }

    Ok(responses)
}

/// Helper to retry a single poll call until it succeeds or we exhaust [`crate::consts::MAX_TRIES`].
pub async fn poll_with_retries<R: Send>(
    mut client: CoreServiceEndpointClient<Channel>,
    server_id: u32,
    req_id: ProtoRequestId,
    poll_fn: impl for<'a> Fn(
        &'a mut CoreServiceEndpointClient<Channel>,
        Request<ProtoRequestId>,
    )
        -> Pin<Box<dyn Future<Output = Result<Response<R>, Status>> + Send + 'a>>,
) -> (u32, ProtoRequestId, R) {
    for count in 0..MAX_TRIES {
        // By default our gRPC calls do not time out. Here we're giving it 2sec per poll attempt to reply.
        tokio::select! {
            result = poll_fn(&mut client, Request::new(req_id.clone())) => {
                match result {
                    Ok(resp) => return (server_id, req_id, resp.into_inner()),
                    Err(e) => {
                        let id_str = RequestId::try_from(req_id.clone()).unwrap().to_string();
                        tracing::trace!("Attempt {count} for server {server_id}, req {id_str}: {e:?}");
                    }
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                tracing::trace!("Attempt {count} for server {server_id} timed out");
            }
        }
        // Back-off a little bit before re-trying
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
    panic!("no response for server {server_id} after {MAX_TRIES} tries");
}
