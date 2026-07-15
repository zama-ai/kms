use crate::client::tests::common::{PollConfig, default_isolated_extra_data, retrying_poll};
use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT};
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::testing::helpers::domain_to_msg;
use kms_grpc::kms::v1::{KeyGenPreprocRequest, KeyGenRequest};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use std::collections::HashMap;
use tokio::task::JoinSet;
use tonic::transport::Channel;

// =============================================================================
// ISOLATED TEST HELPERS
// =============================================================================
// These helpers are used by isolated tests that use the consolidated testing
// module (kms_lib::testing). They provide simplified interfaces for common
// threshold operations without requiring the full test setup infrastructure.

/// Helper to run the insecure (dummy) preprocessing on all clients.
///
/// This sends insecure_key_gen_preproc requests to all clients and waits for
/// them to complete, so the resulting preprocessing ID can be consumed by a
/// subsequent insecure key generation.
///
/// # Arguments
/// * `clients` - Map of party ID to gRPC client
/// * `preproc_id` - Unique identifier for this preprocessing request
/// * `params` - FHE parameters to store with the preprocessing
///
/// # Returns
/// * `Ok(())` once the preprocessing is finished on all parties
/// * `Err` if any party failed
pub(crate) async fn run_insecure_preproc(
    clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    preproc_id: &kms_grpc::RequestId,
    params: kms_grpc::kms::v1::FheParameter,
) -> anyhow::Result<()> {
    let domain_msg = domain_to_msg(&dummy_domain());

    let mut preproc_tasks = JoinSet::new();
    for client in clients.values() {
        let mut cur_client = client.clone();
        let preproc_req = KeyGenPreprocRequest {
            request_id: Some((*preproc_id).into()),
            params: params as i32,
            domain: Some(domain_msg.clone()),
            keyset_config: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: Some((*DEFAULT_EPOCH_ID).into()),
            extra_data: default_isolated_extra_data(),
        };
        preproc_tasks.spawn(async move {
            cur_client
                .insecure_key_gen_preproc(tonic::Request::new(preproc_req))
                .await
        });
    }

    while let Some(res) = preproc_tasks.join_next().await {
        res??;
    }

    // Wait for the (instant) insecure preprocessing to be ready on all parties
    for client in clients.values() {
        retrying_poll(
            client.clone(),
            (*preproc_id).into(),
            "insecure preprocessing result",
            PollConfig::long_poll_config(),
            |client, request| {
                Box::pin(async move { client.get_insecure_key_gen_preproc_result(request).await })
            },
        )
        .await?;
    }

    Ok(())
}

/// Helper to generate threshold key using insecure mode.
///
/// This function first runs the insecure (dummy) preprocessing, then sends
/// insecure_key_gen requests to all clients and waits for key generation to
/// complete. It's designed for use with ThresholdTestEnv.
///
/// # Arguments
/// * `clients` - Map of party ID to gRPC client
/// * `request_id` - Unique identifier for this key generation request
/// * `params` - FHE parameters to use for key generation
/// * `keyset_config` - Optional keyset configuration (defaults to compressed when `None`)
/// * `keyset_added_info` - Optional migration info (e.g. for `UseExisting` keygen)
///
/// # Returns
/// * `Ok((preproc_id, responses))` - the preprocessing ID that was consumed and
///   per-party `(party_id, KeyGenResult)` for use with `verify_keygen_responses`
/// * `Err` if any party failed
pub async fn threshold_insecure_key_gen(
    clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    request_id: &kms_grpc::RequestId,
    params: kms_grpc::kms::v1::FheParameter,
    keyset_config: Option<kms_grpc::kms::v1::KeySetConfig>,
    keyset_added_info: Option<kms_grpc::kms::v1::KeySetAddedInfo>,
) -> anyhow::Result<(
    kms_grpc::RequestId,
    Vec<(
        u32,
        Result<tonic::Response<kms_grpc::kms::v1::KeyGenResult>, tonic::Status>,
    )>,
)> {
    let domain_msg = domain_to_msg(&dummy_domain());

    // The insecure keygen requires an existing preprocessing ID,
    // so run the insecure (dummy) preprocessing first.
    let preproc_id = derive_request_id(&format!("insecure-preproc-{request_id}"))?;
    run_insecure_preproc(clients, &preproc_id, params).await?;

    let mut keygen_tasks = JoinSet::new();
    for client in clients.values() {
        let mut cur_client = client.clone();
        let keygen_req = KeyGenRequest {
            request_id: Some((*request_id).into()),
            params: Some(params as i32),
            preproc_id: Some(preproc_id.into()),
            domain: Some(domain_msg.clone()),
            keyset_config,
            keyset_added_info: keyset_added_info.clone(),
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
        let result = retrying_poll(
            client.clone(),
            (*request_id).into(),
            "insecure keygen result",
            PollConfig::long_poll_config(),
            |client, request| {
                Box::pin(async move { client.get_insecure_key_gen_result(request).await })
            },
        )
        .await;
        responses.push((*party_id, result));
    }

    Ok((preproc_id, responses))
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
#[allow(clippy::too_many_arguments)]
pub async fn threshold_secure_key_gen(
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
    // Note: Isolated callers always use the default context/epoch; if that ever changes
    // we'd need to resolve `context_id` / `epoch_id` to concrete ids and rebuild
    // extra_data via `make_extra_data` so the signed bytes stay consistent.
    assert!(
        context_id.is_none() && epoch_id.is_none(),
        "threshold_secure_key_gen_isolated only supports default context/epoch ids"
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
        retrying_poll(
            client.clone(),
            (*preproc_id).into(),
            "preprocessing result",
            PollConfig::long_poll_config(),
            |client, request| {
                Box::pin(async move { client.get_key_gen_preproc_result(request).await })
            },
        )
        .await?;
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

    // Wait for key generation to complete and collect responses.
    let mut responses = Vec::new();
    for (party_id, client) in clients.iter() {
        let result = retrying_poll(
            client.clone(),
            (*keygen_id).into(),
            "keygen result",
            PollConfig::long_poll_config(),
            |client, request| Box::pin(async move { client.get_key_gen_result(request).await }),
        )
        .await;
        responses.push((*party_id, result));
    }

    Ok(responses)
}
