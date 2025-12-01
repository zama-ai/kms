use crate::{
    dummy_domain, keygen::check_standard_keyset_ext_signature, s3_operations::fetch_elements,
    CmdConfig, CoreClientConfig, SLEEP_TIME_BETWEEN_REQUESTS_MS,
};
use aes_prng::AesRng;
use kms_grpc::{
    kms::v1::FheParameter,
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    rpc_types::PubDataType, RequestId,
};
use kms_lib::{
    client::client_wasm::Client,
    util::key_setup::test_tools::{load_material_from_storage, load_pk_from_storage},
};
use std::{collections::HashMap, path::Path};
use tfhe::ServerKey;
use tokio::task::JoinSet;
use tonic::transport::Channel;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_reshare(
    internal_client: &mut Client,
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    rng: &mut AesRng,
    cmd_conf: &CmdConfig,
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
    kms_addrs: &[alloy_primitives::Address],
    num_parties: usize,
    param: FheParameter,
    key_id: RequestId,
    preproc_id: RequestId,
) -> anyhow::Result<RequestId> {
    let max_iter = cmd_conf.max_iter;
    let request_id = RequestId::new_random(rng);
    // Create the request
    let request = internal_client.reshare_request(
        &request_id,
        &key_id,
        &preproc_id,
        Some(param),
        &dummy_domain(),
    )?;

    // Send the request
    let mut req_tasks = JoinSet::new();
    for (party_id, ce) in core_endpoints.iter() {
        let req_cloned = request.clone();
        let mut cur_client = ce.clone();
        let party_id = *party_id;
        req_tasks.spawn(async move {
            (
                party_id,
                cur_client
                    .initiate_resharing(tonic::Request::new(req_cloned))
                    .await,
            )
        });
    }

    let mut results = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        let (party_id, result) = inner?;
        let result = result?.into_inner();
        assert_eq!(result.request_id, Some(request_id.into()));
        results.push((party_id, result));
    }

    // We need to wait for all responses since a resharing is only successful if _all_ parties respond.
    assert_eq!(results.len(), num_parties);

    // Poll the result endpoint

    let mut response_tasks = JoinSet::new();
    for (party_id, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();

        let party_id = *party_id;
        response_tasks.spawn(async move {
            let response_request: tonic::Request<kms_grpc::kms::v1::RequestId> =
                tonic::Request::new(request_id.into());
            tokio::time::sleep(tokio::time::Duration::from_millis(
                SLEEP_TIME_BETWEEN_REQUESTS_MS,
            ))
            .await;
            let mut response = cur_client.get_resharing_result(response_request).await;

            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    SLEEP_TIME_BETWEEN_REQUESTS_MS,
                ))
                .await;
                let response_request: tonic::Request<kms_grpc::kms::v1::RequestId> =
                    tonic::Request::new(request_id.into());
                response = cur_client.get_resharing_result(response_request).await;
                ctr += 1;
                if ctr >= max_iter {
                    break;
                }
            }

            (party_id, response)
        });
    }

    let mut response_vec = Vec::new();
    while let Some(response) = response_tasks.join_next().await {
        let (party_id, resp) = response?;
        let resp = resp?.into_inner();
        assert_eq!(resp.request_id, Some(request_id.into()));
        assert_eq!(resp.key_id, Some(key_id.into()));
        assert_eq!(resp.preprocessing_id, Some(preproc_id.into()));
        response_vec.push((party_id, resp));
    }

    // Process and verify the responses
    assert_eq!(response_vec.len(), num_parties); // check that we have responses from all parties

    let key_types = vec![
        PubDataType::PublicKey,
        PubDataType::PublicKeyMetadata,
        PubDataType::ServerKey,
    ];
    // We try to download all because all parties needed to respond for a successful resharing
    let party_ids = fetch_elements(
        &key_id.to_string(),
        &key_types,
        cc_conf,
        destination_prefix,
        true,
    )
    .await?;

    assert_eq!(
        party_ids.len(),
        num_parties,
        "Did not fetch keys from all parties after resharing!"
    );

    let public_key = load_pk_from_storage(
        Some(destination_prefix),
        &key_id,
        *party_ids.first().expect("no party IDs found"),
    )
    .await;
    let server_key: ServerKey = load_material_from_storage(
        Some(destination_prefix),
        &key_id,
        PubDataType::ServerKey,
        *party_ids.first().expect("no party IDs found"),
    )
    .await;

    for response in response_vec {
        check_standard_keyset_ext_signature(
            &public_key,
            &server_key,
            &preproc_id,
            &key_id,
            &response.1.external_signature,
            &dummy_domain(),
            kms_addrs,
        )?;
    }
    Ok(request_id)
}
