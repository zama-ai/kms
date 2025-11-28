use crate::s3_operations::fetch_elements;
use crate::{
    dummy_domain, CmdConfig, CoreClientConfig, SharedKeyGenParameters,
    SLEEP_TIME_BETWEEN_REQUESTS_MS,
};
use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use kms_grpc::kms::v1::{FheParameter, KeyGenResult};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::{protobuf_to_alloy_domain, PubDataType};
use kms_grpc::solidity_types::KeygenVerification;
use kms_grpc::RequestId;
use kms_lib::client::client_wasm::Client;
use kms_lib::conf;
use kms_lib::cryptography::signatures::recover_address_from_ext_signature;
use kms_lib::engine::base::{safe_serialize_hash_element_versioned, DSEP_PUBDATA_KEY};
use kms_lib::util::key_setup::test_tools::{load_material_from_storage, load_pk_from_storage};
use std::collections::HashMap;
use std::path::Path;
use tfhe::{CompactPublicKey, ServerKey};
use tokio::task::JoinSet;
use tonic::transport::Channel;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_keygen(
    internal_client: &mut Client,
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    rng: &mut AesRng,
    cc_conf: &CoreClientConfig,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    kms_addrs: &[alloy_primitives::Address],
    param: FheParameter,
    preproc_id: RequestId,
    insecure: bool,
    shared_config: &SharedKeyGenParameters,
    destination_prefix: &Path,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    let num_expected_responses = if cmd_conf.expect_all_responses {
        num_parties
    } else {
        cc_conf.num_majority
    };

    //NOTE: If we do not use dummy_domain here, then
    //this needs changing too in the KeyGenResult command.
    let keyset_config =
        shared_config
            .keyset_type
            .clone()
            .map(|x| kms_grpc::kms::v1::KeySetConfig {
                keyset_type: kms_grpc::kms::v1::KeySetType::from(x) as i32,
                standard_keyset_config: None,
            });
    let dkg_req = internal_client.key_gen_request(
        &req_id,
        &preproc_id,
        shared_config.context_id.as_ref(),
        shared_config.epoch_id.as_ref(),
        Some(param),
        keyset_config,
        None,
        dummy_domain(),
    )?;

    //NOTE: Extract domain from request for sanity, but if we don't use dummy_domain
    //we have an issue in the (Insecure)KeyGenResult commands
    let domain = if let Some(domain) = &dkg_req.domain {
        protobuf_to_alloy_domain(domain)?
    } else {
        return Err(anyhow::anyhow!("No domain provided in crsgen request"));
    };

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for (_party_id, ce) in core_endpoints.iter() {
        let req_cloned = dkg_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            if insecure {
                cur_client
                    .insecure_key_gen(tonic::Request::new(req_cloned))
                    .await
            } else {
                cur_client.key_gen(tonic::Request::new(req_cloned)).await
            }
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(req_response_vec.len(), num_parties); // check that the request has reached all parties

    // get all responses
    let resp_response_vec = get_keygen_responses(
        core_endpoints,
        req_id,
        max_iter,
        insecure,
        num_expected_responses,
    )
    .await?;

    fetch_and_check_keygen(
        num_expected_responses,
        cc_conf,
        kms_addrs,
        destination_prefix,
        req_id,
        domain,
        resp_response_vec,
        cmd_conf.download_all,
    )
    .await?;

    Ok(req_id)
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn fetch_and_check_keygen(
    num_expected_responses: usize,
    cc_conf: &CoreClientConfig,
    kms_addrs: &[alloy_primitives::Address],
    destination_prefix: &Path,
    request_id: RequestId,
    domain: Eip712Domain,
    responses: Vec<KeyGenResult>,
    download_all: bool,
) -> anyhow::Result<()> {
    assert!(
        responses.len() >= num_expected_responses,
        "Expected at least {} responses, but got only {}",
        num_expected_responses,
        responses.len()
    );

    // Download the generated keys.
    let key_types = vec![
        PubDataType::PublicKey,
        PubDataType::PublicKeyMetadata,
        PubDataType::ServerKey,
    ];

    let party_ids = fetch_elements(
        &request_id.to_string(),
        &key_types,
        cc_conf,
        destination_prefix,
        download_all,
    )
    .await?;
    let first_party_id = *party_ids.first().unwrap() as usize;

    // [party_ids] are the logical party IDs, not the party IDs that define storage locations.
    // Here we convert it to the storage party ID if the kms config is provided.
    let storage_party_id = {
        #[cfg(feature = "testing")]
        match cc_conf.cores[first_party_id - 1].config_path {
            Some(ref p) => {
                let core_config: conf::CoreConfig =
                    conf::init_conf(p.to_str().expect("expect core config path")).unwrap();
                core_config
                    .threshold
                    .expect("expect threshold config")
                    .my_id
            }
            None => first_party_id,
        }
        #[cfg(not(feature = "testing"))]
        first_party_id
    };

    // Even if we did not download all keys, we still check that they are identical
    // by checking all signatures against the first downloaded keyset.
    // If all signatures match, then all keys must be identical.
    let public_key =
        load_pk_from_storage(Some(destination_prefix), &request_id, storage_party_id).await;
    let server_key: ServerKey = load_material_from_storage(
        Some(destination_prefix),
        &request_id,
        PubDataType::ServerKey,
        storage_party_id,
    )
    .await;

    for response in responses {
        let resp_req_id: RequestId = response.request_id.try_into()?;
        tracing::info!("Received KeyGenResult with request ID {}", resp_req_id); //TODO print key digests and signatures?

        assert_eq!(
            request_id, resp_req_id,
            "Request ID of response does not match the transaction"
        );

        let external_signature = response.external_signature;
        let prep_id = response.preprocessing_id.ok_or(anyhow::anyhow!(
            "No preprocessing ID in keygen response, cannot verify external signature"
        ))?;
        check_standard_keyset_ext_signature(
            &public_key,
            &server_key,
            &prep_id.try_into()?,
            &request_id,
            &external_signature,
            &domain,
            kms_addrs,
        )
        .inspect_err(|e| tracing::error!("signature check failed: {}", e))?;

        tracing::info!("EIP712 verification of Public Key and Server Key successful.");
    }
    Ok(())
}

pub(crate) async fn get_keygen_responses(
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    request_id: RequestId,
    max_iter: usize,
    insecure: bool,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<KeyGenResult>> {
    // get all responses
    let mut resp_tasks = JoinSet::new();
    //We use enumerate to be able to sort the responses so they are determinstic for a given config
    for (core_id, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let core_id = *core_id; // Copy the key so it is owned in the async block

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete decryption
            tokio::time::sleep(tokio::time::Duration::from_millis(
                SLEEP_TIME_BETWEEN_REQUESTS_MS,
            ))
            .await;

            let mut response = if insecure {
                cur_client
                    .get_insecure_key_gen_result(tonic::Request::new(request_id.into()))
                    .await
            } else {
                cur_client
                    .get_key_gen_result(tonic::Request::new(request_id.into()))
                    .await
            };

            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    SLEEP_TIME_BETWEEN_REQUESTS_MS,
                ))
                .await;
                assert!(ctr < max_iter, "timeout while waiting for keygen after {max_iter} retries (insecure: {insecure})");
                ctr += 1;
                response = if insecure {
                    cur_client
                        .get_insecure_key_gen_result(tonic::Request::new(request_id.into()))
                        .await
                } else {
                    cur_client
                        .get_key_gen_result(tonic::Request::new(request_id.into()))
                        .await
                };

                tracing::info!(
                    "Got response for insecure keygen: {:?} (insecure: {insecure})",
                    response
                );
            }
            (core_id, request_id, response.unwrap().into_inner())
        });
    }

    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        let (core_id, _request_id, resp) = resp?;
        resp_response_vec.push((core_id, resp));
        // break this loop and continue with the rest of the processing if we have enough responses
        if resp_response_vec.len() >= num_expected_responses {
            break;
        }
    }
    resp_response_vec.sort_by_key(|(id, _)| *id);
    let resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();
    Ok(resp_response_vec)
}

/// Check that the external signature on the keygen is valid, i.e. was made by one of the supplied addresses
pub(crate) fn check_standard_keyset_ext_signature(
    public_key: &CompactPublicKey,
    server_key: &ServerKey,
    prep_id: &RequestId,
    key_id: &RequestId,
    external_sig: &[u8],
    domain: &Eip712Domain,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    let server_key_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, server_key)?;
    let public_key_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, public_key)?;

    let sol_type = KeygenVerification::new(prep_id, key_id, server_key_digest, public_key_digest);
    let addr = recover_address_from_ext_signature(&sol_type, domain, external_sig)?;

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "External signature verification failed for keygen as it does not contain the right address!"
        ))
    }
}
