use crate::s3_operations::fetch_public_elements;
use crate::{
    CmdConfig, CoreClientConfig, CoreConf, PartialKeyGenPreprocParameters,
    SLEEP_TIME_BETWEEN_REQUESTS_MS, SharedKeyGenParameters, dummy_domain,
};
use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use kms_grpc::identifiers::EpochId;
use kms_grpc::kms::v1::{FheParameter, KeyGenPreprocResult, KeyGenResult};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::{PubDataType, protobuf_to_alloy_domain};
use kms_grpc::solidity_types::KeygenVerification;
use kms_grpc::{ContextId, RequestId};
use kms_lib::client::client_wasm::Client;
use kms_lib::cryptography::signatures::recover_address_from_ext_signature;
use kms_lib::engine::base::{DSEP_PUBDATA_KEY, safe_serialize_hash_element_versioned};
use kms_lib::util::key_setup::test_tools::{
    load_material_from_pub_storage, load_pk_from_pub_storage,
};
use std::collections::HashMap;
use std::path::Path;
use tfhe::{CompactPublicKey, ServerKey};
use tokio::task::JoinSet;
use tonic::Code;
use tonic::transport::Channel;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicKeyConfig {
    Compressed,
    Uncompressed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretKeyConfig {
    GenerateAll,
    UseExisting,
}

/// Build an explicit standard `KeySetConfig`.
pub(crate) fn build_standard_keyset_config(
    public_key_config: PublicKeyConfig,
    secret_key_config: SecretKeyConfig,
) -> kms_grpc::kms::v1::KeySetConfig {
    kms_grpc::kms::v1::KeySetConfig {
        keyset_type: kms_grpc::kms::v1::KeySetType::Standard as i32,
        standard_keyset_config: Some(kms_grpc::kms::v1::StandardKeySetConfig {
            compute_key_type: 0, // CPU
            secret_key_config: match secret_key_config {
                SecretKeyConfig::GenerateAll => {
                    kms_grpc::kms::v1::KeyGenSecretKeyConfig::GenerateAll as i32
                }
                SecretKeyConfig::UseExisting => {
                    kms_grpc::kms::v1::KeyGenSecretKeyConfig::UseExisting as i32
                }
            },
            compressed_key_config: match public_key_config {
                PublicKeyConfig::Compressed => {
                    kms_grpc::kms::v1::CompressedKeyConfig::CompressedAll
                }
                PublicKeyConfig::Uncompressed => {
                    kms_grpc::kms::v1::CompressedKeyConfig::CompressedNone
                }
            }
            .into(),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_keygen(
    internal_client: &mut Client,
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
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

    // NOTE: If we do not use dummy_domain here, then
    // this needs changing too in the KeyGenResult command.
    let use_existing = shared_config.existing_keyset_id.is_some();
    let keyset_config = Some(build_standard_keyset_config(
        if shared_config.uncompressed {
            PublicKeyConfig::Uncompressed
        } else {
            PublicKeyConfig::Compressed
        },
        if use_existing {
            SecretKeyConfig::UseExisting
        } else {
            SecretKeyConfig::GenerateAll
        },
    ));
    let keyset_added_info =
        shared_config
            .existing_keyset_id
            .map(|id| kms_grpc::kms::v1::KeySetAddedInfo {
                existing_keyset_id: Some(id.into()),
                use_existing_key_tag: shared_config.use_existing_key_tag,
                copy_compressed_key_to_original: shared_config.copy_compressed_key_to_original,
                ..Default::default()
            });
    let dkg_req = internal_client.key_gen_request(
        &req_id,
        &preproc_id,
        shared_config.context_id.as_ref(),
        shared_config.epoch_id.as_ref(),
        Some(param),
        keyset_config,
        keyset_added_info,
        dummy_domain(),
    )?;
    let extra_data = dkg_req.extra_data.clone();

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
        match inner {
            Ok(Ok(resp)) => req_response_vec.push(resp.into_inner()),
            Ok(Err(e)) => {
                tracing::warn!("Keygen request to a core failed: {e}");
            }
            Err(e) => {
                tracing::warn!("Keygen request task panicked: {e}");
            }
        }
    }
    if req_response_vec.len() < num_expected_responses {
        anyhow::bail!(
            "Only {}/{} keygen requests succeeded, need at least {}",
            req_response_vec.len(),
            num_parties,
            num_expected_responses
        );
    }

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
        extra_data,
        resp_response_vec,
        cmd_conf.download_all,
        shared_config.uncompressed,
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
    extra_data: Vec<u8>,
    responses: Vec<KeyGenResult>,
    download_all: bool,
    uncompressed: bool,
) -> anyhow::Result<()> {
    if responses.len() < num_expected_responses {
        anyhow::bail!(
            "Expected at least {} keygen responses, but got only {}",
            num_expected_responses,
            responses.len()
        );
    }

    // Download the generated keys.
    let key_types = if uncompressed {
        vec![PubDataType::PublicKey, PubDataType::ServerKey]
    } else {
        vec![PubDataType::CompressedXofKeySet, PubDataType::PublicKey]
    };

    let party_confs = fetch_public_elements(
        &request_id.to_string(),
        &key_types,
        cc_conf,
        destination_prefix,
        download_all,
    )
    .await?;
    let first_party_id = party_confs
        .first()
        .ok_or_else(|| anyhow::anyhow!("no party configs returned from fetch_public_elements"))?
        .party_id as usize;
    let pub_storage_prefix = Some(cc_conf.cores[first_party_id - 1].object_folder.as_str());

    // Even if we did not download all keys, we still check that they are identical
    // by checking all signatures against the first downloaded keyset.
    // If all signatures match, then all keys must be identical.
    if !uncompressed {
        let compressed_keyset: tfhe::xof_key_set::CompressedXofKeySet =
            load_material_from_pub_storage(
                Some(destination_prefix),
                &request_id,
                PubDataType::CompressedXofKeySet,
                pub_storage_prefix,
            )
            .await;
        let compact_public_key =
            load_pk_from_pub_storage(Some(destination_prefix), &request_id, pub_storage_prefix)
                .await;

        for response in responses {
            let resp_req_id: RequestId = response.request_id.try_into()?;
            tracing::info!("Received KeyGenResult with request ID {}", resp_req_id);

            if request_id != resp_req_id {
                anyhow::bail!(
                    "Request ID of keygen response ({}) does not match the request ({})",
                    resp_req_id,
                    request_id
                );
            }

            let external_signature = response.external_signature;
            let prep_id = response.preprocessing_id.ok_or_else(|| {
                anyhow::anyhow!(
                    "No preprocessing ID in keygen response, cannot verify external signature"
                )
            })?;
            check_compressed_keyset_ext_signature(
                &compressed_keyset,
                &compact_public_key,
                &prep_id.try_into()?,
                &request_id,
                &external_signature,
                &domain,
                extra_data.clone(),
                kms_addrs,
            )
            .inspect_err(|e| tracing::error!("signature check failed: {}", e))?;

            tracing::info!("EIP712 verification of CompressedXofKeySet successful.");
        }
    } else {
        let public_key =
            load_pk_from_pub_storage(Some(destination_prefix), &request_id, pub_storage_prefix)
                .await;
        let server_key: ServerKey = load_material_from_pub_storage(
            Some(destination_prefix),
            &request_id,
            PubDataType::ServerKey,
            pub_storage_prefix,
        )
        .await;

        for response in responses {
            let resp_req_id: RequestId = response.request_id.try_into()?;
            tracing::info!("Received KeyGenResult with request ID {}", resp_req_id);

            if request_id != resp_req_id {
                anyhow::bail!(
                    "Request ID of keygen response ({}) does not match the request ({})",
                    resp_req_id,
                    request_id
                );
            }

            let external_signature = response.external_signature;
            let prep_id = response.preprocessing_id.ok_or_else(|| {
                anyhow::anyhow!(
                    "No preprocessing ID in keygen response, cannot verify external signature"
                )
            })?;
            check_uncompressed_keyset_ext_signature(
                &public_key,
                &server_key,
                &prep_id.try_into()?,
                &request_id,
                &external_signature,
                &domain,
                extra_data.clone(),
                kms_addrs,
            )
            .inspect_err(|e| tracing::error!("signature check failed: {}", e))?;

            tracing::info!("EIP712 verification of Public Key and Server Key successful.");
        }
    }
    Ok(())
}

pub(crate) async fn get_keygen_responses(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    request_id: RequestId,
    max_iter: usize,
    insecure: bool,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<KeyGenResult>> {
    // get all responses
    let mut resp_tasks = JoinSet::new();
    for (core_conf, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let core_conf = core_conf.clone();

        resp_tasks.spawn(async move {
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
                if ctr >= max_iter {
                    anyhow::bail!(
                        "timeout while waiting for keygen from party {:?} after {max_iter} retries (insecure: {insecure})",
                        core_conf.party_id
                    );
                }
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
            let resp = response.map_err(|e| {
                anyhow::anyhow!("keygen response from party {:?} failed: {e}", core_conf.party_id)
            })?;
            Ok((core_conf, request_id, resp.into_inner()))
        });
    }

    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        match resp {
            Ok(Ok((core_conf, _request_id, inner))) => {
                resp_response_vec.push((core_conf, inner));
            }
            Ok(Err(e)) => {
                tracing::warn!("A core failed to return keygen result: {e}");
            }
            Err(e) => {
                tracing::warn!("Keygen response task panicked: {e}");
            }
        }
        // break this loop and continue with the rest of the processing if we have enough responses
        if resp_response_vec.len() >= num_expected_responses {
            break;
        }
    }
    if resp_response_vec.len() < num_expected_responses {
        anyhow::bail!(
            "Only got {}/{} keygen responses, need at least {}",
            resp_response_vec.len(),
            core_endpoints.len(),
            num_expected_responses
        );
    }
    resp_response_vec.sort_by_key(|(conf, _)| conf.party_id);
    let resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();
    Ok(resp_response_vec)
}

pub(crate) async fn do_abort_key_gen(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    request_id: RequestId,
    max_iter: usize,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<String>> {
    // get all responses
    let mut resp_tasks = JoinSet::new();
    for (_core_conf, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();

        resp_tasks.spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(
                SLEEP_TIME_BETWEEN_REQUESTS_MS,
            ))
            .await;

            let mut response = cur_client
                .abort_key_gen(tonic::Request::new(request_id.into()))
                .await;
            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    SLEEP_TIME_BETWEEN_REQUESTS_MS,
                ))
                .await;
                // do at most max_iter retries
                if ctr >= max_iter {
                    return Err(Code::Unavailable);
                }
                ctr += 1;
                response = cur_client
                    .abort_key_gen(tonic::Request::new(request_id.into()))
                    .await;
                tracing::info!("Got response for abort_key_gen: {:?}", response);
            }
            response.map_err(|e| e.code())
        });
    }

    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        match resp {
            Ok(Ok(_)) => {
                resp_response_vec.push(Code::Ok.description().to_string());
            }
            Ok(Err(code)) => {
                resp_response_vec.push(code.description().to_string());
            }
            Err(e) => {
                tracing::warn!("Join error in abort key gen response: {e}");
            }
        }
        // break this loop and continue with the rest of the processing if we have enough responses
        if resp_response_vec.len() >= num_expected_responses {
            break;
        }
    }
    if resp_response_vec.len() < num_expected_responses {
        anyhow::bail!(
            "Only got {}/{} abort key gen responses, need at least {}",
            resp_response_vec.len(),
            core_endpoints.len(),
            num_expected_responses
        );
    }
    Ok(resp_response_vec)
}

/// Check that the external signature on the keygen is valid, i.e. was made by one of the supplied addresses
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_uncompressed_keyset_ext_signature(
    public_key: &CompactPublicKey,
    server_key: &ServerKey,
    prep_id: &RequestId,
    key_id: &RequestId,
    external_sig: &[u8],
    domain: &Eip712Domain,
    extra_data: Vec<u8>,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    let server_key_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, server_key)?;
    let public_key_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, public_key)?;

    tracing::info!(
        "Checking external signature for standard keyset: key_id={},preproc_id={},server_key_digest={},public_key_digest={}",
        key_id,
        prep_id,
        hex::encode(&server_key_digest),
        hex::encode(&public_key_digest)
    );

    let sol_type = KeygenVerification::new_uncompressed(
        prep_id,
        key_id,
        server_key_digest,
        public_key_digest,
        extra_data,
    );
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

/// Check external signature for compressed keyset
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_compressed_keyset_ext_signature(
    compressed_keyset: &tfhe::xof_key_set::CompressedXofKeySet,
    public_key: &CompactPublicKey,
    prep_id: &RequestId,
    key_id: &RequestId,
    external_sig: &[u8],
    domain: &Eip712Domain,
    extra_data: Vec<u8>,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    let keyset_digest =
        safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, compressed_keyset)?;
    let public_key_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, public_key)?;

    tracing::info!(
        "Checking external signature for compressed keyset: key_id={},preproc_id={},xof_keyset_digest={},public_key_digest={}",
        key_id,
        prep_id,
        hex::encode(&keyset_digest),
        hex::encode(&public_key_digest)
    );

    let sol_type = KeygenVerification::new_compressed(
        prep_id,
        key_id,
        keyset_digest,
        public_key_digest,
        extra_data,
    );
    let addr = recover_address_from_ext_signature(&sol_type, domain, external_sig)?;

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "External signature verification failed for compressed keygen"
        ))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_preproc(
    internal_client: &mut Client,
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    rng: &mut AesRng,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    fhe_params: FheParameter,
    context_id: Option<&ContextId>,
    epoch_id: Option<&EpochId>,
    keyset_config: Option<kms_grpc::kms::v1::KeySetConfig>,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    // NOTE: we use a dummy domain because preprocessing is triggered by the gateway in production
    // this function is only used for testing.
    let domain = dummy_domain();
    let pp_req = internal_client.preproc_request(
        &req_id,
        Some(fhe_params),
        context_id,
        epoch_id,
        keyset_config,
        &domain,
    )?;
    let extra_data = pp_req.extra_data.clone();

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for (_party_id, ce) in core_endpoints.iter() {
        let req_cloned = pp_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(req_cloned))
                .await
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        match inner {
            Ok(Ok(resp)) => req_response_vec.push(resp.into_inner()),
            Ok(Err(e)) => {
                tracing::warn!("Preproc request to a core failed: {e}");
            }
            Err(e) => {
                tracing::warn!("Preproc request task panicked: {e}");
            }
        }
    }
    if req_response_vec.len() < num_parties {
        anyhow::bail!(
            "Only {}/{} preproc requests succeeded",
            req_response_vec.len(),
            num_parties,
        );
    }

    let responses = get_preproc_keygen_responses(core_endpoints, req_id, max_iter).await?;
    for response in responses {
        // this part also verifies the signature
        internal_client.process_preproc_response(
            &req_id,
            &domain,
            &response,
            extra_data.clone(),
        )?;
    }

    Ok(req_id)
}

pub(crate) async fn do_partial_preproc(
    internal_client: &mut Client,
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    rng: &mut AesRng,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    fhe_params: FheParameter,
    preproc_params: &PartialKeyGenPreprocParameters,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    // NOTE: we use a dummy domain because preprocessing is triggered by the gateway in production
    // this function is only used for testing.
    let domain = dummy_domain();
    let pp_req = internal_client.partial_preproc_request(
        &req_id,
        Some(fhe_params),
        preproc_params.context_id.as_ref(),
        preproc_params.epoch_id.as_ref(),
        None,
        &domain,
        Some(kms_grpc::kms::v1::PartialKeyGenPreprocParams {
            percentage_offline: preproc_params.percentage_offline,
            store_dummy_preprocessing: preproc_params.store_dummy_preprocessing,
        }),
    )?;
    let extra_data = pp_req
        .base_request
        .as_ref()
        .map(|b| b.extra_data.clone())
        .unwrap_or_default();

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for (_party_id, ce) in core_endpoints.iter() {
        let req_cloned = pp_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .partial_key_gen_preproc(tonic::Request::new(req_cloned))
                .await
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        match inner {
            Ok(Ok(resp)) => req_response_vec.push(resp.into_inner()),
            Ok(Err(e)) => {
                tracing::warn!("Partial preproc request to a core failed: {e}");
            }
            Err(e) => {
                tracing::warn!("Partial preproc request task panicked: {e}");
            }
        }
    }
    if req_response_vec.len() < num_parties {
        anyhow::bail!(
            "Only {}/{} partial preproc requests succeeded",
            req_response_vec.len(),
            num_parties,
        );
    }

    let responses = get_preproc_keygen_responses(core_endpoints, req_id, max_iter).await?;
    for response in responses {
        internal_client.process_preproc_response(
            &req_id,
            &domain,
            &response,
            extra_data.clone(),
        )?;
    }

    Ok(req_id)
}

pub(crate) async fn get_preproc_keygen_responses(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    request_id: RequestId,
    max_iter: usize,
) -> anyhow::Result<Vec<KeyGenPreprocResult>> {
    let mut resp_tasks = JoinSet::new();
    for (core_conf, client) in core_endpoints.iter() {
        let mut client = client.clone();
        let core_conf = core_conf.clone(); // Copy the key so it is owned in the async block
        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete preprocessing
            tokio::time::sleep(tokio::time::Duration::from_millis(
                SLEEP_TIME_BETWEEN_REQUESTS_MS,
            ))
            .await;

            tracing::info!(
                "Polling preproc result for request {} from party {}",
                request_id, core_conf.party_id
            );
            let mut response = client
                .get_key_gen_preproc_result(tonic::Request::new(request_id.into()))
                .await;
            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    SLEEP_TIME_BETWEEN_REQUESTS_MS,
                ))
                .await;
                // do at most max_iter retries
                if ctr >= max_iter {
                    anyhow::bail!(
                        "timeout while waiting for preprocessing from party {:?} after {max_iter} retries.",
                        core_conf.party_id
                    );
                }
                ctr += 1;
                tracing::info!(
                    "Preproc result not ready yet for request {} from party {} (retry {}/{})",
                    request_id, core_conf.party_id, ctr, max_iter
                );
                response = client
                    .get_key_gen_preproc_result(tonic::Request::new(request_id.into()))
                    .await;
            }

            let resp = response.map_err(|e| {
                anyhow::anyhow!("preprocessing response from party {:?} failed: {e}", core_conf.party_id)
            })?;
            Ok((core_conf, request_id, resp.into_inner()))
        });
    }
    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        match resp {
            Ok(Ok((core_conf, _request_id, inner))) => {
                resp_response_vec.push((core_conf, inner));
            }
            Ok(Err(e)) => {
                tracing::warn!("A core failed to return preprocessing result: {e}");
            }
            Err(e) => {
                tracing::warn!("Preprocessing response task panicked: {e}");
            }
        }
    }
    if resp_response_vec.len() < core_endpoints.len() {
        anyhow::bail!(
            "Only got {}/{} preprocessing responses",
            resp_response_vec.len(),
            core_endpoints.len(),
        );
    }
    resp_response_vec.sort_by_key(|(conf, _)| conf.party_id);
    let resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();
    Ok(resp_response_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_grpc::rpc_types::{PrivDataType, PubDataType};
    use kms_lib::{
        consts::{
            DEFAULT_EPOCH_ID, OTHER_CENTRAL_TEST_ID, SIGNING_KEY_ID, TEST_CENTRAL_KEY_ID,
            TEST_PARAM, default_extra_data,
        },
        cryptography::signatures::{PrivateSigKey, compute_eip712_signature},
        engine::base::INSECURE_PREPROCESSING_ID,
        util::key_setup::{ensure_central_keys_exist, ensure_central_server_signing_keys_exist},
        vault::storage::{ram::RamStorage, read_versioned_at_request_id},
    };
    use std::str::FromStr;
    use tfhe::xof_key_set::CompressedXofKeySet;

    #[tokio::test]
    async fn test_eip712_sigs() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        // make sure signing keys exist
        ensure_central_server_signing_keys_exist(
            &mut pub_storage,
            &mut priv_storage,
            &SIGNING_KEY_ID,
            true,
        )
        .await;

        // generate a small FHE keyset for testing
        let key_id = &TEST_CENTRAL_KEY_ID;
        let prep_id = &INSECURE_PREPROCESSING_ID;
        ensure_central_keys_exist(
            &mut pub_storage,
            &mut priv_storage,
            TEST_PARAM,
            key_id,
            &OTHER_CENTRAL_TEST_ID,
            &DEFAULT_EPOCH_ID,
            true,
            false,
        )
        .await;
        let compressed_keyset: CompressedXofKeySet = read_versioned_at_request_id(
            &pub_storage,
            &RequestId::from_str(&key_id.to_string()).unwrap(),
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();
        let compact_public_key: tfhe::CompactPublicKey = read_versioned_at_request_id(
            &pub_storage,
            &RequestId::from_str(&key_id.to_string()).unwrap(),
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();

        // read generated private signature key, derive public verification key and address from it
        let sk: PrivateSigKey = read_versioned_at_request_id(
            &priv_storage,
            &RequestId::from_str(&SIGNING_KEY_ID.to_string()).unwrap(),
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        let addr = sk.address();

        // === compressed keyset signatures ===
        let compressed_keyset_digest =
            safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &compressed_keyset).unwrap();
        let public_key_digest =
            safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &compact_public_key).unwrap();
        let compressed_sol_struct = KeygenVerification::new_compressed(
            prep_id,
            key_id,
            compressed_keyset_digest.clone(),
            public_key_digest.clone(),
            vec![],
        );
        let compressed_sol_struct_extra_data = KeygenVerification::new_compressed(
            prep_id,
            key_id,
            compressed_keyset_digest,
            public_key_digest.clone(),
            default_extra_data(),
        );

        let compressed_sig = compute_eip712_signature(&sk, &compressed_sol_struct, &dummy_domain())
            .expect("signature computation should succeed");
        let compressed_sig_extra_data =
            compute_eip712_signature(&sk, &compressed_sol_struct_extra_data, &dummy_domain())
                .expect("signature computation should succeed");

        // check that the signature verifies and unwraps without error
        check_compressed_keyset_ext_signature(
            &compressed_keyset,
            &compact_public_key,
            prep_id,
            key_id,
            &compressed_sig,
            &dummy_domain(),
            vec![],
            &[addr],
        )
        .expect("signature should be valid");
        check_compressed_keyset_ext_signature(
            &compressed_keyset,
            &compact_public_key,
            prep_id,
            key_id,
            &compressed_sig_extra_data,
            &dummy_domain(),
            default_extra_data(),
            &[addr],
        )
        .expect("signature should be valid");

        // check that verification fails for a wrong address
        let wrong_address = alloy_primitives::address!("0EdA6bf26964aF942Eed9e03e53442D37aa960EE");
        assert!(
            check_compressed_keyset_ext_signature(
                &compressed_keyset,
                &compact_public_key,
                prep_id,
                key_id,
                &compressed_sig,
                &dummy_domain(),
                vec![],
                &[wrong_address]
            )
            .unwrap_err()
            .to_string()
            .contains("External signature verification failed for compressed keygen")
        );

        // check that verification fails for signature that is too short
        let short_sig = [0_u8; 37];
        assert!(
            check_compressed_keyset_ext_signature(
                &compressed_keyset,
                &compact_public_key,
                prep_id,
                key_id,
                &short_sig,
                &dummy_domain(),
                vec![],
                &[addr]
            )
            .unwrap_err()
            .to_string()
            .contains("Expected external signature of length 65 Bytes, but got 37")
        );

        // check that verification fails for a byte string that is not a signature
        let malformed_sig = [23_u8; 65];
        assert!(
            check_compressed_keyset_ext_signature(
                &compressed_keyset,
                &compact_public_key,
                prep_id,
                key_id,
                &malformed_sig,
                &dummy_domain(),
                vec![],
                &[addr]
            )
            .unwrap_err()
            .to_string()
            .contains("signature error")
        );

        // check that verification fails for a signature that does not match the message
        let wrong_sig = hex::decode("cf92fe4c0b7c72fd8571c9a6680f2cd7481ebed7a3c8c7c7a6e6eaf27f5654f36100c146e609e39950953602ed73a3c10c1672729295ed8b33009b375813e5801b").unwrap();
        assert!(
            check_compressed_keyset_ext_signature(
                &compressed_keyset,
                &compact_public_key,
                prep_id,
                key_id,
                &wrong_sig,
                &dummy_domain(),
                vec![],
                &[addr]
            )
            .unwrap_err()
            .to_string()
            .contains("External signature verification failed for compressed keygen")
        );
    }
}
