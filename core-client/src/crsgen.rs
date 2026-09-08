use crate::s3_operations::fetch_public_elements;
use crate::{
    CmdConfig, CoreClientConfig, CoreConf, SLEEP_TIME_BETWEEN_REQUESTS_MS, SigVerificationMaterial,
};

use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use hashing::hash_versioned;
use kms_grpc::kms::v1::{CrsGenResult, FheParameter, TypedSignature};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::{ContextId, EpochId, RequestId};
use kms_lib::client::client_wasm::Client;
use kms_lib::engine::base::{DSEP_PUBDATA_CRS, crs_payload_bytes, crs_sol_type};
use kms_lib::util::key_setup::test_tools::load_material_from_pub_storage;
use std::collections::HashMap;
use std::path::Path;
use tfhe::zk::CompactPkeCrs;
use threshold_execution::zk::ceremony::max_num_bits_from_crs;
use tokio::task::JoinSet;
use tonic::Code;
use tonic::transport::Channel;

#[expect(clippy::too_many_arguments)]
pub(crate) async fn do_crsgen(
    internal_client: &mut Client,
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    rng: &mut AesRng,
    cc_conf: &CoreClientConfig,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    max_num_bits: Option<u32>,
    param: FheParameter,
    insecure: bool,
    destination_prefix: &Path,
    context_id: Option<ContextId>,
    epoch_id: Option<EpochId>,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    let num_expected_responses = if cmd_conf.expect_all_responses {
        num_parties
    } else {
        cc_conf.num_majority
    };

    // The EIP-712 domain comes from the config (falling back to `dummy_domain`),
    // so the request built here and a later (Insecure)CrsGenResult fetch verify
    // against the same domain.
    let domain = cc_conf.default_domain()?;
    let crs_req = internal_client.crs_gen_request(
        &req_id,
        context_id.as_ref(),
        epoch_id.as_ref(),
        max_num_bits,
        Some(param),
        &domain,
    )?;
    let extra_data = crs_req.extra_data.clone();

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for ce in core_endpoints.values() {
        let req_cloned = crs_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            if insecure {
                cur_client
                    .insecure_crs_gen(tonic::Request::new(req_cloned))
                    .await
            } else {
                cur_client.crs_gen(tonic::Request::new(req_cloned)).await
            }
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        match inner {
            Ok(Ok(resp)) => req_response_vec.push(resp.into_inner()),
            Ok(Err(e)) => {
                tracing::warn!("CRS gen request to a core failed: {e}");
            }
            Err(e) => {
                tracing::warn!("Error in CRS gen request: {e}");
            }
        }
    }
    if req_response_vec.len() < num_expected_responses {
        anyhow::bail!(
            "Only {}/{} CRS gen requests succeeded, need at least {}",
            req_response_vec.len(),
            num_parties,
            num_expected_responses
        );
    }

    // get all responses
    let resp_response_vec = get_crsgen_responses(
        core_endpoints,
        req_id,
        max_iter,
        insecure,
        num_expected_responses,
    )
    .await?;

    fetch_and_check_crsgen(
        num_expected_responses,
        cc_conf,
        internal_client,
        destination_prefix,
        req_id,
        Some(SigVerificationMaterial { domain, extra_data }),
        resp_response_vec,
        cmd_conf.download_all,
    )
    .await?;

    Ok(req_id)
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn fetch_and_check_crsgen(
    num_expected_responses: usize,
    cc_conf: &CoreClientConfig,
    internal_client: &Client,
    destination_prefix: &Path,
    request_id: RequestId,
    // EIP-712 domain + extra_data to verify the external signature against. When
    // `None`, the CRS is still downloaded and request IDs checked, but the
    // external signature is not verified (an error is logged).
    verify: Option<SigVerificationMaterial>,
    responses: Vec<CrsGenResult>,
    download_all: bool,
) -> anyhow::Result<()> {
    if responses.len() < num_expected_responses {
        anyhow::bail!(
            "Expected at least {} CRS gen responses, but got only {}",
            num_expected_responses,
            responses.len()
        );
    }

    // Download the generated CRS.
    let party_confs = fetch_public_elements(
        &request_id.to_string(),
        &[PubDataType::CRS],
        cc_conf,
        destination_prefix,
        download_all,
    )
    .await?;

    let core_config = cc_conf
        .cores
        .iter()
        .find(|c| c == &&party_confs[0])
        .ok_or_else(|| {
            anyhow::anyhow!(
                "core client config not found for party {:?} in CRS gen",
                party_confs[0].party_id
            )
        })?;

    // Even if we did not download all CRSes, we still check that they are identical
    // by checking all signatures against the first downloaded CRS.
    // If all signatures match, then all CRSes must be identical.
    let crs: CompactPkeCrs = load_material_from_pub_storage(
        Some(destination_prefix),
        &request_id,
        PubDataType::CRS,
        Some(core_config.object_folder.as_str()),
    )
    .await;

    for response in responses {
        let resp_req_id: RequestId = response.request_id.try_into()?;
        tracing::info!(
            "Received CrsGenResult with request ID {}. Signature:{}. Digest:{}",
            resp_req_id,
            hex::encode(&response.crs_digest),
            hex::encode(crate::ecdsa_signature(&response.signatures).unwrap_or_default())
        );

        if request_id != resp_req_id {
            anyhow::bail!(
                "Request ID of CRS gen response ({}) does not match the request ({})",
                resp_req_id,
                request_id
            );
        }

        match verify.as_ref() {
            Some(material) => {
                check_crsgen_signatures(
                    internal_client,
                    &crs,
                    &request_id,
                    &response.signatures,
                    &material.domain,
                    material.extra_data.clone(),
                )
                .inspect_err(|e| tracing::error!("CRS signature check failed: {}", e))?;

                tracing::info!("Verification of every requested CRS signature successful.");
            }
            None => {
                tracing::error!(
                    "CRS gen result for request {} fetched WITHOUT signature verification \
                     (no EIP-712 domain supplied).",
                    request_id
                );
            }
        }
    }
    Ok(())
}

pub(crate) async fn get_crsgen_responses(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    request_id: RequestId,
    max_iter: usize,
    insecure: bool,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<CrsGenResult>> {
    // get all responses
    let mut resp_tasks = JoinSet::new();
    for (core_conf, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let core_conf = core_conf.clone();

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete crs generation
            tokio::time::sleep(tokio::time::Duration::from_millis(SLEEP_TIME_BETWEEN_REQUESTS_MS)).await;

            let mut response = if insecure {
                cur_client
                    .get_insecure_crs_gen_result(tonic::Request::new(request_id.into()))
                    .await
            } else {
                cur_client
                    .get_crs_gen_result(tonic::Request::new(request_id.into()))
                    .await
            };

            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(SLEEP_TIME_BETWEEN_REQUESTS_MS)).await;
                // do at most max_iter retries
                if ctr >= max_iter {
                    anyhow::bail!(
                        "timeout while waiting for CRS gen from party {:?} after {max_iter} retries (insecure: {insecure})",
                        core_conf.party_id
                    );
                }
                ctr += 1;
                response = if insecure {
                    cur_client
                        .get_insecure_crs_gen_result(tonic::Request::new(request_id.into()))
                        .await
                } else {
                    cur_client
                        .get_crs_gen_result(tonic::Request::new(request_id.into()))
                        .await
                };

                tracing::info!("Got response for crsgen: {:?} (insecure: {insecure})", response);
            }
            let resp = response.map_err(|e| {
                anyhow::anyhow!("CRS gen response from party {:?} failed: {e}", core_conf.party_id)
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
                tracing::warn!("A core failed to return CRS gen result: {e}");
            }
            Err(e) => {
                tracing::warn!("Error in CRS gen response: {e}");
            }
        }
        // break this loop and continue with the rest of the processing if we have enough responses
        if resp_response_vec.len() >= num_expected_responses {
            break;
        }
    }
    if resp_response_vec.len() < num_expected_responses {
        anyhow::bail!(
            "Only got {}/{} CRS gen responses, need at least {}",
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

/// Check every signature the CRS result carries, under every scheme the client
/// requested, and that it was produced by one of the known KMS parties.
fn check_crsgen_signatures(
    internal_client: &Client,
    crs: &CompactPkeCrs,
    crs_id: &RequestId,
    signatures: &[TypedSignature],
    domain: &Eip712Domain,
    extra_data: Vec<u8>,
) -> anyhow::Result<()> {
    let crs_digest = hash_versioned(&DSEP_PUBDATA_CRS, crs)?;

    tracing::info!(
        "Checking the signatures on a CRS gen result. crs_id={},digest={}",
        crs_id,
        hex::encode(&crs_digest),
    );

    let max_num_bits = max_num_bits_from_crs(crs) as u32;
    let sol_type = crs_sol_type(crs_id, &crs_digest, max_num_bits, &extra_data);
    let payload_bytes = crs_payload_bytes(crs_id, max_num_bits, &crs_digest, &extra_data)?;
    internal_client
        .verify_result_signatures(
            signatures,
            &sol_type,
            domain,
            &DSEP_PUBDATA_CRS,
            &payload_bytes,
        )
        .map(|(party_id, _address)| {
            tracing::info!("CRS gen result verified as produced by party {party_id}");
        })
}

pub(crate) async fn do_abort_crs_gen(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    request_id: RequestId,
    max_iter: usize,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<String>> {
    // get all responses
    let mut resp_tasks = JoinSet::new();
    for ce in core_endpoints.values() {
        let mut cur_client = ce.clone();

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete CRS generation
            tokio::time::sleep(tokio::time::Duration::from_millis(
                SLEEP_TIME_BETWEEN_REQUESTS_MS,
            ))
            .await;

            let mut response = cur_client
                .abort_crs_gen(tonic::Request::new(request_id.into()))
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
                    .abort_crs_gen(tonic::Request::new(request_id.into()))
                    .await;
                tracing::info!("Got response for abort_crs_gen: {:?}", response);
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
                tracing::warn!("Join error in abort CRS gen response: {e}");
            }
        }
        // break this loop and continue with the rest of the processing if we have enough responses
        if resp_response_vec.len() >= num_expected_responses {
            break;
        }
    }
    if resp_response_vec.len() < num_expected_responses {
        anyhow::bail!(
            "Only got {}/{} abort CRS gen responses, need at least {}",
            resp_response_vec.len(),
            core_endpoints.len(),
            num_expected_responses
        );
    }
    Ok(resp_response_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_grpc::{rpc_types::{PrivDataType, ecdsa_signatures}, solidity_types::CrsgenVerification};
    use kms_lib::{
        consts::{
            DEFAULT_EPOCH_ID, SIGNING_KEY_ID, TEST_CENTRAL_CRS_ID, TEST_PARAM, default_extra_data,
        },
        cryptography::signatures::{
            PrivateSigKey, PublicSigKey, compute_eip712_signature, gen_sig_keys,
        },
        util::key_setup::{ensure_central_crs_exists, ensure_central_server_signing_keys_exist},
        vault::storage::{ram::RamStorage, read_versioned_at_request_id},
    };
    use rand::SeedableRng;
    use std::str::FromStr;
    use tfhe::zk::CompactPkeCrs;
    use threshold_execution::zk::ceremony::max_num_bits_from_crs;

    /// The error every failed ECDSA check now reports; see the keygen twin.
    const UNKNOWN_PARTY: &str = "belongs to no known party";

    fn client_knowing(pk: PublicSigKey) -> Client {
        let address = pk.address();
        Client::new(
            HashMap::from([(1, pk)]),
            HashMap::new(),
            address,
            None,
            TEST_PARAM,
            None,
        )
    }

    #[tokio::test]
    async fn test_eip712_sigs() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        // make sure signing keys exist
        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();

        // compute a small CRS for testing
        let crs_id = &TEST_CENTRAL_CRS_ID;
        ensure_central_crs_exists(
            &mut pub_storage,
            &mut priv_storage,
            TEST_PARAM,
            crs_id,
            &DEFAULT_EPOCH_ID,
            true,
        )
        .await;
        let crs: CompactPkeCrs = read_versioned_at_request_id(
            &pub_storage,
            &RequestId::from_str(&crs_id.to_string()).unwrap(),
            &PubDataType::CRS.to_string(),
        )
        .await
        .unwrap();

        // read generated private signature key, derive public verifcation key and address from it
        let sk: PrivateSigKey = read_versioned_at_request_id(
            &priv_storage,
            &RequestId::from_str(&SIGNING_KEY_ID.to_string()).unwrap(),
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        let client = client_knowing(sk.verf_key());

        // set up a dummy EIP 712 domain
        let domain = alloy_sol_types::eip712_domain!(
            name: "dummy-test",
            version: "1",
            chain_id: 0,
            verifying_contract: alloy_primitives::Address::ZERO,
            // No salt
        );

        let max_num_bits = max_num_bits_from_crs(&crs);
        let crs_digest =
            hash_versioned(&DSEP_PUBDATA_CRS, &crs).expect("serialization should succeed");
        let crs_sol_struct =
            CrsgenVerification::new(crs_id, max_num_bits, crs_digest.clone(), vec![]);
        let crs_sol_struct_extra_data =
            CrsgenVerification::new(crs_id, max_num_bits, crs_digest, default_extra_data());

        // sign with EIP712
        let external_sig = compute_eip712_signature(&sk, &crs_sol_struct, &domain)
            .expect("signature computation should succeed");
        let external_sig_extra_data =
            compute_eip712_signature(&sk, &crs_sol_struct_extra_data, &domain)
                .expect("signature computation should succeed");

        // check that the signature verifies and unwraps without error
        check_crsgen_signatures(
            &client,
            &crs,
            crs_id,
            &ecdsa_signatures(external_sig.clone()),
            &domain,
            vec![],
        )
        .expect("signature should be valid");
        check_crsgen_signatures(
            &client,
            &crs,
            crs_id,
            &ecdsa_signatures(external_sig_extra_data),
            &domain,
            default_extra_data(),
        )
        .expect("signature should be valid");

        // An empty list is rejected outright: a request that names no scheme
        // still asks for ECDSA, so the entry has to be there.
        assert!(
            check_crsgen_signatures(&client, &crs, crs_id, &[], &domain, vec![])
                .unwrap_err()
                .to_string()
                .contains("carries no signatures")
        );

        // check that verification fails for a client that knows another party
        let mut rng = AesRng::seed_from_u64(0xBEEF);
        let stranger = client_knowing(gen_sig_keys(&mut rng).0);
        assert!(
            check_crsgen_signatures(
                &stranger,
                &crs,
                crs_id,
                &ecdsa_signatures(external_sig.clone()),
                &domain,
                vec![],
            )
            .unwrap_err()
            .to_string()
            .contains(UNKNOWN_PARTY)
        );

        // A signature that is too short, is not a signature at all, or does not
        // cover this message all fail the same way: no known party's address can
        // be recovered from it.
        let short_sig = [0_u8; 37].to_vec();
        let malformed_sig = [23_u8; 65].to_vec();
        let wrong_sig = hex::decode("cf92fe4c0b7c72fd8571c9a6680f2cd7481ebed7a3c8c7c7a6e6eaf27f5654f36100c146e609e39950953602ed73a3c10c1672729295ed8b33009b375813e5801b").unwrap();
        for (label, bad_sig) in [
            ("too short", short_sig),
            ("malformed", malformed_sig),
            ("wrong message", wrong_sig),
        ] {
            let err = check_crsgen_signatures(
                &client,
                &crs,
                crs_id,
                &ecdsa_signatures(bad_sig),
                &domain,
                vec![],
            )
            .unwrap_err()
            .to_string();
            assert!(
                err.contains(UNKNOWN_PARTY),
                "a {label} signature was not rejected as expected: {err}"
            );
        }
    }
}
