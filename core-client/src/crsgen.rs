use crate::s3_operations::fetch_public_elements;
use crate::{dummy_domain, CmdConfig, CoreClientConfig, SLEEP_TIME_BETWEEN_REQUESTS_MS};
use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use kms_grpc::kms::v1::{CrsGenResult, FheParameter};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::{protobuf_to_alloy_domain, PubDataType};
use kms_grpc::solidity_types::CrsgenVerification;
use kms_grpc::RequestId;
use kms_lib::client::client_wasm::Client;
use kms_lib::cryptography::signatures::recover_address_from_ext_signature;
use kms_lib::engine::base::{safe_serialize_hash_element_versioned, DSEP_PUBDATA_CRS};
use kms_lib::util::key_setup::test_tools::load_material_from_storage;
use std::collections::HashMap;
use std::path::Path;
use tfhe::zk::CompactPkeCrs;
use threshold_fhe::execution::zk::ceremony::max_num_bits_from_crs;
use tokio::task::JoinSet;
use tonic::transport::Channel;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_crsgen(
    internal_client: &mut Client,
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    rng: &mut AesRng,
    cc_conf: &CoreClientConfig,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    kms_addrs: &[alloy_primitives::Address],
    max_num_bits: Option<u32>,
    param: FheParameter,
    insecure: bool,
    destination_prefix: &Path,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    let num_expected_responses = if cmd_conf.expect_all_responses {
        num_parties
    } else {
        cc_conf.num_majority
    };

    let crs_req =
        internal_client.crs_gen_request(&req_id, max_num_bits, Some(param), &dummy_domain())?;

    //NOTE: Extract domain from request for sanity, but if we don't use dummy_domain
    //we have an issue in the (Insecure)CrsGenResult commands
    let domain = if let Some(domain) = &crs_req.domain {
        protobuf_to_alloy_domain(domain)?
    } else {
        return Err(anyhow::anyhow!("No domain provided in crsgen request"));
    };

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for (_party_id, ce) in core_endpoints.iter() {
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
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(req_response_vec.len(), num_parties); // check that the request has reached all parties

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
pub(crate) async fn fetch_and_check_crsgen(
    num_expected_responses: usize,
    cc_conf: &CoreClientConfig,
    kms_addrs: &[alloy_primitives::Address],
    destination_prefix: &Path,
    request_id: RequestId,
    domain: Eip712Domain,
    responses: Vec<CrsGenResult>,
    download_all: bool,
) -> anyhow::Result<()> {
    assert!(
        responses.len() >= num_expected_responses,
        "Expected at least {} responses, but got only {}",
        num_expected_responses,
        responses.len()
    );

    // Download the generated CRS.
    let party_ids = fetch_public_elements(
        &request_id.to_string(),
        &[PubDataType::CRS],
        cc_conf,
        destination_prefix,
        download_all,
    )
    .await?;

    // Even if we did not download all CRSes, we still check that they are identical
    // by checking all signatures against the first downloaded CRS.
    // If all signatures match, then all CRSes must be identical.
    let crs: CompactPkeCrs = load_material_from_storage(
        Some(destination_prefix),
        &request_id,
        PubDataType::CRS,
        *party_ids.first().expect("no party IDs found"),
    )
    .await;

    for response in responses {
        let resp_req_id: RequestId = response.request_id.try_into()?;
        tracing::info!("Received CrsGenResult with request ID {}", resp_req_id); //TODO print key digests and signatures?

        assert_eq!(
            request_id, resp_req_id,
            "Request ID of response does not match the transaction"
        );
        let external_signature = response.external_signature;

        check_crsgen_ext_signature(&crs, &request_id, &external_signature, &domain, kms_addrs)
            .inspect_err(|e| tracing::error!("signature check failed: {}", e))?;

        tracing::info!("EIP712 verification of CRS successful.");
    }
    Ok(())
}

pub(crate) async fn get_crsgen_responses(
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    request_id: RequestId,
    max_iter: usize,
    insecure: bool,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<CrsGenResult>> {
    // get all responses
    let mut resp_tasks = JoinSet::new();
    //We use enumerate to be able to sort the responses so they are determinstic for a given config
    for (core_id, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let core_id = *core_id; // Copy the key so it is owned in the async block

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete decryption
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
                assert!(ctr < max_iter, "timeout while waiting for crsgen after {max_iter} retries (insecure: {insecure})");
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
            (core_id,request_id, response.unwrap().into_inner())
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

/// check that the external signature on the CRS is valid, i.e. was made by one of the supplied addresses
fn check_crsgen_ext_signature(
    crs: &CompactPkeCrs,
    crs_id: &RequestId,
    external_sig: &[u8],
    domain: &Eip712Domain,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    let crs_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_CRS, crs)?;

    let max_num_bits = max_num_bits_from_crs(crs);
    let sol_type = CrsgenVerification::new(crs_id, max_num_bits, crs_digest);
    let addr = recover_address_from_ext_signature(&sol_type, domain, external_sig)?;

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "External signature verification failed for crsgen as it does not contain the right address!"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_grpc::rpc_types::PrivDataType;
    use kms_lib::{
        consts::{SIGNING_KEY_ID, TEST_CENTRAL_CRS_ID, TEST_PARAM},
        cryptography::signatures::{compute_eip712_signature, PrivateSigKey},
        util::key_setup::{ensure_central_crs_exists, ensure_central_server_signing_keys_exist},
        vault::storage::{ram::RamStorage, read_versioned_at_request_id},
    };
    use std::str::FromStr;
    use tfhe::zk::CompactPkeCrs;
    use threshold_fhe::execution::zk::ceremony::max_num_bits_from_crs;

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

        // compute a small CRS for testing
        let crs_id = &TEST_CENTRAL_CRS_ID;
        ensure_central_crs_exists(
            &mut pub_storage,
            &mut priv_storage,
            TEST_PARAM,
            crs_id,
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
        let addr = sk.address();

        // set up a dummy EIP 712 domain
        let domain = alloy_sol_types::eip712_domain!(
            name: "dummy-test",
            version: "1",
            chain_id: 0,
            verifying_contract: alloy_primitives::Address::ZERO,
            // No salt
        );

        let max_num_bits = max_num_bits_from_crs(&crs);
        let crs_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_CRS, &crs)
            .expect("serialization should succeed");
        let crs_sol_struct = CrsgenVerification::new(crs_id, max_num_bits, crs_digest);

        // sign with EIP712
        let external_sig = compute_eip712_signature(&sk, &crs_sol_struct, &domain)
            .expect("signature computation should succeed");

        // check that the signature verifies and unwraps without error
        check_crsgen_ext_signature(&crs, crs_id, &external_sig, &domain, &[addr])
            .expect("signature should be valid");

        // check that verification fails for a wrong address
        let wrong_address = alloy_primitives::address!("0EdA6bf26964aF942Eed9e03e53442D37aa960EE");
        assert!(
            check_crsgen_ext_signature(&crs, crs_id, &external_sig, &domain, &[wrong_address])
                .unwrap_err()
                .to_string()
                .contains("External signature verification failed for crsgen as it does not contain the right address")
        );

        // check that verification fails for signature that is too short
        let short_sig = [0_u8; 37];
        assert!(
            check_crsgen_ext_signature(&crs, crs_id, &short_sig, &domain, &[addr])
                .unwrap_err()
                .to_string()
                .contains("Expected external signature of length 65 Bytes, but got 37")
        );

        // check that verification fails for a byte string that is not a signature
        let malformed_sig = [23_u8; 65];
        assert!(
            check_crsgen_ext_signature(&crs, crs_id, &malformed_sig, &domain, &[addr])
                .unwrap_err()
                .to_string()
                .contains("signature error")
        );

        // check that verification fails for a signature that does not match the message
        let wrong_sig = hex::decode("cf92fe4c0b7c72fd8571c9a6680f2cd7481ebed7a3c8c7c7a6e6eaf27f5654f36100c146e609e39950953602ed73a3c10c1672729295ed8b33009b375813e5801b").unwrap();
        assert!(
            check_crsgen_ext_signature(&crs, crs_id, &wrong_sig, &domain, &[addr])
                .unwrap_err()
                .to_string()
                .contains("External signature verification failed for crsgen as it does not contain the right address")
        );
    }
}
