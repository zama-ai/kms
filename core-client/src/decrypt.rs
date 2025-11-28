use crate::{dummy_domain, dummy_handle, print_timings, SLEEP_TIME_BETWEEN_REQUESTS_MS};
use alloy_sol_types::Eip712Domain;
use kms_grpc::{
    kms::v1::{PublicDecryptionRequest, PublicDecryptionResponse, TypedCiphertext, TypedPlaintext},
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    rpc_types::protobuf_to_alloy_domain,
    ContextId, KeyId, RequestId,
};
use kms_lib::cryptography::encryption::PkeSchemeType;
use kms_lib::{
    client::{client_wasm::Client, user_decryption_wasm::ParsedUserDecryptionRequest},
    cryptography::signatures::recover_address_from_ext_signature,
    engine::base::compute_public_decryption_message,
    util::key_setup::test_tools::TestingPlaintext,
};
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tonic::transport::Channel;

/// check that the external signature on the decryption result(s) is valid, i.e. was made by one of the supplied addresses
fn check_ext_pt_signature(
    external_sig: &[u8],
    plaintexts: &Vec<TypedPlaintext>,
    external_handles: Vec<Vec<u8>>,
    domain: Eip712Domain,
    kms_addrs: &[alloy_primitives::Address],
    extra_data: Vec<u8>,
) -> anyhow::Result<()> {
    tracing::debug!("PTs: {:?}", plaintexts);
    tracing::debug!("ext. handles: {:?}", external_handles);
    let message = compute_public_decryption_message(external_handles, plaintexts, extra_data)?;
    let addr = recover_address_from_ext_signature(&message, &domain, external_sig)?;
    tracing::info!("recovered address: {}", addr);

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "External PT signature verification failed!"
        ))
    }
}

fn check_external_decryption_signature(
    responses: &[PublicDecryptionResponse], // one response per party
    expected_answer: TypedPlaintext,
    external_handles: &[Vec<u8>],
    domain: &Eip712Domain,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    let mut results = Vec::new();
    for response in responses {
        let payload = response.payload.as_ref().unwrap();
        check_ext_pt_signature(
            &response.external_signature,
            &payload.plaintexts,
            external_handles.to_owned(),
            domain.clone(),
            kms_addrs,
            vec![],
        )?;

        for (idx, pt) in payload.plaintexts.iter().enumerate() {
            tracing::info!(
                "Decrypt Result #{idx}: Plaintext: {:?} (Bytes: {}).",
                pt,
                hex::encode(pt.bytes.as_slice()),
            );
            results.push(pt.clone());
        }
    }

    let tp_expected = TestingPlaintext::try_from(expected_answer)?;
    for result in results {
        assert_eq!(tp_expected, TestingPlaintext::try_from(result).unwrap());
    }

    tracing::info!("Decryption response successfully processed.");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_user_decrypt<R: Rng + CryptoRng>(
    rng: &mut R,
    num_requests: usize,
    internal_client: Arc<RwLock<Client>>,
    ct_batch: Vec<TypedCiphertext>,
    key_id: KeyId,
    context_id: Option<ContextId>,
    core_endpoints_req: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    core_endpoints_resp: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    ptxt: TypedPlaintext,
    num_parties: usize,
    max_iter: usize,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<(Option<RequestId>, String)>> {
    let mut join_set: JoinSet<Result<_, anyhow::Error>> = JoinSet::new();
    let mut timings_start = HashMap::new();
    let mut durations = Vec::new();
    let start = tokio::time::Instant::now();

    for _ in 0..num_requests {
        let req_id = RequestId::new_random(rng);
        let internal_client = internal_client.clone();
        let ct_batch = ct_batch.clone();
        let core_endpoints_req = core_endpoints_req.clone();
        let core_endpoints_resp = core_endpoints_resp.clone();
        let original_plaintext = ptxt.clone();

        // start timing measurement for this request
        timings_start.insert(req_id, tokio::time::Instant::now()); // start timing for this request

        // USER_DECRYPTION REQUEST
        join_set.spawn(async move {
            let user_decrypt_req_tuple = internal_client.write().await.user_decryption_request(
                &dummy_domain(),
                ct_batch,
                &req_id,
                &key_id.into(),
                context_id.as_ref(),
                PkeSchemeType::MlKem512,
            )?;

            let (user_decrypt_req, enc_pk, enc_sk) = user_decrypt_req_tuple;

            // make parallel requests by calling user decryption in a thread
            let mut req_tasks = JoinSet::new();

            for ce in core_endpoints_req.values() {
                let req_cloned = user_decrypt_req.clone();
                let mut cur_client = ce.clone();
                req_tasks.spawn(async move {
                    cur_client
                        .user_decrypt(tonic::Request::new(req_cloned))
                        .await
                });
            }

            // make sure all requests have been sent
            let mut req_response_vec = Vec::new();
            while let Some(inner) = req_tasks.join_next().await {
                req_response_vec.push(inner.unwrap().unwrap().into_inner());
            }
            assert_eq!(req_response_vec.len(), num_parties); // check that the request has reached all parties

            tracing::info!(
                "{:?} ###! Sent all user decrypt requests. Since start {:?}",
                req_id.as_str(),
                start.elapsed()
            );

            // get all responses
            let mut resp_tasks = JoinSet::new();
            for ce in core_endpoints_resp.values() {
                let mut cur_client = ce.clone();
                let req_id_clone = user_decrypt_req.request_id.as_ref().unwrap().clone();

                resp_tasks.spawn(async move {
                    // Sleep to give the server some time to complete decryption
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        SLEEP_TIME_BETWEEN_REQUESTS_MS,
                    ))
                    .await;

                    let mut response = cur_client
                        .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
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
                        assert!(
                            ctr < max_iter,
                            "timeout while waiting for user decryption after {max_iter} retries."
                        );
                        ctr += 1;
                        response = cur_client
                            .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                            .await;
                    }
                    (req_id_clone, response.unwrap().into_inner())
                });
            }

            // collect responses (at least num_expected_responses)
            let mut resp_response_vec = Vec::new();
            while let Some(resp) = resp_tasks.join_next().await {
                resp_response_vec.push(resp.unwrap().1);
                // break this loop and continue with the rest of the processing if we have enough responses
                if resp_response_vec.len() >= num_expected_responses {
                    break;
                }
            }

            tracing::info!(
                "{:?} ###! Received {} user decrypt responses. Since start {:?}",
                req_id.as_str(),
                resp_response_vec.len(),
                start.elapsed()
            );

            let client_request = ParsedUserDecryptionRequest::try_from(&user_decrypt_req).unwrap();
            let eip712_domain =
                protobuf_to_alloy_domain(user_decrypt_req.domain.as_ref().unwrap()).unwrap();
            let plaintexts = internal_client
                .read()
                .await
                .process_user_decryption_resp(
                    &client_request,
                    &eip712_domain,
                    &resp_response_vec,
                    &enc_pk,
                    &enc_sk,
                )
                .inspect_err(|e| {
                    tracing::error!(
                        "Error: User decryption response is NOT valid! Reason: {}",
                        e
                    )
                })?;

            // test that all results are matching the original plaintext
            for pt in &plaintexts {
                assert_eq!(
                    TestingPlaintext::try_from(pt.clone())?,
                    TestingPlaintext::try_from(original_plaintext.clone())?
                );
            }

            let decrypted_plaintext = plaintexts[0].clone();

            tracing::info!(
                "User decryption response is ok: {:?} / {:?}",
                original_plaintext,
                TestingPlaintext::try_from(decrypted_plaintext.clone())?,
            );

            let res = format!(
                "User decrypted Plaintext {:?}",
                TestingPlaintext::try_from(decrypted_plaintext)?
            );

            tracing::info!(
                "{:?} ###! Verified user decrypt responses and reconstructed. Since start {:?}",
                req_id.as_str(),
                start.elapsed()
            );

            Ok((Some(req_id), res))
        });
    }
    let mut result_vec = Vec::new();
    while let Some(result) = join_set.join_next().await {
        let res = result??;
        let req_id = res.0.unwrap();
        let elapsed = timings_start.remove(&req_id).unwrap().elapsed();
        durations.push(elapsed);
        result_vec.push(res);
    }

    print_timings("user decrypt", &mut durations, start);

    Ok(result_vec)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn get_public_decrypt_responses(
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    dec_req: Option<PublicDecryptionRequest>,
    expected_answer: Option<TypedPlaintext>,
    request_id: RequestId,
    max_iter: usize,
    num_expected_responses: usize,
    internal_client: &Client,
    kms_addrs: &[alloy_primitives::Address],
    start: tokio::time::Instant,
) -> anyhow::Result<Vec<PublicDecryptionResponse>> {
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

            let mut response = cur_client
                .get_public_decryption_result(tonic::Request::new(request_id.into()))
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
                assert!(
                    ctr < max_iter,
                    "timeout while waiting for public decryption after {max_iter} retries."
                );
                ctr += 1;
                response = cur_client
                    .get_public_decryption_result(tonic::Request::new(request_id.into()))
                    .await;
            }
            (core_id, request_id, response.unwrap().into_inner())
        });
    }
    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        let (core_id, _req_id, resp) = resp?;
        resp_response_vec.push((core_id, resp));
        // break this loop and continue with the rest of the processing if we have enough responses
        if resp_response_vec.len() >= num_expected_responses {
            break;
        }
    }

    tracing::info!(
        "{:?} ###! Received {} public decrypt responses. Since start {:?}",
        request_id.as_str(),
        resp_response_vec.len(),
        start.elapsed()
    );

    resp_response_vec.sort_by_key(|(id, _)| *id);
    let resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();

    //If an expected answer is provided, then consider it,
    //otherwise consider the first answer
    let ptxt = expected_answer.unwrap_or_else(|| {
        resp_response_vec
            .first()
            .unwrap()
            .payload
            .as_ref()
            .unwrap()
            .plaintexts
            .first()
            .unwrap()
            .clone()
    });

    let (domain, external_handles) = if let Some(decryption_request) = dec_req.as_ref() {
        let domain_msg = decryption_request.domain.as_ref().unwrap();
        let domain = protobuf_to_alloy_domain(domain_msg)?;
        // retrieve external handles from request
        let external_handles: Vec<_> = decryption_request
            .ciphertexts
            .iter()
            .map(|ct| ct.external_handle.clone())
            .collect();
        (domain, external_handles)
    } else {
        //If the decryption request isn't provided we assume it was dummy domains and handles
        let num_handles = resp_response_vec
            .first()
            .unwrap()
            .payload
            .as_ref()
            .unwrap()
            .plaintexts
            .len();
        (dummy_domain(), vec![dummy_handle(); num_handles])
    };

    // check the internal signatures
    internal_client.process_decryption_resp(
        dec_req,
        &resp_response_vec,
        num_expected_responses as u32,
    )?;

    // check the external signatures
    check_external_decryption_signature(
        &resp_response_vec,
        ptxt,
        &external_handles,
        &domain,
        kms_addrs,
    )
    .unwrap();

    tracing::info!(
        "{:?} ###! Verified public decypt responses. Since start {:?}",
        request_id.as_str(),
        start.elapsed()
    );

    Ok(resp_response_vec)
}
