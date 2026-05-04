use crate::{CoreConf, SLEEP_TIME_BETWEEN_REQUESTS_MS, dummy_domain, dummy_handle, print_timings};
use alloy_sol_types::Eip712Domain;
use kms_grpc::{
    ContextId, EpochId, KeyId, RequestId,
    kms::v1::{PublicDecryptionRequest, PublicDecryptionResponse, TypedCiphertext, TypedPlaintext},
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    rpc_types::protobuf_to_alloy_domain,
};
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
    plaintexts: &[TypedPlaintext],
    external_handles: &[Vec<u8>],
    domain: Eip712Domain,
    kms_addrs: &[alloy_primitives::Address],
    extra_data: &[u8],
) -> anyhow::Result<()> {
    tracing::debug!(
        "Checking signature for PTs: {:?}, ext. handles: {:?}, extra_data: {}, ext. sig {}",
        plaintexts,
        external_handles,
        hex::encode(extra_data),
        hex::encode(external_sig)
    );
    let message = compute_public_decryption_message(external_handles, plaintexts, extra_data)?;
    let addr = recover_address_from_ext_signature(&message, &domain, external_sig)?;

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
    extra_data: &[u8],
) -> anyhow::Result<()> {
    let mut results = Vec::new();
    for response in responses {
        let payload = response
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing payload in decryption response"))?;
        check_ext_pt_signature(
            &response.external_signature,
            &payload.plaintexts,
            external_handles,
            domain.clone(),
            kms_addrs,
            extra_data,
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
        let tp_result = TestingPlaintext::try_from(result)?;
        if tp_expected != tp_result {
            anyhow::bail!(
                "decryption result mismatch: expected {:?}, got {:?}",
                tp_expected,
                tp_result
            );
        }
    }

    tracing::info!("Decryption response successfully processed.");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_public_decrypt<R: Rng + CryptoRng>(
    rng: &mut R,
    num_requests: usize,
    internal_client: Arc<RwLock<Client>>,
    ct_batch: Vec<TypedCiphertext>,
    key_id: KeyId,
    context_id: Option<ContextId>,
    epoch_id: Option<EpochId>,
    core_endpoints_req: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    core_endpoints_resp: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    ptxt: TypedPlaintext,
    num_parties: usize,
    kms_addrs: Vec<alloy_primitives::Address>,
    max_iter: usize,
    num_expected_responses: usize,
    inter_request_delay: tokio::time::Duration,
    parallel_requests: usize,
    extra_data: Vec<u8>,
) -> anyhow::Result<Vec<(Option<RequestId>, String)>> {
    let mut timings_start = HashMap::new();
    let mut durations = Vec::new();

    let mut join_set: JoinSet<Result<_, anyhow::Error>> = JoinSet::new();
    let start = tokio::time::Instant::now();
    for i in 0..num_requests {
        // Sleep between parallel_requests requests if a non-zero delay is provided (skip before first)
        if i > 0 && i.checked_rem(parallel_requests) == Some(0) && !inter_request_delay.is_zero() {
            tracing::info!(
                "Current status {i}/{num_requests}. Sleeping for {:?} before sending {parallel_requests} more parallel requests.",
                inter_request_delay
            );
            tokio::time::sleep(inter_request_delay).await;
        }
        let req_id = RequestId::new_random(rng);
        let internal_client = internal_client.clone();
        let ct_batch = ct_batch.clone();
        let core_endpoints_req = core_endpoints_req.clone();
        let core_endpoints_resp = core_endpoints_resp.clone();
        let ptxt = ptxt.clone();
        let kms_addrs = kms_addrs.clone();
        let extra_data = extra_data.clone();

        // start timing measurement for this request
        timings_start.insert(req_id, tokio::time::Instant::now()); // start timing for this request

        join_set.spawn(async move {
            // DECRYPTION REQUEST
            let dec_req = internal_client.write().await.public_decryption_request(
                ct_batch,
                &dummy_domain(),
                &req_id,
                context_id.as_ref(),
                &key_id.into(),
                epoch_id.as_ref(),
                &extra_data,
            )?;

            // make parallel requests by calling [decrypt] in a thread
            let mut req_tasks = JoinSet::new();

            for ce in core_endpoints_req.values() {
                let req_cloned = dec_req.clone();
                let mut cur_client = ce.clone();
                req_tasks.spawn(async move {
                    cur_client
                        .public_decrypt(tonic::Request::new(req_cloned))
                        .await
                });
            }

            let mut req_response_vec = Vec::new();
            while let Some(inner) = req_tasks.join_next().await {
                match inner {
                    Ok(Ok(resp)) => req_response_vec.push(resp.into_inner()),
                    Ok(Err(e)) => {
                        tracing::warn!("Public decrypt request to a core failed: {e}");
                    }
                    Err(e) => {
                        tracing::warn!("Public decrypt request task panicked: {e}");
                    }
                }
            }
            if req_response_vec.len() < num_expected_responses {
                anyhow::bail!(
                    "Only {}/{} public decrypt requests succeeded, need at least {}",
                    req_response_vec.len(),
                    num_parties,
                    num_expected_responses
                );
            }

            tracing::info!(
                "{:?} ###! Sent {}/{} public decrypt requests successfully. Since start {:?}",
                req_id.as_str(),
                req_response_vec.len(),
                num_parties,
                start.elapsed()
            );

            let resp_response_vec = get_public_decrypt_responses(
                &core_endpoints_resp,
                Some(dec_req),
                Some(ptxt),
                req_id,
                max_iter,
                num_expected_responses,
                &*internal_client.read().await,
                &kms_addrs,
                start,
            )
            .await?;

            let res = format!("{resp_response_vec:x?}");
            Ok((req_id, res))
        });
    }

    let mut result_vec = Vec::new();
    while let Some(result) = join_set.join_next().await {
        let (req_id, resp_msg) = result??;
        let elapsed = timings_start
            .remove(&req_id)
            .unwrap_or_else(|| {
                panic!("programmer error, req_id {req_id} should have been inserted to timing map")
            })
            .elapsed();
        durations.push(elapsed);
        result_vec.push((Some(req_id), resp_msg));
    }

    print_timings("public decrypt", &mut durations, start);

    Ok(result_vec)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_user_decrypt<R: Rng + CryptoRng>(
    rng: &mut R,
    num_requests: usize,
    internal_client: Arc<RwLock<Client>>,
    ct_batch: Vec<TypedCiphertext>,
    key_id: KeyId,
    context_id: Option<ContextId>,
    epoch_id: Option<EpochId>,
    core_endpoints_req: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    core_endpoints_resp: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    ptxt: TypedPlaintext,
    num_parties: usize,
    max_iter: usize,
    num_expected_responses: usize,
    inter_request_delay: tokio::time::Duration,
    parallel_requests: usize,
    extra_data: Vec<u8>,
) -> anyhow::Result<Vec<(Option<RequestId>, String)>> {
    let mut join_set: JoinSet<Result<_, anyhow::Error>> = JoinSet::new();
    let mut timings_start = HashMap::new();
    let mut durations = Vec::new();
    let start = tokio::time::Instant::now();

    for i in 0..num_requests {
        // Sleep between parallel_requests requests if a non-zero delay is provided (skip before first)
        if i > 0 && i.checked_rem(parallel_requests) == Some(0) && !inter_request_delay.is_zero() {
            tracing::info!(
                "Current status {i}/{num_requests}. Sleeping for {:?} before sending {parallel_requests} more parallel requests.",
                inter_request_delay
            );
            tokio::time::sleep(inter_request_delay).await;
        }
        let req_id = RequestId::new_random(rng);
        let internal_client = internal_client.clone();
        let ct_batch = ct_batch.clone();
        let core_endpoints_req = core_endpoints_req.clone();
        let core_endpoints_resp = core_endpoints_resp.clone();
        let original_plaintext = ptxt.clone();
        let extra_data = extra_data.clone();

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
                epoch_id.as_ref(),
                &extra_data,
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

            // make sure enough requests have been sent
            let mut req_response_vec = Vec::new();
            while let Some(inner) = req_tasks.join_next().await {
                match inner {
                    Ok(Ok(resp)) => req_response_vec.push(resp.into_inner()),
                    Ok(Err(e)) => {
                        tracing::warn!("User decrypt request to a core failed: {e}");
                    }
                    Err(e) => {
                        tracing::warn!("User decrypt request task panicked: {e}");
                    }
                }
            }
            if req_response_vec.len() < num_expected_responses {
                anyhow::bail!(
                    "Only {}/{} user decrypt requests succeeded, need at least {}",
                    req_response_vec.len(),
                    num_parties,
                    num_expected_responses
                );
            }

            tracing::info!(
                "{:?} ###! Sent {}/{} user decrypt requests successfully. Since start {:?}",
                req_id.as_str(),
                req_response_vec.len(),
                num_parties,
                start.elapsed()
            );

            // get all responses
            let mut resp_tasks = JoinSet::new();
            for ce in core_endpoints_resp.values() {
                let mut cur_client = ce.clone();
                let req_id_clone = user_decrypt_req.request_id.as_ref().ok_or_else(|| anyhow::anyhow!("request_id not set in user decrypt request"))?.clone();

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
                        && response.as_ref().unwrap_err().code()
                            == tonic::Code::Unavailable
                    {
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            SLEEP_TIME_BETWEEN_REQUESTS_MS,
                        ))
                        .await;
                        // do at most max_iter retries
                        if ctr >= max_iter {
                            anyhow::bail!(
                                "timeout while waiting for user decryption after {max_iter} retries."
                            );
                        }
                        ctr += 1;
                        response = cur_client
                            .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                            .await;
                    }
                    let resp = response.map_err(|e| {
                        anyhow::anyhow!("user decryption response failed: {e}")
                    })?;
                    Ok((req_id_clone, resp.into_inner()))
                });
            }

            // collect responses (at least num_expected_responses)
            let mut resp_response_vec = Vec::new();
            while let Some(resp) = resp_tasks.join_next().await {
                match resp {
                    Ok(Ok((_req_id, inner))) => {
                        resp_response_vec.push(inner);
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("A core failed to return user decryption result: {e}");
                    }
                    Err(e) => {
                        tracing::warn!("User decryption response task panicked: {e}");
                    }
                }
                // break this loop and continue with the rest of the processing if we have enough responses
                if resp_response_vec.len() >= num_expected_responses {
                    break;
                }
            }
            if resp_response_vec.len() < num_expected_responses {
                anyhow::bail!(
                    "Only got {}/{} user decryption responses, need at least {}",
                    resp_response_vec.len(),
                    num_parties,
                    num_expected_responses
                );
            }

            tracing::info!(
                "{:?} ###! Received {} user decrypt responses. Since start {:?}",
                req_id.as_str(),
                resp_response_vec.len(),
                start.elapsed()
            );

            let client_request = ParsedUserDecryptionRequest::try_from(&user_decrypt_req).map_err(|e| anyhow::anyhow!("failed to parse user decryption request: {e}"))?;
            let eip712_domain =
                protobuf_to_alloy_domain(user_decrypt_req.domain.as_ref().ok_or_else(|| anyhow::anyhow!("domain not set in user decrypt request"))?)?;
            let plaintexts = internal_client
                .read()
                .await
                .process_user_decryption_resp(
                    &client_request,
                    &eip712_domain,
                    &enc_pk,
                    &enc_sk,
                    None,
                    &resp_response_vec,
                )
                .inspect_err(|e| {
                    tracing::error!(
                        "Error: User decryption response is NOT valid! Reason: {}",
                        e
                    )
                })?;

            // test that all results are matching the original plaintext
            for pt in &plaintexts {
                anyhow::ensure!(
                    TestingPlaintext::try_from(pt.clone())? == TestingPlaintext::try_from(original_plaintext.clone())?,
                    "user decryption result mismatch: expected {:?}, got {:?}",
                    TestingPlaintext::try_from(original_plaintext.clone())?,
                    TestingPlaintext::try_from(pt.clone())?
                );
            }

            let decrypted_plaintext = plaintexts.first().ok_or_else(|| anyhow::anyhow!("no plaintexts in user decryption response"))?.clone();

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

            Ok((req_id, res))
        });
    }
    let mut result_vec = Vec::new();
    while let Some(result) = join_set.join_next().await {
        let (req_id, resp_msg) = result??;
        let elapsed = timings_start
            .remove(&req_id)
            .unwrap_or_else(|| {
                panic!("programmer error, req_id {req_id} should have been inserted to timing map")
            })
            .elapsed();
        durations.push(elapsed);
        result_vec.push((Some(req_id), resp_msg));
    }

    print_timings("user decrypt", &mut durations, start);

    Ok(result_vec)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn get_public_decrypt_responses(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
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
    for (core_conf, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let core_conf = core_conf.clone();

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
                if ctr >= max_iter {
                    anyhow::bail!(
                        "timeout while waiting for public decryption from party {:?} after {max_iter} retries.",
                        core_conf.party_id
                    );
                }
                ctr += 1;
                response = cur_client
                    .get_public_decryption_result(tonic::Request::new(request_id.into()))
                    .await;
            }
            let resp = response.map_err(|e| {
                anyhow::anyhow!("public decryption response from party {:?} failed: {e}", core_conf.party_id)
            })?;
            Ok((core_conf, request_id, resp.into_inner()))
        });
    }
    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        match resp {
            Ok(Ok((core_conf, _req_id, inner))) => {
                resp_response_vec.push((core_conf, inner));
            }
            Ok(Err(e)) => {
                tracing::warn!("A core failed to return public decryption result: {e}");
            }
            Err(e) => {
                tracing::warn!("Public decryption response task panicked: {e}");
            }
        }
        // break this loop and continue with the rest of the processing if we have enough responses
        if resp_response_vec.len() >= num_expected_responses {
            break;
        }
    }
    if resp_response_vec.len() < num_expected_responses {
        anyhow::bail!(
            "Only got {}/{} public decryption responses, need at least {}",
            resp_response_vec.len(),
            core_endpoints.len(),
            num_expected_responses
        );
    }

    tracing::info!(
        "{:?} ###! Received {} public decrypt responses. Since start {:?}",
        request_id.as_str(),
        resp_response_vec.len(),
        start.elapsed()
    );

    resp_response_vec.sort_by_key(|(conf, _)| conf.party_id);
    let resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();

    //If an expected answer is provided, then consider it,
    //otherwise consider the first answer
    let ptxt = match expected_answer {
        Some(pt) => pt,
        None => resp_response_vec
            .first()
            .ok_or_else(|| anyhow::anyhow!("no public decryption responses available"))?
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing payload in first decryption response"))?
            .plaintexts
            .first()
            .ok_or_else(|| anyhow::anyhow!("no plaintexts in first decryption response"))?
            .clone(),
    };

    let (domain, external_handles, extra_data) = if let Some(decryption_request) = dec_req.as_ref()
    {
        let domain_msg = decryption_request
            .domain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("domain not set in decryption request"))?;
        let domain = protobuf_to_alloy_domain(domain_msg)?;
        // retrieve external handles from request
        let external_handles: Vec<_> = decryption_request
            .ciphertexts
            .iter()
            .map(|ct| ct.external_handle.clone())
            .collect();
        let extra_data = decryption_request.extra_data.clone();
        (domain, external_handles, extra_data)
    } else {
        //If the decryption request isn't provided we assume it was dummy domains and handles
        let num_handles = resp_response_vec
            .first()
            .ok_or_else(|| anyhow::anyhow!("no public decryption responses available"))?
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing payload in first decryption response"))?
            .plaintexts
            .len();
        let extra_data = resp_response_vec
            .first()
            .ok_or_else(|| anyhow::anyhow!("no public decryption responses available"))?
            .extra_data
            .clone();
        (
            dummy_domain(),
            vec![dummy_handle(); num_handles],
            extra_data,
        )
    };

    // check the internal signatures
    internal_client.process_decryption_resp(
        dec_req,
        num_expected_responses as u32,
        &resp_response_vec,
    )?;

    // check the external signatures
    check_external_decryption_signature(
        &resp_response_vec,
        ptxt,
        &external_handles,
        &domain,
        kms_addrs,
        &extra_data,
    )?;

    tracing::info!(
        "{:?} ###! Verified public decypt responses. Since start {:?}",
        request_id.as_str(),
        start.elapsed()
    );

    Ok(resp_response_vec)
}
