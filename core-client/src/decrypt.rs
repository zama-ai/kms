use crate::{CoreConf, SLEEP_TIME_BETWEEN_REQUESTS_MS, print_phased_timings};
use alloy_sol_types::Eip712Domain;
use kms_grpc::{
    ContextId, EpochId, KeyId, RequestId,
    kms::v1::{
        PublicDecryptionRequest, PublicDecryptionResponse, TypedCiphertext, TypedPlaintext,
        UserDecryptionRequest,
    },
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    rpc_types::protobuf_to_alloy_domain,
};
use kms_lib::{
    client::{client_wasm::Client, user_decryption_wasm::ParsedUserDecryptionRequest},
    cryptography::encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey},
    cryptography::signatures::recover_address_from_ext_signature,
    engine::base::compute_public_decryption_message,
    util::key_setup::test_tools::TestingPlaintext,
};
use prost::Message as _;
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tonic::transport::Channel;

type CoreEndpointClient = CoreServiceEndpointClient<Channel>;
type CoreEndpointClients = Arc<[CoreEndpointClient]>;

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

#[expect(clippy::too_many_arguments)]
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
    domain: Eip712Domain,
) -> anyhow::Result<Vec<(Option<RequestId>, String)>> {
    // `extra_data` is always derived from the (resolved) context/epoch via
    // `make_extra_data` (RFC-005 v2) — never user-supplied — matching the
    // keygen/CRS request builders.
    let extra_data = crate::extra_data_from_context_epoch(context_id, epoch_id)?;

    // PHASE 0: build every request up front.
    let mut requests = Vec::with_capacity(num_requests);
    for _ in 0..num_requests {
        let req_id = RequestId::new_random(rng);
        let dec_req = internal_client.write().await.public_decryption_request(
            ct_batch.clone(),
            &domain,
            &req_id,
            context_id.as_ref(),
            &key_id.into(),
            epoch_id.as_ref(),
            &extra_data,
        )?;
        requests.push((req_id, dec_req));
    }

    // PHASE 1: send the prebuilt requests and collect their responses.
    let mut join_set: JoinSet<Result<_, anyhow::Error>> = JoinSet::new();
    let mut durations_to_get_responses = Vec::new();
    let start = tokio::time::Instant::now();

    for (i, (req_id, dec_req)) in requests.into_iter().enumerate() {
        // Sleep between parallel_requests requests if a non-zero delay is provided (skip before first)
        if i > 0 && i.checked_rem(parallel_requests) == Some(0) && !inter_request_delay.is_zero() {
            tracing::info!(
                "Current status {i}/{num_requests}. Sleeping for {:?} before sending {parallel_requests} more parallel requests.",
                inter_request_delay
            );
            tokio::time::sleep(inter_request_delay).await;
        }
        let internal_client = internal_client.clone();
        let core_endpoints_req = core_endpoints_req.clone();
        let core_endpoints_resp = core_endpoints_resp.clone();
        let kms_addrs = kms_addrs.clone();

        join_set.spawn(async move {
            // start timing this request's collect window
            let request_start = tokio::time::Instant::now();

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

            // collect only — verification is deferred to phase 2 (below) so it stays out of the throughput window.
            let (resp_response_vec, time_to_get_responses) = get_public_decrypt_responses(
                &core_endpoints_resp,
                None,
                None,
                req_id,
                max_iter,
                num_expected_responses,
                &*internal_client.read().await,
                &kms_addrs,
                request_start,
            )
            .await?;

            Ok((req_id, dec_req, resp_response_vec, time_to_get_responses))
        });
    }

    // Drain phase 1: gather every request, its responses, and its collect-only latency.
    let mut collected = Vec::with_capacity(num_requests);
    while let Some(result) = join_set.join_next().await {
        let (req_id, dec_req, resp_response_vec, time_to_get_responses) = result??;
        durations_to_get_responses.push(time_to_get_responses);
        collected.push((req_id, dec_req, resp_response_vec));
    }
    let collect_elapsed = start.elapsed();

    // PHASE 2: verify each result in parallel. Measured and reported separately from the throughput figure.
    let verify_start = tokio::time::Instant::now();
    let mut verify_tasks: JoinSet<Result<(RequestId, String), anyhow::Error>> = JoinSet::new();
    for (req_id, dec_req, resp_response_vec) in collected {
        let internal_client = internal_client.clone();
        let kms_addrs = kms_addrs.clone();
        let ptxt = ptxt.clone();
        verify_tasks.spawn(async move {
            verify_public_decrypt_responses(
                &resp_response_vec,
                PubDecVerificationMaterial::Request(dec_req),
                Some(ptxt),
                &*internal_client.read().await,
                &kms_addrs,
                num_expected_responses,
            )?;
            Ok((req_id, format!("{resp_response_vec:x?}")))
        });
    }

    let mut result_vec = Vec::with_capacity(durations_to_get_responses.len());
    while let Some(res) = verify_tasks.join_next().await {
        let (req_id, msg) = res??;
        result_vec.push((Some(req_id), msg));
    }
    let verify_elapsed = verify_start.elapsed();

    print_phased_timings(
        "public decrypt",
        collect_elapsed,
        &durations_to_get_responses,
        verify_elapsed,
    );

    Ok(result_vec)
}

struct CollectedUserDecrypt {
    req_id: RequestId,
    user_decrypt_req: UserDecryptionRequest,
    enc_pk: UnifiedPublicEncKey,
    enc_sk: UnifiedPrivateEncKey,
    resp_response_vec: Vec<kms_grpc::kms::v1::UserDecryptionResponse>,
    collect_duration: tokio::time::Duration,
}

struct UserDecryptMetrics {
    target_rate: u64,
    duration_secs: u64,
    max_in_flight: usize,
    offered: u64,
    completed: u64,
    failed: u64,
    shed: u64,
    achieved_rate: f64,
    saturated: bool,
    request_payload_bytes: u64,
    request_payload_messages: u64,
    request_payload_mib_per_sec: f64,
    request_payload_avg_bytes: f64,
    response_payload_bytes: u64,
    response_payload_messages: u64,
    response_payload_mib_per_sec: f64,
    response_payload_avg_bytes: f64,
    reconstruction_failed: u64,
    latency_stat: crate::DurationStat,
    reconstruction_stat: crate::DurationStat,
    reconstruction_wall: tokio::time::Duration,
}

/// Wire format for the `USER_DECRYPT_METRICS` line the CI harness parses.
/// Serializing a dedicated struct keeps the JSON shape (field names, nesting)
/// tied to the type instead of a hand-maintained `format!` string.
#[derive(serde::Serialize)]
struct UserDecryptMetricsJson {
    target_rate: u64,
    #[serde(rename = "duration")]
    duration_secs: u64,
    max_in_flight: usize,
    offered: u64,
    completed: u64,
    failed: u64,
    shed: u64,
    achieved_rate: f64,
    saturated: bool,
    request_payload_bytes: u64,
    request_payload_messages: u64,
    request_payload_mib_per_sec: f64,
    request_payload_avg_bytes: f64,
    response_payload_bytes: u64,
    response_payload_messages: u64,
    response_payload_mib_per_sec: f64,
    response_payload_avg_bytes: f64,
    reconstruction_failed: u64,
    latency_ms: DurationStatMsJson,
    reconstruction_ms: ReconstructionMsJson,
}

#[derive(serde::Serialize)]
struct DurationStatMsJson {
    avg: f64,
    std_dev: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    min: f64,
    max: f64,
}

#[derive(serde::Serialize)]
struct ReconstructionMsJson {
    avg: f64,
    std_dev: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    min: f64,
    max: f64,
    wall: f64,
}

fn duration_stat_ms(stat: &crate::DurationStat) -> DurationStatMsJson {
    let ms = |d: tokio::time::Duration| d.as_secs_f64() * 1000.0;
    DurationStatMsJson {
        avg: ms(stat.avg),
        std_dev: ms(stat.std_dev),
        p50: ms(stat.p50),
        p95: ms(stat.p95),
        p99: ms(stat.p99),
        min: ms(stat.min),
        max: ms(stat.max),
    }
}

impl From<&UserDecryptMetrics> for UserDecryptMetricsJson {
    fn from(m: &UserDecryptMetrics) -> Self {
        let recon = duration_stat_ms(&m.reconstruction_stat);
        Self {
            target_rate: m.target_rate,
            duration_secs: m.duration_secs,
            max_in_flight: m.max_in_flight,
            offered: m.offered,
            completed: m.completed,
            failed: m.failed,
            shed: m.shed,
            achieved_rate: m.achieved_rate,
            saturated: m.saturated,
            request_payload_bytes: m.request_payload_bytes,
            request_payload_messages: m.request_payload_messages,
            request_payload_mib_per_sec: m.request_payload_mib_per_sec,
            request_payload_avg_bytes: m.request_payload_avg_bytes,
            response_payload_bytes: m.response_payload_bytes,
            response_payload_messages: m.response_payload_messages,
            response_payload_mib_per_sec: m.response_payload_mib_per_sec,
            response_payload_avg_bytes: m.response_payload_avg_bytes,
            reconstruction_failed: m.reconstruction_failed,
            latency_ms: duration_stat_ms(&m.latency_stat),
            reconstruction_ms: ReconstructionMsJson {
                avg: recon.avg,
                std_dev: recon.std_dev,
                p50: recon.p50,
                p95: recon.p95,
                p99: recon.p99,
                min: recon.min,
                max: recon.max,
                wall: m.reconstruction_wall.as_secs_f64() * 1000.0,
            },
        }
    }
}

impl UserDecryptMetrics {
    fn log_json(&self) {
        match serde_json::to_string(&UserDecryptMetricsJson::from(self)) {
            Ok(metrics) => println!("USER_DECRYPT_METRICS {metrics}"),
            Err(e) => tracing::error!("failed to serialize user decrypt metrics: {e}"),
        }
    }
}

#[expect(clippy::too_many_arguments)]
async fn send_and_collect_user_decrypt(
    rate: u64,
    req_id: RequestId,
    user_decrypt_req: UserDecryptionRequest,
    enc_pk: UnifiedPublicEncKey,
    enc_sk: UnifiedPrivateEncKey,
    core_endpoints_req: CoreEndpointClients,
    core_endpoints_resp: CoreEndpointClients,
    num_parties: usize,
    max_iter: usize,
    num_expected_responses: usize,
) -> anyhow::Result<CollectedUserDecrypt> {
    let request_start = tokio::time::Instant::now();

    let mut req_tasks = JoinSet::new();
    for ce in core_endpoints_req.iter() {
        let req_cloned = user_decrypt_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .user_decrypt(tonic::Request::new(req_cloned))
                .await
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        match inner {
            Ok(Ok(resp)) => req_response_vec.push(resp.into_inner()),
            Ok(Err(e)) => {
                tracing::debug!("User decrypt request to a core failed: {e}");
            }
            Err(e) => {
                tracing::debug!("User decrypt request task panicked: {e}");
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

    let mut resp_tasks = JoinSet::new();
    for ce in core_endpoints_resp.iter() {
        let mut cur_client = ce.clone();
        let req_id_clone = user_decrypt_req
            .request_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("request_id not set in user decrypt request"))?
            .clone();

        resp_tasks.spawn(async move {
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
            let resp =
                response.map_err(|e| anyhow::anyhow!("user decryption response failed: {e}"))?;
            Ok((req_id_clone, resp.into_inner()))
        });
    }

    let mut resp_response_vec = Vec::new();
    let mut collect_duration = None;
    while let Some(resp) = resp_tasks.join_next().await {
        match resp {
            Ok(Ok((_req_id, inner))) => {
                resp_response_vec.push(inner);
            }
            Ok(Err(e)) => {
                tracing::debug!("A core failed to return user decryption result: {e}");
            }
            Err(e) => {
                tracing::debug!("User decryption response task panicked: {e}");
            }
        }
        if resp_response_vec.len() >= num_expected_responses {
            collect_duration = Some(request_start.elapsed());
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
    let pending_response_tasks = resp_tasks.len();
    if pending_response_tasks > 0 {
        tokio::spawn(async move {
            while let Some(resp) = resp_tasks.join_next().await {
                match resp {
                    Ok(Ok((_req_id, _inner))) => {}
                    Ok(Err(e)) => {
                        tracing::debug!("Outstanding user decryption response failed: {e}");
                    }
                    Err(e) => {
                        tracing::debug!("Outstanding user decryption response task panicked: {e}");
                    }
                }
            }
            tracing::debug!(
                rate,
                drained = pending_response_tasks,
                "drained outstanding udec resp tasks"
            );
        });
    }

    let collect_duration = collect_duration.expect("set once the response quota is met");
    tracing::debug!(
        rate,
        got = resp_response_vec.len(),
        needed = num_expected_responses,
        elapsed = ?collect_duration,
        "udec resp"
    );

    Ok(CollectedUserDecrypt {
        req_id,
        user_decrypt_req,
        enc_pk,
        enc_sk,
        resp_response_vec,
        collect_duration,
    })
}

fn drain_finished_user_decrypts(
    join_set: &mut JoinSet<Result<CollectedUserDecrypt, anyhow::Error>>,
    collected: &mut Vec<CollectedUserDecrypt>,
    durations: &mut Vec<tokio::time::Duration>,
    failed: &mut u64,
) {
    while let Some(result) = join_set.try_join_next() {
        match result {
            Ok(Ok(collected_result)) => {
                durations.push(collected_result.collect_duration);
                collected.push(collected_result);
            }
            Ok(Err(e)) => {
                *failed += 1;
                tracing::debug!("User decrypt request failed: {e}");
            }
            Err(e) => {
                *failed += 1;
                tracing::warn!("User decrypt task panicked: {e}");
            }
        }
    }
}

async fn reconstruct_user_decrypt(
    internal_client: Arc<RwLock<Client>>,
    expected: TestingPlaintext,
    collected: CollectedUserDecrypt,
) -> anyhow::Result<(RequestId, String, tokio::time::Duration)> {
    let CollectedUserDecrypt {
        req_id,
        user_decrypt_req,
        enc_pk,
        enc_sk,
        resp_response_vec,
        collect_duration: _,
    } = collected;
    let reconstruct_one_start = tokio::time::Instant::now();
    let client_request = ParsedUserDecryptionRequest::try_from(&user_decrypt_req)
        .map_err(|e| anyhow::anyhow!("failed to parse user decryption request: {e}"))?;
    let eip712_domain = protobuf_to_alloy_domain(
        user_decrypt_req
            .domain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("domain not set in user decrypt request"))?,
    )?;
    let plaintexts = internal_client.read().await.process_user_decryption_resp(
        &client_request,
        &eip712_domain,
        &enc_pk,
        &enc_sk,
        None,
        &resp_response_vec,
    )?;

    let mut decoded = plaintexts.into_iter().map(TestingPlaintext::try_from);
    let first = decoded
        .next()
        .ok_or_else(|| anyhow::anyhow!("no plaintexts in user decryption response"))??;
    anyhow::ensure!(
        first == expected,
        "user decryption result mismatch: expected {expected:?}, got {first:?}"
    );
    for pt in decoded {
        let pt = pt?;
        anyhow::ensure!(
            pt == expected,
            "user decryption result mismatch: expected {expected:?}, got {pt:?}"
        );
    }

    tracing::debug!("User decryption response is ok: {expected:?} / {first:?}");
    Ok((
        req_id,
        format!("User decrypted Plaintext {first:?}"),
        reconstruct_one_start.elapsed(),
    ))
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn do_user_decrypt_once<R: Rng + CryptoRng>(
    rng: &mut R,
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
    domain: Eip712Domain,
) -> anyhow::Result<Vec<(Option<RequestId>, String)>> {
    let extra_data = crate::extra_data_from_context_epoch(context_id, epoch_id)?;
    let expected = TestingPlaintext::try_from(ptxt)?;
    let core_endpoints_req =
        Arc::<[CoreEndpointClient]>::from(core_endpoints_req.values().cloned().collect::<Vec<_>>());
    let core_endpoints_resp = Arc::<[CoreEndpointClient]>::from(
        core_endpoints_resp.values().cloned().collect::<Vec<_>>(),
    );

    let req_id = RequestId::new_random(rng);
    let (user_decrypt_req, enc_pk, enc_sk) =
        internal_client.write().await.user_decryption_request(
            &domain,
            ct_batch,
            &req_id,
            &key_id.into(),
            context_id.as_ref(),
            epoch_id.as_ref(),
            &extra_data,
        )?;

    let collected = send_and_collect_user_decrypt(
        1,
        req_id,
        user_decrypt_req,
        enc_pk,
        enc_sk,
        core_endpoints_req,
        core_endpoints_resp,
        num_parties,
        max_iter,
        num_expected_responses,
    )
    .await?;
    let collect_duration = collected.collect_duration;

    let reconstruct_start = tokio::time::Instant::now();
    let (req_id, msg, reconstruct_duration) =
        reconstruct_user_decrypt(internal_client, expected, collected).await?;
    let reconstruct_elapsed = reconstruct_start.elapsed();

    print_phased_timings(
        "user decrypt",
        collect_duration,
        &[collect_duration],
        reconstruct_elapsed,
    );
    tracing::debug!(elapsed = ?reconstruct_duration, "udec reconstruct");

    Ok(vec![(Some(req_id), msg)])
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn do_user_decrypt<R: Rng + CryptoRng>(
    rng: &mut R,
    rate: u64,
    duration_secs: u64,
    max_in_flight: usize,
    drain_timeout_secs: u64,
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
    domain: Eip712Domain,
) -> anyhow::Result<Vec<(Option<RequestId>, String)>> {
    let total_requests = (rate * duration_secs) as usize;
    let extra_data = crate::extra_data_from_context_epoch(context_id, epoch_id)?;
    let expected = TestingPlaintext::try_from(ptxt)?;
    let core_endpoints_req =
        Arc::<[CoreEndpointClient]>::from(core_endpoints_req.values().cloned().collect::<Vec<_>>());
    let core_endpoints_resp = Arc::<[CoreEndpointClient]>::from(
        core_endpoints_resp.values().cloned().collect::<Vec<_>>(),
    );

    tracing::info!(
        "Prebuilding {total_requests} user decrypt requests: rate={rate}/s, duration={duration_secs}s, max_in_flight={max_in_flight}"
    );
    let mut requests = Vec::with_capacity(total_requests);
    for _ in 0..total_requests {
        let req_id = RequestId::new_random(rng);
        let (user_decrypt_req, enc_pk, enc_sk) =
            internal_client.write().await.user_decryption_request(
                &domain,
                ct_batch.clone(),
                &req_id,
                &key_id.into(),
                context_id.as_ref(),
                epoch_id.as_ref(),
                &extra_data,
            )?;
        requests.push((req_id, user_decrypt_req, enc_pk, enc_sk));
    }

    let mut request_iter = requests.into_iter();
    let mut join_set: JoinSet<Result<CollectedUserDecrypt, anyhow::Error>> = JoinSet::new();
    let mut collected = Vec::with_capacity(total_requests);
    let mut durations_to_get_responses = Vec::with_capacity(total_requests);
    let mut offered = 0_u64;
    let mut failed = 0_u64;
    let mut shed = 0_u64;
    let mut saturated = false;
    let mut request_payload_bytes = 0_u64;
    let mut request_payload_messages = 0_u64;

    let run_start = tokio::time::Instant::now();
    let deadline = run_start + tokio::time::Duration::from_secs(duration_secs);
    let tick_period = tokio::time::Duration::from_millis(5);
    let mut ticker = tokio::time::interval(tick_period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut launch_accumulator = 0_u64;
    // The accumulator assumes a steady 200 ticks/s. With MissedTickBehavior::Delay a
    // stalled iteration pushes ticks late instead of catching up, so the offered rate
    // can quietly fall below target. Count late ticks so that shortfall is observable.
    let mut last_tick = tokio::time::Instant::now();
    let mut late_ticks = 0_u64;

    while tokio::time::Instant::now() < deadline {
        ticker.tick().await;
        let tick_now = tokio::time::Instant::now();
        if tick_now.duration_since(last_tick) > tick_period * 2 {
            late_ticks += 1;
            if late_ticks == 1 {
                tracing::warn!(
                    rate,
                    behind_ms = tick_now.duration_since(last_tick).as_millis() as u64,
                    "user decrypt ticker fell behind; offered rate may drop below target - underpowered test runner?"
                );
            }
        }
        last_tick = tick_now;
        drain_finished_user_decrypts(
            &mut join_set,
            &mut collected,
            &mut durations_to_get_responses,
            &mut failed,
        );

        launch_accumulator = launch_accumulator.saturating_add(rate);
        let launches = launch_accumulator / 200;
        launch_accumulator %= 200;

        for _ in 0..launches {
            let Some((req_id, user_decrypt_req, enc_pk, enc_sk)) = request_iter.next() else {
                break;
            };
            offered += 1;
            if join_set.len() >= max_in_flight {
                // Shed: client drops this arrival because the in-flight cap says saturated.
                shed += 1;
                saturated = true;
                continue;
            }
            request_payload_bytes +=
                user_decrypt_req.encoded_len() as u64 * core_endpoints_req.len() as u64;
            request_payload_messages += core_endpoints_req.len() as u64;
            let core_endpoints_req = Arc::clone(&core_endpoints_req);
            let core_endpoints_resp = Arc::clone(&core_endpoints_resp);
            join_set.spawn(send_and_collect_user_decrypt(
                rate,
                req_id,
                user_decrypt_req,
                enc_pk,
                enc_sk,
                core_endpoints_req,
                core_endpoints_resp,
                num_parties,
                max_iter,
                num_expected_responses,
            ));
        }
    }

    if late_ticks > 0 {
        tracing::warn!(
            rate,
            late_ticks,
            offered,
            target = total_requests,
            "user decrypt ticker fell behind; offered rate likely below target - underpowered test runner?"
        );
    }

    let drain_deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(drain_timeout_secs);
    while !join_set.is_empty() && tokio::time::Instant::now() < drain_deadline {
        if let Ok(Some(result)) =
            tokio::time::timeout_at(drain_deadline, join_set.join_next()).await
        {
            match result {
                Ok(Ok(collected_result)) => {
                    durations_to_get_responses.push(collected_result.collect_duration);
                    collected.push(collected_result);
                }
                Ok(Err(e)) => {
                    failed += 1;
                    tracing::debug!("User decrypt request failed: {e}");
                }
                Err(e) => {
                    failed += 1;
                    tracing::warn!("User decrypt task panicked: {e}");
                }
            }
        } else {
            break;
        }
    }
    if !join_set.is_empty() {
        saturated = true;
        let remaining = join_set.len();
        failed += remaining as u64;
        tracing::warn!("User decrypt drain timed out with {remaining} requests still in flight");
        join_set.abort_all();
    }

    let collect_elapsed = run_start.elapsed();
    let completed = collected.len() as u64;
    let latency_stat = crate::compute_stat_on_durations(&durations_to_get_responses);
    let request_payload_mib_per_sec = if collect_elapsed.is_zero() {
        0.0
    } else {
        request_payload_bytes as f64 / 1024.0 / 1024.0 / collect_elapsed.as_secs_f64()
    };
    let request_payload_avg_bytes = if request_payload_messages == 0 {
        0.0
    } else {
        request_payload_bytes as f64 / request_payload_messages as f64
    };
    let response_payload_bytes = collected
        .iter()
        .flat_map(|collected| collected.resp_response_vec.iter())
        .map(|response| response.encoded_len() as u64)
        .sum();
    let response_payload_messages = collected
        .iter()
        .map(|collected| collected.resp_response_vec.len() as u64)
        .sum();
    let response_payload_mib_per_sec = if collect_elapsed.is_zero() {
        0.0
    } else {
        response_payload_bytes as f64 / 1024.0 / 1024.0 / collect_elapsed.as_secs_f64()
    };
    let response_payload_avg_bytes = if response_payload_messages == 0 {
        0.0
    } else {
        response_payload_bytes as f64 / response_payload_messages as f64
    };

    let reconstruct_start = tokio::time::Instant::now();
    let mut recon_tasks: JoinSet<Result<tokio::time::Duration, anyhow::Error>> = JoinSet::new();
    for collected_result in collected {
        let internal_client = internal_client.clone();
        recon_tasks.spawn(async move {
            reconstruct_user_decrypt(internal_client, expected, collected_result)
                .await
                .map(|(_, _, duration)| duration)
        });
    }

    let mut reconstruction_durations = Vec::with_capacity(durations_to_get_responses.len());
    let mut reconstruction_failed = 0_u64;
    while let Some(res) = recon_tasks.join_next().await {
        match res {
            Ok(Ok(reconstruct_duration)) => {
                reconstruction_durations.push(reconstruct_duration);
            }
            Ok(Err(e)) => {
                reconstruction_failed += 1;
                tracing::debug!("User decrypt reconstruction failed: {e}");
            }
            Err(e) => {
                reconstruction_failed += 1;
                tracing::warn!("User decrypt reconstruction task panicked: {e}");
            }
        }
    }
    let reconstruct_elapsed = reconstruct_start.elapsed();
    let reconstruction_stat = crate::compute_stat_on_durations(&reconstruction_durations);

    let metrics = UserDecryptMetrics {
        target_rate: rate,
        duration_secs,
        max_in_flight,
        offered,
        completed,
        failed,
        shed,
        // TODO: consider also reporting completed / duration_secs; this includes drain time.
        achieved_rate: completed as f64 / collect_elapsed.as_secs_f64(),
        saturated,
        request_payload_bytes,
        request_payload_messages,
        request_payload_mib_per_sec,
        request_payload_avg_bytes,
        response_payload_bytes,
        response_payload_messages,
        response_payload_mib_per_sec,
        response_payload_avg_bytes,
        reconstruction_failed,
        latency_stat,
        reconstruction_stat,
        reconstruction_wall: reconstruct_elapsed,
    };
    metrics.log_json();
    if reconstruction_failed > 0 {
        tracing::warn!(
            reconstruction_failed,
            "user decrypt reconstruction failures"
        );
    }

    print_phased_timings(
        "user decrypt",
        collect_elapsed,
        &durations_to_get_responses,
        reconstruct_elapsed,
    );

    if reconstruction_failed > 0 {
        anyhow::bail!("{reconstruction_failed} user decrypt reconstructions failed");
    }

    Ok(Vec::new())
}

/// Material used to verify fetched public-decryption responses.
///
/// Wrapped in an `Option` at the call sites, where `None` means "skip verification".
/// This replaces the previous `dec_req: Option<PublicDecryptionRequest>` parameter, whose
/// `None` case silently fell back to `dummy_domain()`/`dummy_handle()` rather than either
/// skipping or verifying against real config/CLI material. The two variants are mutually
/// exclusive by construction, so a caller cannot mix request-derived and external material.
pub(crate) enum PubDecVerificationMaterial {
    /// Full-flow: verify against the original request. The EIP-712 domain, external
    /// ciphertext handles and `extra_data` are all derived from it, and the request
    /// itself binds the responses (internal request-binding check).
    Request(PublicDecryptionRequest),
    /// Pure-fetch: verify against externally-supplied material (e.g. from config +
    /// CLI) when the original request object is not available. Responses are still
    /// checked against the trusted KMS keys, but not bound to a specific request.
    External {
        domain: Eip712Domain,
        external_handles: Vec<Vec<u8>>,
        extra_data: Vec<u8>,
    },
}

/// Verify fetched public-decryption responses (internal + external signatures, and that the result
/// matches `expected_answer`, or the first response when `None`).
fn verify_public_decrypt_responses(
    resp_response_vec: &[PublicDecryptionResponse],
    verification: PubDecVerificationMaterial,
    expected_answer: Option<TypedPlaintext>,
    internal_client: &Client,
    kms_addrs: &[alloy_primitives::Address],
    num_expected_responses: usize,
) -> anyhow::Result<()> {
    // Resolve the verification material into (domain, external handles, extra_data) plus the
    // optional original request used for the internal request-binding check.
    let (domain, external_handles, extra_data, request) = match verification {
        PubDecVerificationMaterial::Request(decryption_request) => {
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
            (
                domain,
                external_handles,
                extra_data,
                Some(decryption_request),
            )
        }
        PubDecVerificationMaterial::External {
            domain,
            external_handles,
            extra_data,
        } => (domain, external_handles, extra_data, None),
    };

    // If an expected answer is provided, use it; otherwise consider the first answer.
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

    // check the internal signatures (verifies responses are signed by the trusted KMS keys;
    // request-binding only applies for the `Request` variant)
    internal_client.process_decryption_resp(
        request,
        num_expected_responses as u32,
        resp_response_vec,
    )?;

    // check the external signatures
    check_external_decryption_signature(
        resp_response_vec,
        ptxt,
        &external_handles,
        &domain,
        kms_addrs,
        &extra_data,
    )?;

    Ok(())
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn get_public_decrypt_responses(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    // Verification material for the fetched responses. `None` returns them unverified.
    verification: Option<PubDecVerificationMaterial>,
    expected_answer: Option<TypedPlaintext>,
    request_id: RequestId,
    max_iter: usize,
    num_expected_responses: usize,
    internal_client: &Client,
    kms_addrs: &[alloy_primitives::Address],
    start: tokio::time::Instant,
) -> anyhow::Result<(Vec<PublicDecryptionResponse>, tokio::time::Duration)> {
    // get all responses
    let mut resp_tasks = JoinSet::new();
    //We use enumerate to be able to sort the responses so they are determinstic for a given config
    for (core_conf, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let core_conf = core_conf.clone();

        resp_tasks.spawn(async move {
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

    let time_to_get_responses = start.elapsed();
    tracing::info!(
        "{:?} ###! Received {} public decrypt responses. Since start {:?}",
        request_id.as_str(),
        resp_response_vec.len(),
        time_to_get_responses
    );

    resp_response_vec.sort_by_key(|(conf, _)| conf.party_id);
    let resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();

    // Verify when material is supplied; `None` returns the responses unverified (the perf harness
    // passes `None` and verifies in its own phase).
    if let Some(material) = verification {
        verify_public_decrypt_responses(
            &resp_response_vec,
            material,
            expected_answer,
            internal_client,
            kms_addrs,
            num_expected_responses,
        )?;
        tracing::info!(
            "{:?} ###! Verified public decrypt responses. Since start {:?}",
            request_id.as_str(),
            start.elapsed()
        );
    } else {
        tracing::debug!(
            "{:?} ###! Public decryption result fetched WITHOUT verification (no material supplied).",
            request_id.as_str(),
        );
    }

    Ok((resp_response_vec, time_to_get_responses))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metrics(reconstruction_failed: u64) -> UserDecryptMetrics {
        let sample = [
            tokio::time::Duration::from_millis(10),
            tokio::time::Duration::from_millis(20),
        ];
        UserDecryptMetrics {
            target_rate: 2400,
            duration_secs: 60,
            max_in_flight: 10_000,
            offered: 144_000,
            completed: 143_900,
            failed: 100,
            shed: 0,
            achieved_rate: 2398.3,
            saturated: false,
            request_payload_bytes: 123,
            request_payload_messages: 4,
            request_payload_mib_per_sec: 1.5,
            request_payload_avg_bytes: 30.75,
            response_payload_bytes: 456,
            response_payload_messages: 4,
            response_payload_mib_per_sec: 2.5,
            response_payload_avg_bytes: 114.0,
            reconstruction_failed,
            latency_stat: crate::compute_stat_on_durations(&sample),
            reconstruction_stat: crate::compute_stat_on_durations(&sample),
            reconstruction_wall: tokio::time::Duration::from_millis(5),
        }
    }

    // The `USER_DECRYPT_METRICS` JSON is parsed by
    // ci/perf-testing/argo-workflow/kms-perf-workflow-kms-ci.yaml. This locks
    // the field names/nesting so the serde refactor can't silently drift from that parser.
    #[test]
    fn user_decrypt_metrics_json_matches_ci_parser_contract() {
        let json =
            serde_json::to_string(&UserDecryptMetricsJson::from(&sample_metrics(0))).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["target_rate"], 2400);
        assert_eq!(v["duration"], 60); // renamed from `duration_secs`
        assert_eq!(v["max_in_flight"], 10_000);
        assert_eq!(v["offered"], 144_000);
        assert!(v["achieved_rate"].is_number());
        assert!(v["latency_ms"]["p50"].is_number());
        assert!(v["latency_ms"]["p99"].is_number());
        assert!(v["reconstruction_ms"]["wall"].is_number());
        assert_eq!(v["reconstruction_failed"], 0);

        let v_failed: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&UserDecryptMetricsJson::from(&sample_metrics(3))).unwrap(),
        )
        .unwrap();
        assert_eq!(v_failed["reconstruction_failed"], 3);
    }
}
