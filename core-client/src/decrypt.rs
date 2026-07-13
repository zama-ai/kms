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
use std::{collections::HashMap, future::Future, sync::Arc};
use tokio::{
    sync::RwLock,
    task::JoinSet,
    time::{Duration, Instant},
};
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

/// One public-decrypt request paired with its responses and collection latency.
struct CollectedPublicDecrypt {
    req_id: RequestId,
    dec_req: PublicDecryptionRequest,
    resp_response_vec: Vec<PublicDecryptionResponse>,
    collect_duration: Duration,
}

trait CollectedDecryptRateResult {
    fn collect_duration(&self) -> Duration;
    fn response_payload_bytes(&self) -> u64;
    fn response_payload_messages(&self) -> u64;
}

impl CollectedDecryptRateResult for CollectedPublicDecrypt {
    fn collect_duration(&self) -> Duration {
        self.collect_duration
    }

    fn response_payload_bytes(&self) -> u64 {
        self.resp_response_vec
            .iter()
            .map(|response| response.encoded_len() as u64)
            .sum()
    }

    fn response_payload_messages(&self) -> u64 {
        self.resp_response_vec.len() as u64
    }
}

/// Accumulated responses and counters from a single rate-test run.
struct DecryptRateCollection<T> {
    collected: Vec<T>,
    completed: u64,
    durations_to_get_responses: Vec<Duration>,
    collect_elapsed: Duration,
    offered: u64,
    failed: u64,
    shed: u64,
    saturated: bool,
    request_payload_bytes: u64,
    request_payload_messages: u64,
    response_payload_bytes: u64,
    response_payload_messages: u64,
}

/// Metrics computed from a rate-test run: throughput, payloads, and latency stats.
struct DecryptRateMetrics {
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
    post_process_failed: u64,
    latency_stat: crate::DurationStat,
    post_process_stat: crate::DurationStat,
    post_process_wall: Duration,
}

/// JSON-serializable view of [`DecryptRateMetrics`] consumed by the CI parser.
#[derive(serde::Serialize)]
struct DecryptRateMetricsJson {
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
    latency_ms: DurationStatMsJson,
}

/// Per-phase latency percentiles in milliseconds, plus wall-clock duration.
#[derive(serde::Serialize)]
struct PhaseMsJson {
    avg: f64,
    std_dev: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    min: f64,
    max: f64,
    wall: f64,
}

fn duration_stat_with_wall_ms(stat: &crate::DurationStat, wall: Duration) -> PhaseMsJson {
    let stat = duration_stat_ms(stat);
    PhaseMsJson {
        avg: stat.avg,
        std_dev: stat.std_dev,
        p50: stat.p50,
        p95: stat.p95,
        p99: stat.p99,
        min: stat.min,
        max: stat.max,
        wall: wall.as_secs_f64() * 1000.0,
    }
}

impl From<&DecryptRateMetrics> for DecryptRateMetricsJson {
    fn from(m: &DecryptRateMetrics) -> Self {
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
            latency_ms: duration_stat_ms(&m.latency_stat),
        }
    }
}

impl DecryptRateMetrics {
    fn to_json(
        &self,
        failed_field: &'static str,
        timing_field: &'static str,
    ) -> serde_json::Result<String> {
        let mut value = serde_json::to_value(DecryptRateMetricsJson::from(self))?;
        let object = value
            .as_object_mut()
            .expect("metrics JSON starts as an object");
        object.insert(failed_field.to_owned(), self.post_process_failed.into());
        object.insert(
            timing_field.to_owned(),
            serde_json::to_value(duration_stat_with_wall_ms(
                &self.post_process_stat,
                self.post_process_wall,
            ))?,
        );
        serde_json::to_string(&value)
    }

    fn log_json(
        &self,
        marker: &'static str,
        failed_field: &'static str,
        timing_field: &'static str,
    ) {
        match self.to_json(failed_field, timing_field) {
            Ok(metrics) => println!("{marker} {metrics}"),
            Err(e) => tracing::error!("failed to serialize {marker} metrics: {e}"),
        }
    }
}

fn endpoint_clients(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
) -> CoreEndpointClients {
    Arc::<[CoreEndpointClient]>::from(core_endpoints.values().cloned().collect::<Vec<_>>())
}

/// Collect responses from a set of already-spawned per-party fetch tasks, stopping as soon as
/// `num_expected_responses` have arrived and draining the rest in the background. Shared by the
/// public- and user-decrypt collectors, which differ only in how they build `resp_tasks`.
async fn collect_decrypt_responses<Resp: Send + 'static>(
    label: &'static str,
    rate: u64,
    request_start: Instant,
    mut resp_tasks: JoinSet<anyhow::Result<Resp>>,
    num_parties: usize,
    num_expected_responses: usize,
) -> anyhow::Result<(Vec<Resp>, Duration)> {
    let mut resp_response_vec = Vec::with_capacity(num_expected_responses);
    let mut collect_duration = None;
    while let Some(resp) = resp_tasks.join_next().await {
        match resp {
            Ok(Ok(inner)) => resp_response_vec.push(inner),
            Ok(Err(e)) => tracing::debug!("A core failed to return {label} result: {e}"),
            Err(e) => tracing::debug!("{label} response task panicked: {e}"),
        }
        if resp_response_vec.len() >= num_expected_responses {
            collect_duration = Some(request_start.elapsed());
            break;
        }
    }
    if resp_response_vec.len() < num_expected_responses {
        anyhow::bail!(
            "Only got {}/{} {label} responses, need at least {}",
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
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::debug!("Outstanding {label} response failed: {e}"),
                    Err(e) => {
                        tracing::debug!("Outstanding {label} response task panicked: {e}")
                    }
                }
            }
            tracing::debug!(
                rate,
                drained = pending_response_tasks,
                "drained outstanding {label} resp tasks"
            );
        });
    }

    let collect_duration = collect_duration.expect("set once the response quota is met");
    tracing::debug!(
        rate,
        got = resp_response_vec.len(),
        needed = num_expected_responses,
        elapsed = ?collect_duration,
        "{label} resp"
    );
    Ok((resp_response_vec, collect_duration))
}

#[expect(clippy::too_many_arguments)]
async fn send_and_collect_public_decrypt(
    rate: u64,
    req_id: RequestId,
    dec_req: PublicDecryptionRequest,
    core_endpoints_req: CoreEndpointClients,
    core_endpoints_resp: CoreEndpointClients,
    num_parties: usize,
    max_iter: usize,
    num_expected_responses: usize,
) -> anyhow::Result<CollectedPublicDecrypt> {
    let request_start = Instant::now();

    let mut req_tasks = JoinSet::new();
    for ce in core_endpoints_req.iter() {
        let req_cloned = dec_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .public_decrypt(tonic::Request::new(req_cloned))
                .await
        });
    }

    let mut req_response_vec = Vec::with_capacity(core_endpoints_req.len());
    while let Some(inner) = req_tasks.join_next().await {
        match inner {
            Ok(Ok(resp)) => req_response_vec.push(resp.into_inner()),
            Ok(Err(e)) => {
                tracing::debug!("Public decrypt request to a core failed: {e}");
            }
            Err(e) => {
                tracing::debug!("Public decrypt request task panicked: {e}");
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

    let mut resp_tasks = JoinSet::new();
    for ce in core_endpoints_resp.iter() {
        let mut cur_client = ce.clone();
        resp_tasks.spawn(async move {
            let mut response = cur_client
                .get_public_decryption_result(tonic::Request::new(req_id.into()))
                .await;
            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(Duration::from_millis(SLEEP_TIME_BETWEEN_REQUESTS_MS)).await;
                if ctr >= max_iter {
                    anyhow::bail!(
                        "timeout while waiting for public decryption after {max_iter} retries."
                    );
                }
                ctr += 1;
                response = cur_client
                    .get_public_decryption_result(tonic::Request::new(req_id.into()))
                    .await;
            }
            let resp =
                response.map_err(|e| anyhow::anyhow!("public decryption response failed: {e}"))?;
            Ok(resp.into_inner())
        });
    }

    let (resp_response_vec, collect_duration) = collect_decrypt_responses(
        "public decrypt",
        rate,
        request_start,
        resp_tasks,
        num_parties,
        num_expected_responses,
    )
    .await?;

    Ok(CollectedPublicDecrypt {
        req_id,
        dec_req,
        resp_response_vec,
        collect_duration,
    })
}

/// Deterministic ordering key for a public decryption response. Responses are collected
/// concurrently, so their arrival order is non-deterministic; the `verification_key` is the
/// only per-party identifier present on the response itself, so we sort by it to give a
/// stable order. Both the single-shot path here and the `PublicDecryptResult` fetch path
/// (`get_public_decrypt_responses`) sort by this key, so their formatted output matches.
fn public_decrypt_response_sort_key(response: &PublicDecryptionResponse) -> &[u8] {
    response
        .payload
        .as_ref()
        .map(|payload| payload.verification_key.as_slice())
        .unwrap_or_default()
}

async fn verify_public_decrypt(
    internal_client: Arc<RwLock<Client>>,
    kms_addrs: Vec<alloy_primitives::Address>,
    ptxt: TypedPlaintext,
    num_expected_responses: usize,
    collected: CollectedPublicDecrypt,
) -> anyhow::Result<(RequestId, String, Duration)> {
    let CollectedPublicDecrypt {
        req_id,
        dec_req,
        mut resp_response_vec,
        collect_duration: _,
    } = collected;
    let verify_one_start = Instant::now();
    verify_public_decrypt_responses(
        &resp_response_vec,
        PubDecVerificationMaterial::Request(dec_req),
        Some(ptxt),
        &*internal_client.read().await,
        &kms_addrs,
        num_expected_responses,
    )?;
    resp_response_vec.sort_unstable_by(|a, b| {
        public_decrypt_response_sort_key(a).cmp(public_decrypt_response_sort_key(b))
    });
    Ok((
        req_id,
        format!("{resp_response_vec:x?}"),
        verify_one_start.elapsed(),
    ))
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn do_public_decrypt_once<R: Rng + CryptoRng>(
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
    kms_addrs: Vec<alloy_primitives::Address>,
    max_iter: usize,
    num_expected_responses: usize,
    domain: Eip712Domain,
) -> anyhow::Result<Vec<(Option<RequestId>, String)>> {
    let extra_data = crate::extra_data_from_context_epoch(context_id, epoch_id)?;
    let core_endpoints_req = endpoint_clients(core_endpoints_req);
    let core_endpoints_resp = endpoint_clients(core_endpoints_resp);

    let req_id = RequestId::new_random(rng);
    let dec_req = internal_client.write().await.public_decryption_request(
        ct_batch,
        &domain,
        &req_id,
        context_id.as_ref(),
        &key_id.into(),
        epoch_id.as_ref(),
        &extra_data,
    )?;

    let collected = send_and_collect_public_decrypt(
        1,
        req_id,
        dec_req,
        core_endpoints_req,
        core_endpoints_resp,
        num_parties,
        max_iter,
        num_expected_responses,
    )
    .await?;
    let collect_duration = collected.collect_duration;

    let verify_start = Instant::now();
    let (req_id, msg, verify_duration) = verify_public_decrypt(
        internal_client,
        kms_addrs,
        ptxt,
        num_expected_responses,
        collected,
    )
    .await?;
    let verify_elapsed = verify_start.elapsed();

    print_phased_timings(
        "public decrypt",
        collect_duration,
        &[collect_duration],
        verify_elapsed,
    );
    tracing::debug!(elapsed = ?verify_duration, "pdec verify");

    Ok(vec![(Some(req_id), msg)])
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn do_public_decrypt<R: Rng + CryptoRng>(
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
    kms_addrs: Vec<alloy_primitives::Address>,
    max_iter: usize,
    num_expected_responses: usize,
    domain: Eip712Domain,
) -> anyhow::Result<Vec<(Option<RequestId>, String)>> {
    let total_requests = (rate * duration_secs) as usize;
    let extra_data = crate::extra_data_from_context_epoch(context_id, epoch_id)?;
    let core_endpoints_req = endpoint_clients(core_endpoints_req);
    let core_endpoints_resp = endpoint_clients(core_endpoints_resp);

    // PHASE 1: build the request batch before the timed launch window.
    tracing::info!(
        "Prebuilding {total_requests} public decrypt requests: rate={rate}/s, duration={duration_secs}s, max_in_flight={max_in_flight}"
    );
    let mut requests = Vec::with_capacity(total_requests);
    for _ in 0..total_requests {
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

    let mut collection = collect_decrypt_rate(
        "public decrypt",
        rate,
        duration_secs,
        max_in_flight,
        drain_timeout_secs,
        total_requests,
        requests.into_iter(),
        core_endpoints_req.len(),
        |(_req_id, dec_req)| dec_req.encoded_len() as u64,
        |(req_id, dec_req)| {
            let core_endpoints_req = Arc::clone(&core_endpoints_req);
            let core_endpoints_resp = Arc::clone(&core_endpoints_resp);
            send_and_collect_public_decrypt(
                rate,
                req_id,
                dec_req,
                core_endpoints_req,
                core_endpoints_resp,
                num_parties,
                max_iter,
                num_expected_responses,
            )
        },
    )
    .await;

    let collected = std::mem::take(&mut collection.collected);

    // PHASE 4: verify collected responses and emit metrics.
    let verify_start = Instant::now();
    let mut verify_tasks: JoinSet<Result<Duration, anyhow::Error>> = JoinSet::new();
    for collected_result in collected {
        let internal_client = internal_client.clone();
        let kms_addrs = kms_addrs.clone();
        let ptxt = ptxt.clone();
        verify_tasks.spawn(async move {
            verify_public_decrypt(
                internal_client,
                kms_addrs,
                ptxt,
                num_expected_responses,
                collected_result,
            )
            .await
            .map(|(_, _, duration)| duration)
        });
    }

    let mut verification_durations =
        Vec::with_capacity(collection.durations_to_get_responses.len());
    let mut verification_failed = 0_u64;
    while let Some(res) = verify_tasks.join_next().await {
        match res {
            Ok(Ok(verify_duration)) => {
                verification_durations.push(verify_duration);
            }
            Ok(Err(e)) => {
                verification_failed += 1;
                tracing::debug!("Public decrypt verification failed: {e}");
            }
            Err(e) => {
                verification_failed += 1;
                tracing::warn!("Public decrypt verification task panicked: {e}");
            }
        }
    }
    let verify_elapsed = verify_start.elapsed();

    let metrics = decrypt_rate_metrics(
        rate,
        duration_secs,
        max_in_flight,
        &collection,
        verification_failed,
        &verification_durations,
        verify_elapsed,
    );
    metrics.log_json(
        "PUBLIC_DECRYPT_METRICS",
        "verification_failed",
        "verification_ms",
    );
    if verification_failed > 0 {
        tracing::warn!(verification_failed, "public decrypt verification failures");
    }

    print_phased_timings(
        "public decrypt",
        collection.collect_elapsed,
        &collection.durations_to_get_responses,
        verify_elapsed,
    );

    if verification_failed > 0 {
        anyhow::bail!("{verification_failed} public decrypt verifications failed");
    }

    Ok(Vec::new())
}

/// One user-decrypt request paired with its keys, responses, and collection latency.
struct CollectedUserDecrypt {
    req_id: RequestId,
    user_decrypt_req: UserDecryptionRequest,
    enc_pk: UnifiedPublicEncKey,
    enc_sk: UnifiedPrivateEncKey,
    resp_response_vec: Vec<kms_grpc::kms::v1::UserDecryptionResponse>,
    collect_duration: Duration,
}

impl CollectedDecryptRateResult for CollectedUserDecrypt {
    fn collect_duration(&self) -> Duration {
        self.collect_duration
    }

    fn response_payload_bytes(&self) -> u64 {
        self.resp_response_vec
            .iter()
            .map(|response| response.encoded_len() as u64)
            .sum()
    }

    fn response_payload_messages(&self) -> u64 {
        self.resp_response_vec.len() as u64
    }
}

/// Latency percentiles in milliseconds, serialized into rate-test JSON.
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

fn duration_stat_ms(stat: &crate::DurationStat) -> DurationStatMsJson {
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
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

fn drain_finished_decrypts<T: CollectedDecryptRateResult + 'static>(
    label: &'static str,
    join_set: &mut JoinSet<Result<T, anyhow::Error>>,
    collected: &mut Vec<T>,
    durations: &mut Vec<Duration>,
    failed: &mut u64,
) {
    while let Some(result) = join_set.try_join_next() {
        match result {
            Ok(Ok(collected_result)) => {
                durations.push(collected_result.collect_duration());
                collected.push(collected_result);
            }
            Ok(Err(e)) => {
                *failed += 1;
                tracing::debug!("{label} request failed: {e}");
            }
            Err(e) => {
                *failed += 1;
                tracing::warn!("{label} task panicked: {e}");
            }
        }
    }
}

#[expect(clippy::too_many_arguments)]
async fn collect_decrypt_rate<Req, Requests, T, Fut, Spawn, PayloadBytes>(
    label: &'static str,
    rate: u64,
    duration_secs: u64,
    max_in_flight: usize,
    drain_timeout_secs: u64,
    total_requests: usize,
    mut requests: Requests,
    payload_targets_per_request: usize,
    mut request_payload_bytes: PayloadBytes,
    mut spawn_request: Spawn,
) -> DecryptRateCollection<T>
where
    Requests: Iterator<Item = Req>,
    T: CollectedDecryptRateResult + Send + 'static,
    Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
    Spawn: FnMut(Req) -> Fut,
    PayloadBytes: FnMut(&Req) -> u64,
{
    let mut join_set: JoinSet<Result<T, anyhow::Error>> = JoinSet::new();
    let mut collected = Vec::with_capacity(total_requests);
    let mut durations_to_get_responses = Vec::with_capacity(total_requests);
    let mut offered = 0_u64;
    let mut failed = 0_u64;
    let mut shed = 0_u64;
    let mut saturated = false;
    let mut request_payload_bytes_total = 0_u64;
    let mut request_payload_messages = 0_u64;

    // PHASE 2: launch requests at the configured rate and collect completed work.
    let run_start = Instant::now();
    let deadline = run_start + Duration::from_secs(duration_secs);
    let tick_period = Duration::from_millis(5);
    let mut ticker = tokio::time::interval(tick_period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut launch_accumulator = 0_u64;
    // The accumulator assumes a steady 200 ticks/s. With MissedTickBehavior::Delay a
    // stalled iteration pushes ticks late instead of catching up, so the offered rate
    // can quietly fall below target. Count late ticks so that shortfall is observable.
    let mut last_tick = Instant::now();
    let mut late_ticks = 0_u64;

    while Instant::now() < deadline {
        ticker.tick().await;
        let tick_now = Instant::now();
        if tick_now.duration_since(last_tick) > tick_period * 2 {
            late_ticks += 1;
            if late_ticks == 1 {
                tracing::warn!(
                    rate,
                    behind_ms = tick_now.duration_since(last_tick).as_millis() as u64,
                    "{label} ticker fell behind; offered rate may drop below target - underpowered test runner?"
                );
            }
        }
        last_tick = tick_now;
        drain_finished_decrypts(
            label,
            &mut join_set,
            &mut collected,
            &mut durations_to_get_responses,
            &mut failed,
        );

        launch_accumulator = launch_accumulator.saturating_add(rate);
        let launches = launch_accumulator / 200;
        launch_accumulator %= 200;

        for _ in 0..launches {
            let Some(request) = requests.next() else {
                break;
            };
            offered += 1;
            if join_set.len() >= max_in_flight {
                // Shed: client drops this arrival because the in-flight cap says saturated.
                shed += 1;
                saturated = true;
                continue;
            }
            request_payload_bytes_total +=
                request_payload_bytes(&request) * payload_targets_per_request as u64;
            request_payload_messages += payload_targets_per_request as u64;
            join_set.spawn(spawn_request(request));
        }
    }

    if late_ticks > 0 {
        tracing::warn!(
            rate,
            late_ticks,
            offered,
            target = total_requests,
            "{label} ticker fell behind; offered rate likely below target - underpowered test runner?"
        );
    }

    // PHASE 3: drain in-flight requests for a bounded period.
    let drain_deadline = Instant::now() + Duration::from_secs(drain_timeout_secs);
    while !join_set.is_empty() && Instant::now() < drain_deadline {
        if let Ok(Some(result)) =
            tokio::time::timeout_at(drain_deadline, join_set.join_next()).await
        {
            match result {
                Ok(Ok(collected_result)) => {
                    durations_to_get_responses.push(collected_result.collect_duration());
                    collected.push(collected_result);
                }
                Ok(Err(e)) => {
                    failed += 1;
                    tracing::debug!("{label} request failed: {e}");
                }
                Err(e) => {
                    failed += 1;
                    tracing::warn!("{label} task panicked: {e}");
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
        tracing::warn!("{label} drain timed out with {remaining} requests still in flight");
        join_set.abort_all();
    }

    let collect_elapsed = run_start.elapsed();
    let response_payload_bytes = collected
        .iter()
        .map(CollectedDecryptRateResult::response_payload_bytes)
        .sum();
    let response_payload_messages = collected
        .iter()
        .map(CollectedDecryptRateResult::response_payload_messages)
        .sum();

    let completed = collected.len() as u64;
    DecryptRateCollection {
        collected,
        completed,
        durations_to_get_responses,
        collect_elapsed,
        offered,
        failed,
        shed,
        saturated,
        request_payload_bytes: request_payload_bytes_total,
        request_payload_messages,
        response_payload_bytes,
        response_payload_messages,
    }
}

fn decrypt_rate_metrics<T>(
    rate: u64,
    duration_secs: u64,
    max_in_flight: usize,
    collection: &DecryptRateCollection<T>,
    post_process_failed: u64,
    post_process_durations: &[Duration],
    post_process_wall: Duration,
) -> DecryptRateMetrics {
    let request_payload_mib_per_sec = if collection.collect_elapsed.is_zero() {
        0.0
    } else {
        collection.request_payload_bytes as f64
            / 1024.0
            / 1024.0
            / collection.collect_elapsed.as_secs_f64()
    };
    let request_payload_avg_bytes = if collection.request_payload_messages == 0 {
        0.0
    } else {
        collection.request_payload_bytes as f64 / collection.request_payload_messages as f64
    };
    let response_payload_mib_per_sec = if collection.collect_elapsed.is_zero() {
        0.0
    } else {
        collection.response_payload_bytes as f64
            / 1024.0
            / 1024.0
            / collection.collect_elapsed.as_secs_f64()
    };
    let response_payload_avg_bytes = if collection.response_payload_messages == 0 {
        0.0
    } else {
        collection.response_payload_bytes as f64 / collection.response_payload_messages as f64
    };

    DecryptRateMetrics {
        target_rate: rate,
        duration_secs,
        max_in_flight,
        offered: collection.offered,
        completed: collection.completed,
        failed: collection.failed,
        shed: collection.shed,
        // TODO: consider also reporting completed / duration_secs; this includes drain time.
        achieved_rate: collection.completed as f64 / collection.collect_elapsed.as_secs_f64(),
        saturated: collection.saturated,
        request_payload_bytes: collection.request_payload_bytes,
        request_payload_messages: collection.request_payload_messages,
        request_payload_mib_per_sec,
        request_payload_avg_bytes,
        response_payload_bytes: collection.response_payload_bytes,
        response_payload_messages: collection.response_payload_messages,
        response_payload_mib_per_sec,
        response_payload_avg_bytes,
        post_process_failed,
        latency_stat: crate::compute_stat_on_durations(&collection.durations_to_get_responses),
        post_process_stat: crate::compute_stat_on_durations(post_process_durations),
        post_process_wall,
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
    let request_start = Instant::now();

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

    let mut req_response_vec = Vec::with_capacity(core_endpoints_req.len());
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
                tokio::time::sleep(Duration::from_millis(SLEEP_TIME_BETWEEN_REQUESTS_MS)).await;
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
            Ok(resp.into_inner())
        });
    }

    let (resp_response_vec, collect_duration) = collect_decrypt_responses(
        "user decrypt",
        rate,
        request_start,
        resp_tasks,
        num_parties,
        num_expected_responses,
    )
    .await?;

    Ok(CollectedUserDecrypt {
        req_id,
        user_decrypt_req,
        enc_pk,
        enc_sk,
        resp_response_vec,
        collect_duration,
    })
}

async fn reconstruct_user_decrypt(
    internal_client: Arc<RwLock<Client>>,
    expected: TestingPlaintext,
    collected: CollectedUserDecrypt,
) -> anyhow::Result<(RequestId, String, Duration)> {
    let CollectedUserDecrypt {
        req_id,
        user_decrypt_req,
        enc_pk,
        enc_sk,
        resp_response_vec,
        collect_duration: _,
    } = collected;
    let reconstruct_one_start = Instant::now();
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
    let core_endpoints_req = endpoint_clients(core_endpoints_req);
    let core_endpoints_resp = endpoint_clients(core_endpoints_resp);

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

    let reconstruct_start = Instant::now();
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
    let core_endpoints_req = endpoint_clients(core_endpoints_req);
    let core_endpoints_resp = endpoint_clients(core_endpoints_resp);

    // PHASE 1: build the request batch before the timed launch window.
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

    let mut collection = collect_decrypt_rate(
        "user decrypt",
        rate,
        duration_secs,
        max_in_flight,
        drain_timeout_secs,
        total_requests,
        requests.into_iter(),
        core_endpoints_req.len(),
        |(_req_id, user_decrypt_req, _enc_pk, _enc_sk)| user_decrypt_req.encoded_len() as u64,
        |(req_id, user_decrypt_req, enc_pk, enc_sk)| {
            let core_endpoints_req = Arc::clone(&core_endpoints_req);
            let core_endpoints_resp = Arc::clone(&core_endpoints_resp);
            send_and_collect_user_decrypt(
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
            )
        },
    )
    .await;

    let collected = std::mem::take(&mut collection.collected);

    // PHASE 4: reconstruct collected responses and emit metrics.
    let reconstruct_start = Instant::now();
    let mut recon_tasks: JoinSet<Result<Duration, anyhow::Error>> = JoinSet::new();
    for collected_result in collected {
        let internal_client = internal_client.clone();
        recon_tasks.spawn(async move {
            reconstruct_user_decrypt(internal_client, expected, collected_result)
                .await
                .map(|(_, _, duration)| duration)
        });
    }

    let mut reconstruction_durations =
        Vec::with_capacity(collection.durations_to_get_responses.len());
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

    let metrics = decrypt_rate_metrics(
        rate,
        duration_secs,
        max_in_flight,
        &collection,
        reconstruction_failed,
        &reconstruction_durations,
        reconstruct_elapsed,
    );
    metrics.log_json(
        "USER_DECRYPT_METRICS",
        "reconstruction_failed",
        "reconstruction_ms",
    );
    if reconstruction_failed > 0 {
        tracing::warn!(
            reconstruction_failed,
            "user decrypt reconstruction failures"
        );
    }

    print_phased_timings(
        "user decrypt",
        collection.collect_elapsed,
        &collection.durations_to_get_responses,
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
    start: Instant,
) -> anyhow::Result<(Vec<PublicDecryptionResponse>, Duration)> {
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
                tokio::time::sleep(Duration::from_millis(
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
    let mut resp_response_vec = Vec::with_capacity(core_endpoints.len());
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
    tracing::debug!(
        request_id = request_id.as_str(),
        got = resp_response_vec.len(),
        elapsed = ?time_to_get_responses,
        "pdec resp"
    );

    let mut resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();
    resp_response_vec.sort_unstable_by(|a, b| {
        public_decrypt_response_sort_key(a).cmp(public_decrypt_response_sort_key(b))
    });

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
        tracing::debug!(
            request_id = request_id.as_str(),
            elapsed = ?start.elapsed(),
            "pdec verified"
        );
    } else {
        tracing::debug!(
            request_id = request_id.as_str(),
            "pdec fetched without verification"
        );
    }

    Ok((resp_response_vec, time_to_get_responses))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metrics(
        target_rate: u64,
        offered: u64,
        post_process_failed: u64,
    ) -> DecryptRateMetrics {
        let sample = [Duration::from_millis(10), Duration::from_millis(20)];
        DecryptRateMetrics {
            target_rate,
            duration_secs: 60,
            max_in_flight: 10_000,
            offered,
            completed: offered - 100,
            failed: 10,
            shed: 0,
            achieved_rate: target_rate as f64 - 0.2,
            saturated: false,
            request_payload_bytes: 123,
            request_payload_messages: 4,
            request_payload_mib_per_sec: 1.5,
            request_payload_avg_bytes: 30.75,
            response_payload_bytes: 456,
            response_payload_messages: 4,
            response_payload_mib_per_sec: 2.5,
            response_payload_avg_bytes: 114.0,
            post_process_failed,
            latency_stat: crate::compute_stat_on_durations(&sample),
            post_process_stat: crate::compute_stat_on_durations(&sample),
            post_process_wall: Duration::from_millis(5),
        }
    }

    // The `PUBLIC_DECRYPT_METRICS` JSON is parsed by
    // ci/perf-testing/argo-workflow/kms-perf-workflow-kms-ci.yaml. Keep this
    // in lockstep with that shell parser.
    #[test]
    fn public_decrypt_metrics_json_matches_ci_parser_contract() {
        let json = sample_metrics(500, 30_000, 0)
            .to_json("verification_failed", "verification_ms")
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["target_rate"], 500);
        assert_eq!(v["duration"], 60);
        assert_eq!(v["max_in_flight"], 10_000);
        assert_eq!(v["offered"], 30_000);
        assert!(v["achieved_rate"].is_number());
        assert!(v["latency_ms"]["p50"].is_number());
        assert!(v["latency_ms"]["p99"].is_number());
        assert!(v["verification_ms"]["wall"].is_number());
        assert_eq!(v["verification_failed"], 0);

        let v_failed: serde_json::Value = serde_json::from_str(
            &sample_metrics(500, 30_000, 3)
                .to_json("verification_failed", "verification_ms")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(v_failed["verification_failed"], 3);
    }

    // The `USER_DECRYPT_METRICS` JSON is parsed by
    // ci/perf-testing/argo-workflow/kms-perf-workflow-kms-ci.yaml. This locks
    // the field names/nesting so the serde refactor can't silently drift from that parser.
    #[test]
    fn user_decrypt_metrics_json_matches_ci_parser_contract() {
        let json = sample_metrics(2400, 144_000, 0)
            .to_json("reconstruction_failed", "reconstruction_ms")
            .unwrap();
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
            &sample_metrics(2400, 144_000, 3)
                .to_json("reconstruction_failed", "reconstruction_ms")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(v_failed["reconstruction_failed"], 3);
    }
}
