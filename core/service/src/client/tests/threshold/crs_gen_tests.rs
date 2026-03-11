cfg_if::cfg_if! {
   if #[cfg(any(feature = "slow_tests", feature = "insecure"))] {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::{future::Future, pin::Pin};

    use execution::tfhe_internals::parameters::DKGParams;
    use kms_grpc::RequestId;
    use kms_grpc::kms::v1::CrsGenRequest;
    use kms_grpc::kms::v1::{Empty, FheParameter};
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use serial_test::serial;
    use tokio::task::JoinSet;
    use tonic::transport::Channel;
    use tonic::{Request, Response, Status};

    use crate::client::client_wasm::Client;
    use crate::client::tests::{common::TIME_TO_SLEEP_MS, threshold::common::threshold_handles};
    use crate::consts::{PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL};
    use crate::cryptography::internal_crypto_types::WrappedDKGParams;
    use crate::dummy_domain;
    use crate::engine::base::derive_request_id;
    use crate::util::key_setup::max_threshold;
    use crate::util::key_setup::test_tools::purge;
    use crate::vault::storage::{file::FileStorage, StorageType};
}}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_insecure_crs_gen_threshold() {
    crs_gen(
        4,
        FheParameter::Test,
        Some(16),
        true, // insecure
        1,
        false, // not concurrent
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn secure_threshold_crs() {
    crs_gen(4, FheParameter::Default, Some(2048), false, 1, false).await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_crs_gen_threshold() {
    crs_gen(4, FheParameter::Test, Some(2048), false, 1, false).await;
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
pub(crate) async fn crs_gen(
    amount_parties: usize,
    parameter: FheParameter,
    max_bits: Option<u32>,
    insecure: bool,
    iterations: usize,
    concurrent: bool,
) {
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    for i in 0..iterations {
        let req_crs: RequestId = derive_request_id(&format!(
            "full_crs_{amount_parties}_{max_bits:?}_{parameter:?}_{i}_{insecure}"
        ))
        .unwrap();
        purge(
            None,
            None,
            &req_crs,
            pub_storage_prefixes,
            priv_storage_prefixes,
        )
        .await;
    }
    let dkg_param: WrappedDKGParams = parameter.into();

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    // The threshold handle should only be started after the storage is purged
    // since the threshold parties will load the CRS from private storage
    let (_kms_servers, kms_clients, internal_client) =
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;

    if concurrent {
        let arc_clients = Arc::new(kms_clients);
        let arc_internalclient = Arc::new(internal_client);
        let mut crs_set = JoinSet::new();
        for i in 0..iterations {
            let cur_id: RequestId = derive_request_id(&format!(
                "full_crs_{amount_parties}_{max_bits:?}_{parameter:?}_{i}_{insecure}"
            ))
            .unwrap();
            crs_set.spawn({
                let clients_clone = Arc::clone(&arc_clients);
                let internalclient_clone = Arc::clone(&arc_internalclient);
                async move {
                    run_crs(
                        parameter,
                        &clients_clone,
                        &internalclient_clone,
                        insecure,
                        &cur_id,
                        max_bits,
                    )
                    .await
                }
            });
        }
        let res = crs_set.join_all().await;
        assert_eq!(res.len(), iterations);
    } else {
        for i in 0..iterations {
            let cur_id: RequestId = derive_request_id(&format!(
                "full_crs_{amount_parties}_{max_bits:?}_{parameter:?}_{i}_{insecure}"
            ))
            .unwrap();
            run_crs(
                parameter,
                &kms_clients,
                &internal_client,
                insecure,
                &cur_id,
                max_bits,
            )
            .await;
        }
    }
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
#[allow(clippy::too_many_arguments)]
pub async fn run_crs(
    parameter: FheParameter,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    insecure: bool,
    crs_req_id: &RequestId,
    max_bits: Option<u32>,
) {
    let dkg_param: WrappedDKGParams = parameter.into();
    let domain = dummy_domain();
    let crs_req = internal_client
        .crs_gen_request(crs_req_id, max_bits, Some(parameter), &domain)
        .unwrap();

    let responses = launch_crs(&vec![crs_req.clone()], kms_clients, insecure).await;
    for response in responses {
        response.unwrap();
    }
    wait_for_crsgen_result(&vec![crs_req], kms_clients, internal_client, &dkg_param).await;
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
async fn launch_crs(
    reqs: &Vec<CrsGenRequest>,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    insecure: bool,
) -> Vec<Result<tonic::Response<Empty>, tonic::Status>> {
    let amount_parties = kms_clients.len();
    let mut tasks_gen = JoinSet::new();
    for req in reqs {
        for i in 1..=amount_parties as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req.clone();
            tasks_gen.spawn(async move {
                if insecure {
                    #[cfg(feature = "insecure")]
                    {
                        cur_client
                            .insecure_crs_gen(tonic::Request::new(req_clone))
                            .await
                    }
                    #[cfg(not(feature = "insecure"))]
                    {
                        panic!("cannot perform insecure crs gen")
                    }
                } else {
                    cur_client.crs_gen(tonic::Request::new(req_clone)).await
                }
            });
        }
    }
    let mut responses_gen = Vec::new();
    while let Some(inner) = tasks_gen.join_next().await {
        let resp = inner.unwrap();
        responses_gen.push(resp);
    }
    assert_eq!(responses_gen.len(), amount_parties * reqs.len());
    responses_gen
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
pub async fn wait_for_crsgen_result(
    reqs: &Vec<CrsGenRequest>,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    param: &DKGParams,
) {
    use futures_util::future::join_all;
    use itertools::Itertools;
    use kms_grpc::rpc_types::protobuf_to_alloy_domain;

    let amount_parties: usize = kms_clients.len();

    // Poll each (client, request) pair independently until all succeed.
    let mut futs = Vec::new();
    for req in reqs {
        let req_id: ProtoRequestId = req.request_id.clone().unwrap();
        for i in 1..=amount_parties as u32 {
            if let Some(client) = kms_clients.get(&i) {
                let client: CoreServiceEndpointClient<Channel> = client.clone();
                futs.push(poll_with_retries(client, i, req_id.clone(), |c, req| {
                    Box::pin(c.get_crs_gen_result(req))
                }));
            }
        }
    }
    let joined_responses = join_all(futs).await;

    // first check the happy path
    // the public parameter is checked in ddec tests, so we don't specifically check _pp
    for req in reqs {
        let req_id: RequestId = req.clone().request_id.unwrap().try_into().unwrap();
        let joined_responses: Vec<_> = joined_responses
            .iter()
            .cloned()
            .filter_map(|(i, rid, resp)| {
                if rid == req_id.into() {
                    Some((i, resp))
                } else {
                    None
                }
            })
            .collect();
        // domain should always exist
        let domain = protobuf_to_alloy_domain(&req.domain.clone().unwrap()).unwrap();

        // we need to setup the storage devices in the right order
        // so that the client can read the CRS
        tracing::debug!(
            "Got {} responses for CRS gen request id {}",
            joined_responses.len(),
            req_id
        );
        let res_storage = joined_responses
            .into_iter()
            .map(|(i, res)| {
                (res, {
                    let prefix = PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[i as usize - 1].as_deref();
                    FileStorage::new(None, StorageType::PUB, prefix).unwrap()
                })
            })
            .collect_vec();
        // Compute threshold < amount_parties/3
        let threshold = max_threshold(amount_parties);
        let min_agree_count = (threshold + 1) as u32;

        let pp = internal_client
            .process_distributed_crs_result(&req_id, res_storage.clone(), &domain, min_agree_count)
            .await
            .unwrap();
        crate::client::crs_gen::tests::verify_pp(param, &pp);

        // if there are [THRESHOLD] result missing, we can still recover the result
        let _pp = internal_client
            .process_distributed_crs_result(
                &req_id,
                res_storage[0..res_storage.len() - threshold].to_vec(),
                &domain,
                min_agree_count,
            )
            .await
            .unwrap();

        // if there are only THRESHOLD results then we do not have consensus as at least THRESHOLD+1 is needed
        assert!(internal_client
            .process_distributed_crs_result(
                &req_id,
                res_storage[0..threshold].to_vec(),
                &domain,
                min_agree_count
            )
            .await
            .is_err());

        // if the request_id is wrong, we get nothing
        let bad_request_id = derive_request_id("bad_request_id").unwrap();
        assert!(internal_client
            .process_distributed_crs_result(
                &bad_request_id,
                res_storage.clone(),
                &domain,
                min_agree_count
            )
            .await
            .is_err());

        // test that having [THRESHOLD] wrong signatures still works
        let mut final_responses_with_bad_sig = res_storage.clone();
        let bad_sig = {
            let mut tmp = res_storage[0].0.external_signature.clone();
            tmp[0] ^= 0xff;
            tmp
        };
        set_signatures(&mut final_responses_with_bad_sig, threshold, &bad_sig);

        let _pp = internal_client
            .process_distributed_crs_result(
                &req_id,
                final_responses_with_bad_sig,
                &domain,
                min_agree_count,
            )
            .await
            .unwrap();

        // having [amount_parties-threshold] wrong signatures won't work
        let mut final_responses_with_bad_sig = res_storage.clone();
        set_signatures(
            &mut final_responses_with_bad_sig,
            amount_parties - threshold,
            &bad_sig,
        );
        assert!(internal_client
            .process_distributed_crs_result(
                &req_id,
                final_responses_with_bad_sig,
                &domain,
                min_agree_count
            )
            .await
            .is_err());

        // having [amount_parties-(threshold+1)] wrong digests still works
        let mut final_responses_with_bad_digest = res_storage.clone();
        set_digests(
            &mut final_responses_with_bad_digest,
            amount_parties - (threshold + 1),
            hex::decode("9fdca770403e2eed9dacb4cdd405a14fc6df7226")
                .unwrap()
                .as_slice(),
        );
        let _pp = internal_client
            .process_distributed_crs_result(
                &req_id,
                final_responses_with_bad_digest,
                &domain,
                min_agree_count,
            )
            .await
            .unwrap();

        // having [amount_parties-threshold] wrong digests will fail
        let mut final_responses_with_bad_digest = res_storage.clone();
        set_digests(
            &mut final_responses_with_bad_digest,
            amount_parties - threshold,
            hex::decode("9fdca770403e2eed9dacb4cdd405a14fc6df7226")
                .unwrap()
                .as_slice(),
        );
        assert!(internal_client
            .process_distributed_crs_result(
                &req_id,
                final_responses_with_bad_digest,
                &domain,
                min_agree_count
            )
            .await
            .is_err());
    }
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
fn set_signatures(
    crs_res_storage: &mut [(kms_grpc::kms::v1::CrsGenResult, FileStorage)],
    count: usize,
    sig: &[u8],
) {
    for (crs_gen_result, _) in crs_res_storage.iter_mut().take(count) {
        crs_gen_result.external_signature = sig.to_vec();
    }
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
fn set_digests(
    crs_res_storage: &mut [(kms_grpc::kms::v1::CrsGenResult, FileStorage)],
    count: usize,
    digest: &[u8],
) {
    for (crs_gen_result, _) in crs_res_storage.iter_mut().take(count) {
        crs_gen_result.crs_digest = digest.to_vec();
    }
}

type ProtoRequestId = kms_grpc::kms::v1::RequestId;

/// Retry a single poll call until it succeeds or we exhaust [`crate::consts::MAX_TRIES`].
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
async fn poll_with_retries<R: Send>(
    mut client: CoreServiceEndpointClient<Channel>,
    server_id: u32,
    req_id: ProtoRequestId,
    poll_fn: impl for<'a> Fn(
        &'a mut CoreServiceEndpointClient<Channel>,
        Request<ProtoRequestId>,
    )
        -> Pin<Box<dyn Future<Output = Result<Response<R>, Status>> + Send + 'a>>,
) -> (u32, ProtoRequestId, R) {
    use crate::consts::MAX_TRIES;

    for count in 0..MAX_TRIES {
        // By default our gRPC calls do not time out. Here we're giving it 2sec per poll attempt to reply.
        tokio::select! {
            result = poll_fn(&mut client, Request::new(req_id.clone())) => {
                match result {
                    Ok(resp) => return (server_id, req_id, resp.into_inner()),
                    Err(e) => {
                        let id_str = RequestId::try_from(req_id.clone()).unwrap().to_string();
                        tracing::trace!("Attempt {count} for server {server_id}, req {id_str}: {e:?}");
                    }
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                tracing::trace!("Attempt {count} for server {server_id} timed out");
            }
        }
        // Back-off a little bit before re-trying
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
    panic!("no response for server {server_id} after {MAX_TRIES} tries");
}
