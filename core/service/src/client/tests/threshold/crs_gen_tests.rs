use crate::client::client_wasm::Client;
use crate::consts::PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL;
use crate::cryptography::internal_crypto_types::WrappedDKGParams;
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::util::key_setup::max_threshold;
use crate::vault::storage::{StorageType, file::FileStorage};
use kms_grpc::RequestId;
use kms_grpc::kms::v1::CrsGenRequest;
use kms_grpc::kms::v1::CrsInfo;
use kms_grpc::kms::v1::{Empty, FheParameter};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use std::collections::HashMap;
use std::path::Path;
use threshold_execution::tfhe_internals::parameters::DKGParams;
use tokio::task::JoinSet;
use tonic::transport::Channel;

cfg_if::cfg_if! {
   if #[cfg(feature = "slow_tests")] {
    use std::sync::Arc;
    use crate::testing::setup::ThresholdTestEnv;
    use crate::testing::prelude::{MaterialType, TestMaterialSpec};
}}

#[tokio::test(flavor = "multi_thread")]
async fn test_insecure_crs_gen_threshold() -> anyhow::Result<()> {
    use crate::consts::TEST_PARAM;
    use crate::testing::prelude::{TestMaterialSpec, ThresholdTestEnv};

    let amount_parties = 4;
    let parameter = FheParameter::Test;
    let max_bits = Some(16);

    // Signing keys for request auth.
    let spec = TestMaterialSpec::threshold_signing_only(amount_parties);

    let env = ThresholdTestEnv::builder()
        .with_test_name("insecure_crs_gen_threshold")
        .with_party_count(amount_parties)
        .with_threshold(1)
        .with_material_spec(spec)
        .with_prss()
        .build()
        .await?;

    let internal_client = env.create_internal_client(&TEST_PARAM, None).await?;
    let (clients, _servers, material_path, _guards) = env.into_parts();

    let crs_req_id: RequestId = derive_request_id(&format!(
        "insecure_crs_gen_threshold_{amount_parties}_{max_bits:?}_{parameter:?}"
    ))?;

    let _ = run_crs(
        parameter,
        &clients,
        &internal_client,
        true, // insecure
        &crs_req_id,
        max_bits,
        Some(&material_path),
    )
    .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn secure_threshold_crs() -> anyhow::Result<()> {
    use crate::consts::DEFAULT_PARAM;
    use crate::testing::prelude::{KeyType, TestMaterialSpec, ThresholdTestEnv};

    let amount_parties = 4;
    let parameter = FheParameter::Default;
    let max_bits = Some(2048);

    let spec = {
        let mut s = TestMaterialSpec::threshold_default(amount_parties);
        s.required_keys.remove(&KeyType::FheKeys);
        s
    };

    let env = ThresholdTestEnv::builder()
        .with_test_name("secure_threshold_crs")
        .with_party_count(amount_parties)
        .with_threshold(1)
        .with_material_spec(spec)
        .with_prss()
        .build()
        .await?;

    let internal_client = env.create_internal_client(&DEFAULT_PARAM, None).await?;
    let (clients, _servers, material_path, _guards) = env.into_parts();

    let crs_req_id: RequestId = derive_request_id(&format!(
        "secure_threshold_crs_{amount_parties}_{max_bits:?}_{parameter:?}"
    ))?;

    let _ = run_crs(
        parameter,
        &clients,
        &internal_client,
        false, // secure
        &crs_req_id,
        max_bits,
        Some(&material_path),
    )
    .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_crs_gen_threshold() -> anyhow::Result<()> {
    use crate::consts::TEST_PARAM;
    use crate::testing::prelude::{TestMaterialSpec, ThresholdTestEnv};

    let amount_parties = 4;
    let parameter = FheParameter::Test;
    let max_bits = Some(2048);

    let spec = TestMaterialSpec::threshold_signing_only(amount_parties);

    let env = ThresholdTestEnv::builder()
        .with_test_name("test_crs_gen_threshold")
        .with_party_count(amount_parties)
        .with_threshold(1)
        .with_material_spec(spec)
        .with_prss()
        .build()
        .await?;

    let internal_client = env.create_internal_client(&TEST_PARAM, None).await?;
    let (clients, _servers, material_path, _guards) = env.into_parts();

    let crs_req_id: RequestId = derive_request_id(&format!(
        "test_crs_gen_threshold_{amount_parties}_{max_bits:?}_{parameter:?}"
    ))?;

    let _ = run_crs(
        parameter,
        &clients,
        &internal_client,
        false, // secure
        &crs_req_id,
        max_bits,
        Some(&material_path),
    )
    .await;

    Ok(())
}

#[cfg(feature = "slow_tests")]
pub(crate) async fn crs_gen(
    amount_parties: usize,
    parameter: FheParameter,
    max_bits: Option<u32>,
    iterations: usize,
    concurrent: bool,
) {
    let dkg_param: WrappedDKGParams = parameter.into();

    // CRS gen needs signing keys (for request auth) but not FHE keys. PRSS is bootstrapped
    // at runtime via `.with_prss()` below.
    let mut spec = TestMaterialSpec::threshold_signing_only(amount_parties);
    if matches!(parameter, FheParameter::Default) {
        spec.material_type = MaterialType::Default;
    }

    let env = ThresholdTestEnv::builder()
        .with_test_name(format!("crs_gen_{amount_parties}_{parameter:?}"))
        .with_party_count(amount_parties)
        .with_material_spec(spec)
        .with_prss()
        .build()
        .await
        .unwrap();
    let internal_client = env.create_internal_client(&dkg_param, None).await.unwrap();
    let (kms_clients, _kms_servers, material_path, _guards) = env.into_parts();

    if concurrent {
        let arc_clients = Arc::new(kms_clients);
        let arc_internalclient = Arc::new(internal_client);
        let mut crs_set = JoinSet::new();
        for i in 0..iterations {
            let cur_id: RequestId = derive_request_id(&format!(
                "full_crs_{amount_parties}_{max_bits:?}_{parameter:?}_{i}"
            ))
            .unwrap();
            crs_set.spawn({
                let clients_clone = Arc::clone(&arc_clients);
                let internalclient_clone = Arc::clone(&arc_internalclient);
                let path_clone = material_path.clone();
                async move {
                    let _ = run_crs(
                        parameter,
                        &clients_clone,
                        &internalclient_clone,
                        false,
                        &cur_id,
                        max_bits,
                        Some(path_clone.as_path()),
                    )
                    .await;
                }
            });
        }
        let res = crs_set.join_all().await;
        assert_eq!(res.len(), iterations);
    } else {
        for i in 0..iterations {
            let cur_id: RequestId = derive_request_id(&format!(
                "full_crs_{amount_parties}_{max_bits:?}_{parameter:?}_{i}"
            ))
            .unwrap();
            let _ = run_crs(
                parameter,
                &kms_clients,
                &internal_client,
                false,
                &cur_id,
                max_bits,
                Some(material_path.as_path()),
            )
            .await;
        }
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn run_crs(
    parameter: FheParameter,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    insecure: bool,
    crs_req_id: &RequestId,
    max_bits: Option<u32>,
    test_path: Option<&Path>,
) -> Vec<CrsInfo> {
    let dkg_param: WrappedDKGParams = parameter.into();
    let domain = dummy_domain();
    let crs_req = internal_client
        .crs_gen_request(crs_req_id, None, None, max_bits, Some(parameter), &domain)
        .unwrap();

    let responses = launch_crs(&vec![crs_req.clone()], kms_clients, insecure).await;
    for response in responses {
        response.unwrap();
    }
    wait_for_crsgen_result(
        &vec![crs_req],
        kms_clients,
        internal_client,
        &dkg_param,
        test_path,
    )
    .await
}
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
                    cur_client
                        .insecure_crs_gen(tonic::Request::new(req_clone))
                        .await
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
pub async fn wait_for_crsgen_result(
    reqs: &Vec<CrsGenRequest>,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    param: &DKGParams,
    test_path: Option<&Path>,
) -> Vec<CrsInfo> {
    let amount_parties = kms_clients.len();
    // wait a bit for the crs generation to finish
    let joined_responses =
        crate::par_poll_responses!(kms_clients, reqs, get_crs_gen_result, amount_parties);

    let mut results = Vec::new();
    // first check the happy path
    // the public parameter is checked in ddec tests, so we don't specifically check _pp
    for req in reqs {
        use itertools::Itertools;
        use kms_grpc::rpc_types::protobuf_to_alloy_domain;

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
        tracing::info!(
            "Got {} responses for CRS gen request id {}",
            joined_responses.len(),
            req_id
        );
        let res_storage = joined_responses
            .into_iter()
            .map(|(i, res)| {
                (res, {
                    let prefix = PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[i as usize - 1].as_deref();
                    FileStorage::new(test_path, StorageType::PUB, prefix).unwrap()
                })
            })
            .collect_vec();
        // Compute threshold < amount_parties/3
        let threshold = max_threshold(amount_parties);
        let min_agree_count = (threshold + 1) as u32;

        let pp = internal_client
            .process_distributed_crs_result(
                &req_id,
                res_storage.clone(),
                &domain,
                req.extra_data.clone(),
                min_agree_count,
            )
            .await
            .unwrap();
        crate::client::crs_gen::tests::verify_pp(param, &pp);

        // if there are [THRESHOLD] result missing, we can still recover the result
        let _pp = internal_client
            .process_distributed_crs_result(
                &req_id,
                res_storage[0..res_storage.len() - threshold].to_vec(),
                &domain,
                req.extra_data.clone(),
                min_agree_count,
            )
            .await
            .unwrap();

        let ref_response = res_storage[0].0.clone();
        results.push(CrsInfo {
            crs_id: ref_response.request_id,
            crs_digest: ref_response.crs_digest,
        });

        // if there are only THRESHOLD results then we do not have consensus as at least THRESHOLD+1 is needed
        assert!(
            internal_client
                .process_distributed_crs_result(
                    &req_id,
                    res_storage[0..threshold].to_vec(),
                    &domain,
                    req.extra_data.clone(),
                    min_agree_count
                )
                .await
                .is_err()
        );

        // if the request_id is wrong, we get nothing
        let bad_request_id = derive_request_id("bad_request_id").unwrap();
        assert!(
            internal_client
                .process_distributed_crs_result(
                    &bad_request_id,
                    res_storage.clone(),
                    &domain,
                    req.extra_data.clone(),
                    min_agree_count
                )
                .await
                .is_err()
        );

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
                req.extra_data.clone(),
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
        assert!(
            internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_sig,
                    &domain,
                    req.extra_data.clone(),
                    min_agree_count
                )
                .await
                .is_err()
        );

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
                req.extra_data.clone(),
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
        assert!(
            internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_digest,
                    &domain,
                    req.extra_data.clone(),
                    min_agree_count
                )
                .await
                .is_err()
        );
    }
    results
}
fn set_signatures(
    crs_res_storage: &mut [(kms_grpc::kms::v1::CrsGenResult, FileStorage)],
    count: usize,
    sig: &[u8],
) {
    for (crs_gen_result, _) in crs_res_storage.iter_mut().take(count) {
        crs_gen_result.external_signature = sig.to_vec();
    }
}
fn set_digests(
    crs_res_storage: &mut [(kms_grpc::kms::v1::CrsGenResult, FileStorage)],
    count: usize,
    digest: &[u8],
) {
    for (crs_gen_result, _) in crs_res_storage.iter_mut().take(count) {
        crs_gen_result.crs_digest = digest.to_vec();
    }
}

// Poll the client method function `f_to_poll` until there is a result
// or error out until some timeout.
// The requests from the `reqs` argument need to implement `RequestIdGetter`.
#[macro_export]
macro_rules! par_poll_responses {
    ($kms_clients:expr,$reqs:expr,$f_to_poll:ident,$amount_parties:expr) => {{
        use $crate::consts::MAX_TRIES;
        let mut joined_responses = vec![];
        for count in 0..MAX_TRIES {
            // Reset the list every time since we get all old results as well
            joined_responses = vec![];
            tokio::time::sleep(tokio::time::Duration::from_secs(30 * $reqs.len() as u64)).await;

            let mut tasks_get = JoinSet::new();
            for req in $reqs {
                for i in 1..=$amount_parties as u32 {
                    // Make sure we only consider clients for which
                    // we haven't killed the corresponding server
                    if let Some(cur_client) = $kms_clients.get(&i) {
                        let mut cur_client = cur_client.clone();
                        let req_id_proto = req.request_id.clone().unwrap();
                        tasks_get.spawn(async move {
                            (
                                i,
                                req_id_proto.clone(),
                                cur_client
                                    .$f_to_poll(tonic::Request::new(req_id_proto))
                                    .await,
                            )
                        });
                    }
                }
            }

            while let Some(res) = tasks_get.join_next().await {
                match res {
                    Ok(inner) => {
                        // Validate if the result returned is ok, if not we ignore, since it likely means that the process is still running on the server
                        if let (j, req_id, Ok(resp)) = inner {
                            joined_responses.push((j, req_id, resp.into_inner()));
                        } else {
                            let (j, req_id, inner_resp) = inner;
                            // Explicitly convert to string to avoid any type conversion issues
                            let req_id_str = match kms_grpc::RequestId::try_from(req_id.clone()).unwrap() {
                                id => id.to_string(),
                            };
                            tracing::info!("Response in iteration {count} for server {j} and req_id {req_id_str} is: {:?}", inner_resp);
                        }
                    }
                    _ => {
                        panic!("Something went wrong while polling for responses");
                    }
                }
            }

            if joined_responses.len() >= $kms_clients.len() * $reqs.len() {
                break;
            }

            // fail if we can't find a response
            if count >= MAX_TRIES - 1 {
                panic!("could not get response after {} tries", count);
            }
        }

        joined_responses
    }};
}
