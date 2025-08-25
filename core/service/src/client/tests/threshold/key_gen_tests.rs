cfg_if::cfg_if! {
   if #[cfg(any(feature = "slow_tests", feature = "insecure"))] {
    use crate::client::client_wasm::Client;
    use crate::consts::MAX_TRIES;
    use crate::cryptography::internal_crypto_types::WrappedDKGParams;
    use crate::dummy_domain;
    use crate::engine::base::derive_request_id;
    use crate::engine::threshold::service::ThresholdFheKeys;
    use crate::util::key_setup::test_tools::purge;
    use crate::vault::storage::StorageReader;
    use crate::vault::storage::{file::FileStorage, StorageType};
    use kms_grpc::kms::v1::{Empty, FheParameter, KeySetAddedInfo, KeySetConfig, KeySetType};
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use kms_grpc::rpc_types::PrivDataType;
    use kms_grpc::rpc_types::PubDataType;
    use kms_grpc::RequestId;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::str::FromStr;
    use tfhe::integer::compression_keys::DecompressionKey;
    use tfhe::shortint::list_compression::NoiseSquashingCompressionPrivateKey;
    use threshold_fhe::execution::runtime::party::Role;
    use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
    use tokio::task::JoinSet;
    use tonic::transport::Channel;
}}

#[cfg(feature = "slow_tests")]
use crate::client::tests::common::TIME_TO_SLEEP_MS;
#[cfg(feature = "insecure")]
use crate::consts::TEST_PARAM;
#[cfg(feature = "slow_tests")]
use crate::consts::TEST_THRESHOLD_KEY_ID_4P;
#[cfg(feature = "slow_tests")]
use crate::util::rate_limiter::RateLimiterConfig;
#[cfg(feature = "slow_tests")]
use std::sync::Arc;
#[cfg(feature = "slow_tests")]
use threshold_fhe::execution::tfhe_internals::test_feature::run_decompression_test;

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(crate) enum TestKeyGenResult {
    DecompressionOnly(DecompressionKey),
    Standard((tfhe::ClientKey, tfhe::CompactPublicKey, tfhe::ServerKey)),
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
#[allow(dead_code)]
impl TestKeyGenResult {
    fn get_decompression_only(self) -> tfhe::integer::compression_keys::DecompressionKey {
        match self {
            TestKeyGenResult::DecompressionOnly(inner) => inner,
            TestKeyGenResult::Standard(_) => panic!("expecting to match decompression only"),
        }
    }

    fn get_standard(self) -> (tfhe::ClientKey, tfhe::CompactPublicKey, tfhe::ServerKey) {
        match self {
            TestKeyGenResult::DecompressionOnly(_) => panic!("expected to find standard"),
            TestKeyGenResult::Standard(inner) => inner,
        }
    }
}

#[cfg(feature = "insecure")]
#[rstest::rstest]
#[case(4)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_insecure_dkg(#[case] amount_parties: usize) {
    let key_id: RequestId = derive_request_id(&format!(
        "test_inscure_dkg_key_{amount_parties}_{TEST_PARAM:?}"
    ))
    .unwrap();
    purge(None, None, None, &key_id, amount_parties).await;
    let (_kms_servers, kms_clients, internal_client) =
        super::common::threshold_handles(TEST_PARAM, amount_parties, true, None, None).await;
    let keys = run_threshold_keygen(
        FheParameter::Test,
        &kms_clients,
        &internal_client,
        None,
        &key_id,
        None,
        None,
        true,
    )
    .await;
    _ = keys.clone().get_standard();

    let panic_res = std::panic::catch_unwind(|| keys.get_decompression_only());
    assert!(panic_res.is_err());
}

#[cfg(feature = "insecure")]
#[rstest::rstest]
#[case(4)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_dkg(#[case] amount_parties: usize) {
    // NOTE: amount_parties must not be too high
    // because every party will load all the keys and each ServerKey is 1.5 GB
    // and each private key share is 1 GB. Using 7 parties fails on a 32 GB machine.

    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();

    let key_id: RequestId = derive_request_id(&format!(
        "default_insecure_dkg_key_{amount_parties}_{param:?}",
    ))
    .unwrap();
    purge(None, None, None, &key_id, amount_parties).await;
    let (_kms_servers, kms_clients, internal_client) =
        super::common::threshold_handles(*dkg_param, amount_parties, true, None, None).await;
    let keys = run_threshold_keygen(
        param,
        &kms_clients,
        &internal_client,
        None,
        &key_id,
        None,
        None,
        true,
    )
    .await;

    // check that we have the new mod switch key
    let (client_key, _, server_key) = keys.clone().get_standard();
    crate::client::key_gen::tests::check_conformance(server_key, client_key);

    let panic_res = std::panic::catch_unwind(|| keys.get_decompression_only());
    assert!(panic_res.is_err());
}

#[cfg(all(feature = "slow_tests", feature = "insecure"))]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_insecure_threshold_decompression_keygen() {
    // Note that the first 2 key gens are insecure, but the last is secure as needed to generate decompression keys
    run_threshold_decompression_keygen(4, FheParameter::Test, true).await;
}

// Test threshold sns compression keygen using the testing parameters
// this test will use an existing base key stored under the key ID `TEST_THRESHOLD_KEY_ID_4P`
#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_threshold_sns_compression_keygen() {
    run_threshold_sns_compression_keygen(4, FheParameter::Test, &TEST_THRESHOLD_KEY_ID_4P, false)
        .await;
}

// TODO(2674)
#[cfg(all(feature = "slow_tests", feature = "insecure"))]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[tracing_test::traced_test]
async fn test_insecure_threshold_sns_compression_keygen() {
    run_threshold_sns_compression_keygen(4, FheParameter::Test, &TEST_THRESHOLD_KEY_ID_4P, true)
        .await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn secure_threshold_keygen_test() {
    preproc_and_keygen(4, FheParameter::Test, false, 1, false).await;
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
pub(crate) async fn run_threshold_keygen(
    parameter: FheParameter,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    preproc_req_id: Option<RequestId>,
    keygen_req_id: &RequestId,
    decompression_keygen: Option<(RequestId, RequestId)>,
    sns_compression_keygen: Option<RequestId>,
    insecure: bool,
) -> TestKeyGenResult {
    let keyset_config = match (decompression_keygen, sns_compression_keygen) {
        (None, None) => None,
        (None, Some(_overwrite_keyset_id)) => Some(KeySetConfig {
            keyset_type: KeySetType::AddSnsCompressionKey.into(),
            standard_keyset_config: None,
        }),
        (Some((_from, _to)), None) => Some(KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly.into(),
            standard_keyset_config: None,
        }),
        (Some(_), Some(_)) => {
            panic!("cannot have both decompression and sns compression keygen")
        }
    };
    let keyset_added_info = match (decompression_keygen, sns_compression_keygen) {
        (None, None) => None,
        (None, Some(overwrite_keyset_id)) => Some(KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: None,
            to_keyset_id_decompression_only: None,
            base_keyset_id_for_sns_compression_key: Some(overwrite_keyset_id.into()),
        }),
        (Some((from, to)), None) => Some(KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: Some(from.into()),
            to_keyset_id_decompression_only: Some(to.into()),
            base_keyset_id_for_sns_compression_key: None,
        }),
        (Some(_), Some(_)) => {
            panic!("cannot have both decompression and sns compression keygen")
        }
    };

    let domain = dummy_domain();
    let req_keygen = internal_client
        .key_gen_request(
            keygen_req_id,
            preproc_req_id,
            Some(parameter),
            keyset_config,
            keyset_added_info,
            domain,
        )
        .unwrap();

    let responses = launch_dkg(req_keygen.clone(), kms_clients, insecure).await;
    for response in responses {
        response.unwrap();
    }

    wait_for_keygen_result(
        req_keygen.request_id.clone().try_into().unwrap(),
        preproc_req_id,
        kms_clients,
        internal_client,
        insecure,
        decompression_keygen.is_some(),
    )
    .await
}

//Helper function to launch dkg
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
async fn launch_dkg(
    req_keygen: kms_grpc::kms::v1::KeyGenRequest,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    insecure: bool,
) -> Vec<Result<tonic::Response<Empty>, tonic::Status>> {
    let mut tasks_gen = JoinSet::new();
    for i in 1..=kms_clients.len() as u32 {
        //Send kg request
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        let req_clone = req_keygen.clone();
        tasks_gen.spawn(async move {
            if insecure {
                #[cfg(feature = "insecure")]
                {
                    cur_client
                        .insecure_key_gen(tonic::Request::new(req_clone))
                        .await
                }
                #[cfg(not(feature = "insecure"))]
                {
                    panic!("cannot perform insecure key gen")
                }
            } else {
                cur_client.key_gen(tonic::Request::new(req_clone)).await
            }
        });
    }

    let mut responses_gen = Vec::new();
    while let Some(resp) = tasks_gen.join_next().await {
        responses_gen.push(resp.unwrap());
    }
    responses_gen
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
async fn wait_for_keygen_result(
    req_get_keygen: RequestId,
    req_preproc: Option<RequestId>,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    insecure: bool,
    decompression_keygen: bool,
) -> TestKeyGenResult {
    use threshold_fhe::execution::{
        runtime::party::Role, tfhe_internals::test_feature::to_hl_client_key,
    };
    let domain = dummy_domain();

    let mut finished = Vec::new();
    // Wait at most MAX_TRIES times 15 seconds for all preprocessing to finish
    for _ in 0..MAX_TRIES {
        tokio::time::sleep(tokio::time::Duration::from_secs(if insecure {
            1
        } else {
            15
        }))
        .await;

        let mut tasks = JoinSet::new();
        for i in 1..=kms_clients.len() as u32 {
            let req_clone = req_get_keygen.into();
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            tasks.spawn(async move {
                (
                    i,
                    if insecure {
                        #[cfg(feature = "insecure")]
                        {
                            cur_client
                                .get_insecure_key_gen_result(tonic::Request::new(req_clone))
                                .await
                        }
                        #[cfg(not(feature = "insecure"))]
                        {
                            panic!("cannot perform insecure keygen")
                        }
                    } else {
                        cur_client
                            .get_key_gen_result(tonic::Request::new(req_clone))
                            .await
                    },
                )
            });
        }
        let mut responses = Vec::new();
        while let Some(resp) = tasks.join_next().await {
            responses.push(resp.unwrap());
        }

        finished = responses
            .into_iter()
            .filter(|x| x.1.is_ok())
            .collect::<Vec<_>>();
        if finished.len() == kms_clients.len() {
            break;
        }
    }

    finished.sort_by(|(i, _), (j, _)| i.cmp(j));
    assert_eq!(finished.len(), kms_clients.len());

    let mut out = None;
    if decompression_keygen {
        let mut serialized_ref_decompression_key = Vec::new();
        for (idx, kg_res) in finished.into_iter() {
            let role = Role::indexed_from_one(idx as usize);
            let kg_res = kg_res.unwrap().into_inner();
            let storage = FileStorage::new(None, StorageType::PUB, Some(role)).unwrap();
            let decompression_key: Option<DecompressionKey> = internal_client
                .retrieve_key_no_verification(&kg_res, PubDataType::DecompressionKey, &storage)
                .await
                .unwrap();
            assert!(decompression_key.is_some());
            if role.one_based() == 1 {
                serialized_ref_decompression_key =
                    bc2wrap::serialize(decompression_key.as_ref().unwrap()).unwrap();
            } else {
                assert_eq!(
                    serialized_ref_decompression_key,
                    bc2wrap::serialize(decompression_key.as_ref().unwrap()).unwrap()
                )
            }
            if out.is_none() {
                out = Some(TestKeyGenResult::DecompressionOnly(
                    decompression_key.unwrap(),
                ))
            }
        }
    } else {
        use crate::engine::base::INSECURE_PREPROCESSING_ID;

        let mut serialized_ref_pk = Vec::new();
        let mut serialized_ref_server_key = Vec::new();
        let mut all_threshold_fhe_keys = HashMap::new();
        let mut final_public_key = None;
        let mut final_server_key = None;

        let preproc_id = match req_preproc {
            Some(ref id) => id,
            None => &INSECURE_PREPROCESSING_ID,
        };

        for (idx, kg_res) in finished.into_iter() {
            let role = Role::indexed_from_one(idx as usize);
            let kg_res = kg_res.unwrap().into_inner();
            let storage = FileStorage::new(None, StorageType::PUB, Some(role)).unwrap();

            let (server_key, public_key) = internal_client
                .retrieve_server_key_and_public_key(
                    preproc_id,
                    &req_get_keygen,
                    &kg_res,
                    &domain,
                    &storage,
                )
                .await
                .unwrap()
                .unwrap();

            if role.one_based() == 1 {
                serialized_ref_pk = bc2wrap::serialize(&public_key).unwrap();
                serialized_ref_server_key = bc2wrap::serialize(&server_key).unwrap();
            } else {
                assert_eq!(serialized_ref_pk, bc2wrap::serialize(&public_key).unwrap());
                assert_eq!(
                    serialized_ref_server_key,
                    bc2wrap::serialize(&server_key).unwrap()
                );
            }

            let key_id =
                RequestId::from_str(kg_res.request_id.unwrap().request_id.as_str()).unwrap();
            let priv_storage = FileStorage::new(None, StorageType::PRIV, Some(role)).unwrap();
            let mut threshold_fhe_keys: ThresholdFheKeys = priv_storage
                .read_data(&key_id, &PrivDataType::FheKeyInfo.to_string())
                .await
                .unwrap();
            // we do not need the sns key to reconstruct, remove it to save memory
            threshold_fhe_keys.sns_key = None;
            all_threshold_fhe_keys.insert(role, threshold_fhe_keys);
            if final_public_key.is_none() {
                final_public_key = Some(public_key);
            }
            if final_server_key.is_none() {
                final_server_key = Some(server_key);
            }
        }

        let threshold = kms_clients.len().div_ceil(3) - 1;
        let (lwe_sk, glwe_sk, sns_glwe_sk, sns_compression_sk) =
            try_reconstruct_shares(internal_client.params, threshold, all_threshold_fhe_keys);
        out = Some(TestKeyGenResult::Standard((
            to_hl_client_key(
                &internal_client.params,
                lwe_sk,
                glwe_sk,
                None,
                None,
                Some(sns_glwe_sk),
                sns_compression_sk,
            )
            .unwrap(),
            final_public_key.unwrap(),
            final_server_key.unwrap(),
        )));
    }

    if !insecure {
        // Try to request another kg with the same preproc but another request id,
        // we should see that it fails because the preproc material is consumed.
        //
        // We only test for the secure variant of the dkg because the insecure
        // variant does not use preprocessing material.
        tracing::debug!("starting another dkg with a used preproc ID");
        let other_key_gen_id = derive_request_id("test_dkg other key id").unwrap();
        let keygen_req_data = internal_client
            .key_gen_request(
                &other_key_gen_id,
                req_preproc,
                Some(FheParameter::Test),
                None,
                None,
                domain,
            )
            .unwrap();
        let responses = launch_dkg(keygen_req_data.clone(), kms_clients, insecure).await;
        for response in responses {
            assert_eq!(response.unwrap_err().code(), tonic::Code::NotFound);
        }
    }
    out.unwrap()
}

#[cfg(feature = "slow_tests")]
pub(crate) async fn run_threshold_decompression_keygen(
    amount_parties: usize,
    parameter: FheParameter,
    insecure: bool,
) {
    let preproc_id_1 = if insecure {
        None
    } else {
        Some(
            derive_request_id(&format!(
                "decom_dkg_preproc_{amount_parties}_{parameter:?}_1"
            ))
            .unwrap(),
        )
    };
    let key_id_1: RequestId =
        derive_request_id(&format!("decom_dkg_key_{amount_parties}_{parameter:?}_1")).unwrap();
    purge(None, None, None, &key_id_1, amount_parties).await;

    let preproc_id_2 = if insecure {
        None
    } else {
        Some(
            derive_request_id(&format!(
                "decom_dkg_preproc_{amount_parties}_{parameter:?}_2"
            ))
            .unwrap(),
        )
    };
    let key_id_2: RequestId =
        derive_request_id(&format!("decom_dkg_key_{amount_parties}_{parameter:?}_2")).unwrap();
    purge(None, None, None, &key_id_2, amount_parties).await;

    let preproc_id_3 = derive_request_id(&format!(
        "decom_dkg_preproc_{amount_parties}_{parameter:?}_3"
    ))
    .unwrap();
    let key_id_3: RequestId =
        derive_request_id(&format!("decom_dkg_key_{amount_parties}_{parameter:?}_3")).unwrap();
    purge(None, None, None, &key_id_3, amount_parties).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let dkg_param: WrappedDKGParams = parameter.into();
    let (kms_servers, kms_clients, internal_client) =
        super::common::threshold_handles(*dkg_param, amount_parties, true, None, None).await;

    if !insecure {
        run_preproc(
            amount_parties,
            parameter,
            &kms_clients,
            &internal_client,
            &preproc_id_1.unwrap(),
            None,
            None,
        )
        .await;
    }

    let keys1 = run_threshold_keygen(
        parameter,
        &kms_clients,
        &internal_client,
        preproc_id_1,
        &key_id_1,
        None,
        None,
        insecure,
    )
    .await;
    let (client_key_1, _public_key_1, server_key_1) = keys1.get_standard();

    if !insecure {
        run_preproc(
            amount_parties,
            parameter,
            &kms_clients,
            &internal_client,
            &preproc_id_2.unwrap(),
            None,
            None,
        )
        .await;
    }

    let keys2 = run_threshold_keygen(
        parameter,
        &kms_clients,
        &internal_client,
        preproc_id_2,
        &key_id_2,
        None,
        None,
        insecure,
    )
    .await;
    let (client_key_2, _public_key_2, _server_key_2) = keys2.get_standard();

    // We always need to run preproc for the last keygen
    run_preproc(
        amount_parties,
        parameter,
        &kms_clients,
        &internal_client,
        &preproc_id_3,
        None,
        None,
    )
    .await;

    // finally do the decompression keygen between the first and second keysets
    let decompression_key = run_threshold_keygen(
        parameter,
        &kms_clients,
        &internal_client,
        Some(preproc_id_3),
        &key_id_3,
        Some((key_id_1, key_id_2)),
        None,
        insecure,
    )
    .await
    .get_decompression_only();

    for handle in kms_servers.into_values() {
        handle.assert_shutdown().await;
    }

    run_decompression_test(
        &client_key_1,
        &client_key_2,
        Some(&server_key_1),
        decompression_key.into_raw_parts(),
    );
}

// Run the threshold sns compression keygen protocol
// which should only generate the sns compression key (and its private shares)
// from an existing `base_key_id`. The resulting key should be one that is
// identical to the key under `base_key_id` except for the sns compression key.
#[cfg(feature = "slow_tests")]
async fn run_threshold_sns_compression_keygen(
    amount_parties: usize,
    parameter: FheParameter,
    base_key_id: &RequestId,
    insecure: bool,
) {
    use threshold_fhe::execution::tfhe_internals::test_feature::run_sns_compression_test;
    // for generating the sns compression key
    let preproc_id = if insecure {
        None
    } else {
        Some(
            derive_request_id(&format!(
                "sns_com_dkg_preproc_{amount_parties}_{parameter:?}"
            ))
            .unwrap(),
        )
    };
    let sns_compression_req_id: RequestId =
        derive_request_id(&format!("sns_com_dkg_key_{amount_parties}_{parameter:?}")).unwrap();
    purge(None, None, None, &sns_compression_req_id, amount_parties).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let dkg_param: WrappedDKGParams = parameter.into();
    let (kms_servers, kms_clients, internal_client) =
        super::common::threshold_handles(*dkg_param, amount_parties, true, None, None).await;

    // generate the sns compression key by overwriting the first key
    if !insecure {
        run_preproc(
            amount_parties,
            parameter,
            &kms_clients,
            &internal_client,
            &preproc_id.unwrap(),
            None,
            Some(*base_key_id),
        )
        .await;
    }

    let keys2 = run_threshold_keygen(
        parameter,
        &kms_clients,
        &internal_client,
        preproc_id,
        &sns_compression_req_id,
        None,
        Some(*base_key_id),
        insecure,
    )
    .await;
    let (client_key_2, _public_key_2, server_key_2) = keys2.get_standard();

    for handle in kms_servers.into_values() {
        handle.assert_shutdown().await;
    }

    let pub_storage =
        FileStorage::new(None, StorageType::PUB, Some(Role::indexed_from_one(1))).unwrap();
    let server_key_base: tfhe::ServerKey = internal_client
        .get_key(base_key_id, PubDataType::ServerKey, &pub_storage)
        .await
        .unwrap();
    crate::client::key_gen::tests::identical_keys_except_sns_compression(
        server_key_base,
        server_key_2.clone(),
    )
    .await;
    run_sns_compression_test(client_key_2, server_key_2);
}

#[cfg(feature = "slow_tests")]
pub(crate) async fn preproc_and_keygen(
    amount_parties: usize,
    parameter: FheParameter,
    insecure: bool,
    iterations: usize,
    concurrent: bool,
) {
    for i in 0..iterations {
        let req_preproc: RequestId = derive_request_id(&format!(
            "full_dkg_preproc_{amount_parties}_{parameter:?}_{i}"
        ))
        .unwrap();
        purge(None, None, None, &req_preproc, amount_parties).await;
        let req_key: RequestId =
            derive_request_id(&format!("full_dkg_key_{amount_parties}_{parameter:?}_{i}")).unwrap();
        purge(None, None, None, &req_key, amount_parties).await;
    }

    let dkg_param: WrappedDKGParams = parameter.into();
    // Preproc should use all the tokens in the bucket,
    // then they're returned to the bucket before keygen starts.
    // If something is wrong with the rate limiter logic
    // then the keygen step should fail since there are not enough tokens.
    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100 * 2 * iterations, // Ensure the bucket is big enough to carry out the concurrent requests
        pub_decrypt: 1,
        user_decrypt: 1,
        crsgen: 1,
        preproc: 100,
        keygen: 100,
    };

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (_kms_servers, kms_clients, internal_client) = super::common::threshold_handles(
        *dkg_param,
        amount_parties,
        true,
        Some(rate_limiter_conf),
        None,
    )
    .await;

    if concurrent {
        let arc_clients = Arc::new(kms_clients);
        let arc_internalclient = Arc::new(internal_client);
        let mut preprocset = JoinSet::new();
        let mut preproc_ids = HashMap::new();
        for i in 0..iterations {
            let cur_id: RequestId = derive_request_id(&format!(
                "full_dkg_preproc_{amount_parties}_{parameter:?}_{i}"
            ))
            .unwrap();
            preproc_ids.insert(i, cur_id);
            preprocset.spawn({
                let clients_clone = Arc::clone(&arc_clients);
                let internalclient_clone = Arc::clone(&arc_internalclient);
                async move {
                    run_preproc(
                        amount_parties,
                        parameter,
                        &clients_clone,
                        &internalclient_clone,
                        &cur_id,
                        None,
                        None,
                    )
                    .await
                }
            });
        }
        // Ensure preprocessing is done, otherwise we risk getting blocked by the rate limiter in keygen
        preprocset.join_all().await;
        let mut keyset = JoinSet::new();
        for i in 0..iterations {
            let key_id: RequestId =
                derive_request_id(&format!("full_dkg_key_{amount_parties}_{parameter:?}_{i}"))
                    .unwrap();
            let preproc_ids_clone = preproc_ids.get(&i).unwrap().to_owned();
            keyset.spawn({
                let clients_clone = Arc::clone(&arc_clients);
                let internalclient_clone = Arc::clone(&arc_internalclient);
                async move {
                    // todo proper use of insecure to skip preproc
                    run_threshold_keygen(
                        parameter,
                        &clients_clone,
                        &internalclient_clone,
                        Some(preproc_ids_clone),
                        &key_id,
                        None,
                        None,
                        insecure,
                    )
                    .await
                }
            });
        }
        let all_key_sets = keyset.join_all().await;
        for keyset in all_key_sets {
            // blockchain parameters always have mod switch noise reduction key
            let (client_key, _, server_key) = keyset.get_standard();
            crate::client::key_gen::tests::check_conformance(server_key, client_key);
        }
        tracing::info!("Finished concurrent preproc and keygen");
    } else {
        let mut preproc_ids = HashMap::new();
        for i in 0..iterations {
            let cur_id: RequestId = derive_request_id(&format!(
                "full_dkg_preproc_{amount_parties}_{parameter:?}_{i}"
            ))
            .unwrap();
            run_preproc(
                amount_parties,
                parameter,
                &kms_clients,
                &internal_client,
                &cur_id,
                None,
                None,
            )
            .await;
            preproc_ids.insert(i, cur_id);
        }
        for i in 0..iterations {
            let key_id: RequestId =
                derive_request_id(&format!("full_dkg_key_{amount_parties}_{parameter:?}_{i}"))
                    .unwrap();
            let keyset = run_threshold_keygen(
                parameter,
                &kms_clients,
                &internal_client,
                Some(preproc_ids.get(&i).unwrap().to_owned()),
                &key_id,
                None,
                None,
                insecure,
            )
            .await;
            // blockchain parameters always have mod switch noise reduction key
            let (client_key, _, server_key) = keyset.get_standard();
            crate::client::key_gen::tests::check_conformance(server_key, client_key);
        }
        tracing::info!("Finished sequential preproc and keygen");
    }
}

// TODO parallel preproc needs to be investigated, there are two issues
// 1. for parallelism=4, it took 700, parallelism=2 is 300s, but parallelism=1 is 100s,
// so running preproc in parallel is slower than sequential
// 2. for parallelism=4, sometimes (not always) it fails with
// kms_lib-9439e559ff01deb4(86525,0x16e223000) malloc: Heap corruption detected, free list is damaged at 0x600000650510
// *** Incorrect guard value: 0
// issue: https://github.com/zama-ai/kms-core/issues/663
#[cfg(feature = "slow_tests")]
async fn run_preproc(
    amount_parties: usize,
    parameter: FheParameter,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    preproc_req_id: &RequestId,
    decompression_keygen: Option<(RequestId, RequestId)>,
    sns_compression_keygen: Option<RequestId>,
) {
    let keyset_config = match (decompression_keygen, sns_compression_keygen) {
        (None, None) => None,
        (None, Some(_overwrite_keyset_id)) => Some(KeySetConfig {
            keyset_type: KeySetType::AddSnsCompressionKey.into(),
            standard_keyset_config: None,
        }),
        (Some((_from, _to)), None) => Some(KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly.into(),
            standard_keyset_config: None,
        }),
        (Some(_), Some(_)) => {
            panic!("cannot have both decompression and sns compression keygen")
        }
    };

    let domain = dummy_domain();

    let preproc_request = internal_client
        .preproc_request(preproc_req_id, Some(parameter), keyset_config, &domain)
        .unwrap();

    // Execute preprocessing
    let mut tasks_gen = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        let req_clone = preproc_request.clone();
        tasks_gen.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(req_clone))
                .await
        });
    }
    let preproc_res = tasks_gen.join_all().await;
    preproc_res.iter().for_each(|x| {
        assert!(x.is_ok());
    });
    assert_eq!(preproc_res.len(), amount_parties);

    // the responses should be empty
    let responses = poll_key_gen_preproc_result(preproc_request, kms_clients, MAX_TRIES).await;
    for response in responses {
        internal_client
            .process_preproc_response(preproc_req_id, &domain, &response)
            .unwrap();
    }
}

//Check status of preproc request
#[cfg(feature = "slow_tests")]
async fn poll_key_gen_preproc_result(
    request: kms_grpc::kms::v1::KeyGenPreprocRequest,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    max_iter: usize,
) -> Vec<kms_grpc::kms::v1::KeyGenPreprocResult> {
    let mut resp_tasks = JoinSet::new();
    for (_, client) in kms_clients.iter() {
        let mut client = client.clone();
        let req_id_clone = request.request_id.as_ref().unwrap().clone();

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete preprocessing
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            let mut response = client
                .get_key_gen_preproc_result(tonic::Request::new(req_id_clone.clone()))
                .await;
            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                if ctr >= max_iter {
                    panic!("timeout while waiting for preprocessing after {max_iter} retries");
                }
                ctr += 1;
                response = client
                    .get_key_gen_preproc_result(tonic::Request::new(req_id_clone.clone()))
                    .await;
            }

            (req_id_clone, response.unwrap().into_inner())
        });
    }

    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        // any failures that happen will panic here
        resp_response_vec.push(resp.unwrap().1);
    }
    resp_response_vec
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
fn try_reconstruct_shares(
    param: DKGParams,
    threshold: usize,
    all_threshold_fhe_keys: HashMap<Role, crate::engine::threshold::service::ThresholdFheKeys>,
) -> (
    tfhe::core_crypto::prelude::LweSecretKeyOwned<u64>,
    tfhe::core_crypto::prelude::GlweSecretKeyOwned<u64>,
    tfhe::core_crypto::prelude::GlweSecretKeyOwned<u128>,
    Option<NoiseSquashingCompressionPrivateKey>,
) {
    use tfhe::core_crypto::prelude::GlweSecretKeyOwned;
    use threshold_fhe::execution::tfhe_internals::{
        private_keysets::GlweSecretKeyShareEnum, utils::reconstruct_bit_vec,
    };

    let param_handle = param.get_params_basics_handle();
    let lwe_shares = all_threshold_fhe_keys
        .iter()
        .map(|(k, v)| (*k, v.private_keys.lwe_compute_secret_key_share.data.clone()))
        .collect::<HashMap<_, _>>();
    let lwe_secret_key = reconstruct_bit_vec(lwe_shares, param_handle.lwe_dimension().0, threshold);
    let lwe_secret_key =
        tfhe::core_crypto::prelude::LweSecretKeyOwned::from_container(lwe_secret_key);

    let lwe_enc_shares = all_threshold_fhe_keys
        .iter()
        .map(|(k, v)| {
            (
                *k,
                v.private_keys.lwe_encryption_secret_key_share.data.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    _ = reconstruct_bit_vec(
        lwe_enc_shares,
        param_handle.lwe_hat_dimension().0,
        threshold,
    );

    // normal keygen should always give us a z128 glwe
    let glwe_shares = all_threshold_fhe_keys
        .iter()
        .map(|(k, v)| {
            (
                *k,
                match v.private_keys.glwe_secret_key_share.clone() {
                    GlweSecretKeyShareEnum::Z64(_) => {
                        panic!("expected z128 in glwe shares")
                    }
                    GlweSecretKeyShareEnum::Z128(inner) => inner.data,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    let glwe_sk = GlweSecretKeyOwned::from_container(
        reconstruct_bit_vec(glwe_shares, param_handle.glwe_sk_num_bits(), threshold),
        param_handle.polynomial_size(),
    );

    let sns_lwe_shares = all_threshold_fhe_keys
        .iter()
        .map(|(k, v)| (*k, v.private_keys.glwe_secret_key_share_sns_as_lwe.clone()))
        .filter_map(|(k, v)| match v {
            Some(vv) => Some((k, vv.data)),
            None => None,
        })
        .collect::<HashMap<_, _>>();
    let dkg_sns_param = match param {
        DKGParams::WithoutSnS(_) => panic!("missing sns param"),
        DKGParams::WithSnS(sns_param) => sns_param,
    };
    let sns_glwe_sk = GlweSecretKeyOwned::from_container(
        reconstruct_bit_vec(
            sns_lwe_shares,
            dkg_sns_param
                .sns_params
                .glwe_dimension
                .to_equivalent_lwe_dimension(dkg_sns_param.sns_params.polynomial_size)
                .0,
            threshold,
        )
        .into_iter()
        .map(|x| x as u128)
        .collect(),
        dkg_sns_param.sns_params.polynomial_size,
    );

    let sns_compression_key_shares = all_threshold_fhe_keys
        .iter()
        .map(|(k, v)| (*k, v.private_keys.glwe_sns_compression_key_as_lwe.clone()))
        .filter_map(|(k, v)| match v {
            Some(vv) => Some((k, vv.data)),
            None => None,
        })
        .collect::<HashMap<_, _>>();
    let sns_compression_private_key =
        if let Some(sns_compression_params) = dkg_sns_param.sns_compression_params {
            let sns_compression_key_bits = reconstruct_bit_vec(
                sns_compression_key_shares,
                dkg_sns_param.sns_compression_sk_num_bits(),
                threshold,
            )
            .into_iter()
            .map(|x| x as u128)
            .collect::<Vec<_>>();

            Some(NoiseSquashingCompressionPrivateKey::from_raw_parts(
                GlweSecretKeyOwned::from_container(
                    sns_compression_key_bits,
                    sns_compression_params.packing_ks_polynomial_size,
                ),
                sns_compression_params,
            ))
        } else {
            None
        };

    (
        lwe_secret_key,
        glwe_sk,
        sns_glwe_sk,
        sns_compression_private_key,
    )
}
