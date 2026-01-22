cfg_if::cfg_if! {
   if #[cfg(any(feature = "slow_tests", feature = "insecure"))] {
    use crate::client::tests::threshold::common::threshold_handles;
    use crate::client::client_wasm::Client;
    use crate::consts::MAX_TRIES;
    use crate::consts::DEFAULT_EPOCH_ID;
    use crate::cryptography::internal_crypto_types::WrappedDKGParams;
    use crate::dummy_domain;
    use crate::engine::base::derive_request_id;
    use crate::engine::base::INSECURE_PREPROCESSING_ID;
    use crate::engine::threshold::service::ThresholdFheKeys;
    use crate::util::key_setup::test_tools::purge;
    use crate::vault::storage::crypto_material::PrivateCryptoMaterialReader;
    use crate::vault::storage::{file::FileStorage, StorageType};
    use kms_grpc::kms::v1::{CompressedKeyConfig, Empty, FheParameter, KeySetAddedInfo, KeySetConfig, KeySetType};
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use kms_grpc::rpc_types::PubDataType;
    use kms_grpc::RequestId;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::str::FromStr;
    use tfhe::integer::compression_keys::DecompressionKey;
    use tfhe::prelude::Tagged;
    use tfhe::shortint::list_compression::NoiseSquashingCompressionPrivateKey;
    use threshold_fhe::execution::runtime::party::Role;
    use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
    use threshold_fhe::execution::tfhe_internals::test_feature::to_hl_client_key;
    use tokio::task::JoinSet;
    use tonic::transport::Channel;
}}

#[cfg(feature = "slow_tests")]
use crate::client::tests::common::TIME_TO_SLEEP_MS;
#[cfg(feature = "insecure")]
use crate::consts::TEST_PARAM;
use crate::consts::{PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL};
#[cfg(feature = "slow_tests")]
use crate::util::rate_limiter::RateLimiterConfig;
use alloy_dyn_abi::Eip712Domain;
use kms_grpc::kms::v1::KeyGenResult;
#[cfg(feature = "slow_tests")]
use kms_grpc::kms::v1::StandardKeySetConfig;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use std::path::Path;
#[cfg(feature = "slow_tests")]
use std::sync::Arc;
#[cfg(feature = "slow_tests")]
use threshold_fhe::execution::tfhe_internals::test_feature::run_decompression_test;
use tonic::{Response, Status};

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(crate) enum TestKeyGenResult {
    DecompressionOnly(DecompressionKey),
    Standard((tfhe::ClientKey, tfhe::CompactPublicKey, tfhe::ServerKey)),
    Compressed(
        (
            tfhe::ClientKey,
            tfhe::CompressedCompactPublicKey,
            tfhe::CompressedServerKey,
        ),
    ),
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
#[allow(dead_code)]
impl TestKeyGenResult {
    fn get_decompression_only(self) -> tfhe::integer::compression_keys::DecompressionKey {
        match self {
            TestKeyGenResult::DecompressionOnly(inner) => inner,
            _ => panic!("expecting to match decompression only"),
        }
    }

    pub(crate) fn get_standard(self) -> (tfhe::ClientKey, tfhe::CompactPublicKey, tfhe::ServerKey) {
        match self {
            TestKeyGenResult::Standard(inner) => inner,
            _ => panic!("expected to find standard"),
        }
    }

    pub(crate) fn get_compressed(
        self,
    ) -> (
        tfhe::ClientKey,
        tfhe::CompressedCompactPublicKey,
        tfhe::CompressedServerKey,
    ) {
        match self {
            TestKeyGenResult::Compressed(inner) => inner,
            _ => panic!("expected to find compressed"),
        }
    }

    fn sanity_check(&self) {
        // encrypt some value, and then decrypt to sanity check the client key
        let expected = 27u8;

        use tfhe::prelude::FheDecrypt;
        use threshold_fhe::execution::tfhe_internals::utils::expanded_encrypt;
        match &self {
            TestKeyGenResult::DecompressionOnly(_) => { /* cannot sanity check */ }
            TestKeyGenResult::Standard((client_key, public_key, server_key)) => {
                tfhe::set_server_key(server_key.clone());
                let ct: tfhe::FheUint8 = expanded_encrypt(public_key, expected, 8).unwrap();
                let pt: u8 = ct.decrypt(client_key);
                assert_eq!(pt, expected);
            }
            TestKeyGenResult::Compressed((client_key, public_key, server_key)) => {
                tfhe::set_server_key(server_key.clone().decompress());
                let ct: tfhe::FheUint8 =
                    expanded_encrypt(&public_key.decompress(), expected, 8).unwrap();
                let actual: u8 = ct.decrypt(client_key);
                assert_eq!(actual, expected);
            }
        }
    }
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
pub(crate) fn standard_keygen_config() -> (Option<KeySetConfig>, Option<KeySetAddedInfo>) {
    (None, None)
}

#[cfg(feature = "slow_tests")]
pub(crate) fn compressed_keygen_config() -> (Option<KeySetConfig>, Option<KeySetAddedInfo>) {
    (
        Some(KeySetConfig {
            keyset_type: KeySetType::Standard.into(),
            standard_keyset_config: Some(StandardKeySetConfig {
                compute_key_type: 0,
                keyset_compression_config: 0,
                compressed_key_config: CompressedKeyConfig::CompressedAll.into(),
            }),
        }),
        None,
    )
}

#[cfg(feature = "slow_tests")]
pub(crate) fn decompression_keygen_config(
    from_keyset_id: &RequestId,
    to_keyset_id: &RequestId,
) -> (Option<KeySetConfig>, Option<KeySetAddedInfo>) {
    (
        Some(KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly.into(),
            standard_keyset_config: None,
        }),
        Some(KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: Some((*from_keyset_id).into()),
            to_keyset_id_decompression_only: Some((*to_keyset_id).into()),
        }),
    )
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
pub(crate) trait KeySetConfigExt {
    fn is_compressed(&self) -> bool;
    fn is_decompression_only(&self) -> bool;
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
impl KeySetConfigExt for Option<KeySetConfig> {
    fn is_compressed(&self) -> bool {
        self.as_ref().is_some_and(|c| {
            c.standard_keyset_config.as_ref().is_some_and(|sc| {
                sc.compressed_key_config == CompressedKeyConfig::CompressedAll as i32
            })
        })
    }

    fn is_decompression_only(&self) -> bool {
        self.as_ref()
            .is_some_and(|c| c.keyset_type == KeySetType::DecompressionOnly as i32)
    }
}

#[cfg(feature = "insecure")]
#[rstest::rstest]
#[case(4)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_insecure_dkg(#[case] amount_parties: usize) {
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let key_id: RequestId = derive_request_id(&format!(
        "test_insecure_dkg_key_{amount_parties}_{TEST_PARAM:?}"
    ))
    .unwrap();
    purge(
        None,
        None,
        &key_id,
        pub_storage_prefixes,
        priv_storage_prefixes,
    )
    .await;
    let (_kms_servers, kms_clients, internal_client) =
        threshold_handles(TEST_PARAM, amount_parties, true, None, None).await;
    let (keyset_config, keyset_added_info) = standard_keygen_config();
    let keys = run_threshold_keygen(
        FheParameter::Test,
        &kms_clients,
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id,
        keyset_config,
        keyset_added_info,
        true,
        None,
        0,
    )
    .await
    .0;
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
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];

    let key_id: RequestId = derive_request_id(&format!(
        "default_insecure_dkg_key_{amount_parties}_{param:?}",
    ))
    .unwrap();
    purge(
        None,
        None,
        &key_id,
        pub_storage_prefixes,
        priv_storage_prefixes,
    )
    .await;
    let (_kms_servers, kms_clients, internal_client) =
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;
    let (keyset_config, keyset_added_info) = standard_keygen_config();
    let keys = run_threshold_keygen(
        param,
        &kms_clients,
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id,
        keyset_config,
        keyset_added_info,
        true,
        None,
        0,
    )
    .await
    .0;

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

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn secure_threshold_keygen_test() {
    preproc_and_keygen(
        4,
        FheParameter::Test,
        false,
        1,
        false,
        None,
        None,
        None,
        false,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn secure_threshold_keygen_test_crash_online() {
    preproc_and_keygen(
        4,
        FheParameter::Test,
        false,
        1,
        false,
        None,
        Some(vec![2]),
        None,
        false,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn secure_threshold_keygen_test_crash_preprocessing() {
    preproc_and_keygen(
        4,
        FheParameter::Test,
        false,
        1,
        false,
        Some(vec![3]),
        None,
        None,
        false,
    )
    .await;
}

/// Test compressed keygen with test parameters and 4 parties.
/// This tests the `compressed_keygen` code path where keys are generated
/// using XOF-seeded compression instead of the standard keygen.
#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[tracing_test::traced_test]
#[serial]
async fn secure_threshold_compressed_keygen_test() {
    preproc_and_keygen(
        4,
        FheParameter::Test,
        false,
        1,
        false,
        None,
        None,
        None,
        true, // compressed = true
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
pub(crate) async fn run_threshold_keygen(
    parameter: FheParameter,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    preproc_req_id: &RequestId,
    keygen_req_id: &RequestId,
    keyset_config: Option<KeySetConfig>,
    keyset_added_info: Option<KeySetAddedInfo>,
    insecure: bool,
    data_root_path: Option<&Path>,
    expected_num_parties_crashed: usize,
) -> (TestKeyGenResult, Option<HashMap<Role, ThresholdFheKeys>>) {
    let domain = dummy_domain();
    let req_keygen = internal_client
        .key_gen_request(
            keygen_req_id,
            preproc_req_id,
            None,
            None,
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
        *preproc_req_id,
        kms_clients,
        internal_client,
        insecure,
        &keyset_config,
        data_root_path,
        expected_num_parties_crashed,
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
    for kms_client in kms_clients.values() {
        //Send kg request
        let mut cur_client = kms_client.clone();
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
#[allow(clippy::too_many_arguments)]
async fn wait_for_keygen_result(
    req_get_keygen: RequestId,
    req_preproc: RequestId,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    insecure: bool,
    keyset_config: &Option<KeySetConfig>,
    data_root_path: Option<&Path>,
    expected_num_parties_crashed: usize,
) -> (TestKeyGenResult, Option<HashMap<Role, ThresholdFheKeys>>) {
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
        for (i, kms_client) in kms_clients {
            let req_clone = req_get_keygen.into();
            let i = *i;
            let mut cur_client = kms_client.clone();
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
    let mut all_private_keys = None;
    if keyset_config.is_decompression_only() {
        let mut serialized_ref_decompression_key = Vec::new();
        for (idx, kg_res) in finished.into_iter() {
            let role = Role::indexed_from_one(idx as usize);
            let storage_prefix = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[idx as usize - 1];
            let kg_res = kg_res.unwrap().into_inner();
            let storage =
                FileStorage::new(data_root_path, StorageType::PUB, storage_prefix.as_deref())
                    .unwrap();
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
        let compressed = keyset_config.is_compressed();
        let res = verify_keygen_responses(
            finished,
            data_root_path,
            internal_client,
            &req_preproc,
            &req_get_keygen,
            &domain,
            kms_clients.len() + expected_num_parties_crashed,
            compressed,
        )
        .await
        .unwrap();
        (out, all_private_keys) = (Some(res.0), Some(res.1));
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
                &req_preproc,
                None,
                None,
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
    (out.unwrap(), all_private_keys)
}

/// __NOTE__: Parties that are crashed during preproc will also be crashed during keygen
#[cfg(feature = "slow_tests")]
pub(crate) async fn run_threshold_decompression_keygen(
    amount_parties: usize,
    parameter: FheParameter,
    insecure: bool,
) {
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let preproc_id_1 = if insecure {
        *INSECURE_PREPROCESSING_ID
    } else {
        derive_request_id(&format!(
            "decom_dkg_preproc_{amount_parties}_{parameter:?}_1"
        ))
        .unwrap()
    };
    let key_id_1: RequestId =
        derive_request_id(&format!("decom_dkg_key_{amount_parties}_{parameter:?}_1")).unwrap();
    purge(
        None,
        None,
        &key_id_1,
        pub_storage_prefixes,
        priv_storage_prefixes,
    )
    .await;

    let preproc_id_2 = if insecure {
        *INSECURE_PREPROCESSING_ID
    } else {
        derive_request_id(&format!(
            "decom_dkg_preproc_{amount_parties}_{parameter:?}_2"
        ))
        .unwrap()
    };
    let key_id_2: RequestId =
        derive_request_id(&format!("decom_dkg_key_{amount_parties}_{parameter:?}_2")).unwrap();
    purge(
        None,
        None,
        &key_id_2,
        pub_storage_prefixes,
        priv_storage_prefixes,
    )
    .await;

    let preproc_id_3 = derive_request_id(&format!(
        "decom_dkg_preproc_{amount_parties}_{parameter:?}_3"
    ))
    .unwrap();
    let key_id_3: RequestId =
        derive_request_id(&format!("decom_dkg_key_{amount_parties}_{parameter:?}_3")).unwrap();
    purge(
        None,
        None,
        &key_id_3,
        pub_storage_prefixes,
        priv_storage_prefixes,
    )
    .await;

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let dkg_param: WrappedDKGParams = parameter.into();
    let (kms_servers, kms_clients, internal_client) =
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;

    if !insecure {
        run_preproc(
            amount_parties,
            parameter,
            &kms_clients,
            &internal_client,
            &preproc_id_1,
            None,
            0,
            None,
        )
        .await;
    }

    let (keyset_config, keyset_added_info) = standard_keygen_config();
    let keys1 = run_threshold_keygen(
        parameter,
        &kms_clients,
        &internal_client,
        &preproc_id_1,
        &key_id_1,
        keyset_config,
        keyset_added_info,
        insecure,
        None,
        0,
    )
    .await
    .0;
    let (client_key_1, _public_key_1, server_key_1) = keys1.get_standard();

    if !insecure {
        run_preproc(
            amount_parties,
            parameter,
            &kms_clients,
            &internal_client,
            &preproc_id_2,
            None,
            0,
            None,
        )
        .await;
    }

    let (keyset_config, keyset_added_info) = standard_keygen_config();
    let keys2 = run_threshold_keygen(
        parameter,
        &kms_clients,
        &internal_client,
        &preproc_id_2,
        &key_id_2,
        keyset_config,
        keyset_added_info,
        insecure,
        None,
        0,
    )
    .await
    .0;
    let (client_key_2, _public_key_2, _server_key_2) = keys2.get_standard();

    // We always need to run preproc for the last keygen
    run_preproc(
        amount_parties,
        parameter,
        &kms_clients,
        &internal_client,
        &preproc_id_3,
        None,
        0,
        None,
    )
    .await;

    // finally do the decompression keygen between the first and second keysets
    let (keyset_config, keyset_added_info) = decompression_keygen_config(&key_id_1, &key_id_2);
    let decompression_key = run_threshold_keygen(
        parameter,
        &kms_clients,
        &internal_client,
        &preproc_id_3,
        &key_id_3,
        keyset_config,
        keyset_added_info,
        insecure,
        None,
        0,
    )
    .await
    .0
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

#[cfg(feature = "slow_tests")]
#[allow(clippy::too_many_arguments)]
/// __NOTE__: Parties that are crashed during preproc will also be crashed during keygen
pub(crate) async fn preproc_and_keygen(
    amount_parties: usize,
    parameter: FheParameter,
    insecure_key_gen: bool,
    iterations: usize,
    concurrent: bool,
    party_ids_to_crash_preproc: Option<Vec<usize>>,
    party_ids_to_crash_keygen: Option<Vec<usize>>,
    partial_preproc: Option<kms_grpc::kms::v1::PartialKeyGenPreprocParams>,
    compressed: bool,
) {
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let mut preproc_ids = vec![];
    let mut key_ids = vec![];
    for i in 0..iterations {
        let req_preproc: RequestId = derive_request_id(&format!(
            "full_dkg_preproc_{amount_parties}_{parameter:?}_{compressed}_{i}"
        ))
        .unwrap();
        purge(
            None,
            None,
            &req_preproc,
            pub_storage_prefixes,
            priv_storage_prefixes,
        )
        .await;
        preproc_ids.push(req_preproc);

        let req_key: RequestId = derive_request_id(&format!(
            "full_dkg_key_{amount_parties}_{parameter:?}_{compressed}_{i}"
        ))
        .unwrap();
        purge(
            None,
            None,
            &req_key,
            pub_storage_prefixes,
            priv_storage_prefixes,
        )
        .await;
        key_ids.push(req_key);
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
        reshare: 1,
    };

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (mut kms_servers, mut kms_clients, mut internal_client) = threshold_handles(
        *dkg_param,
        amount_parties,
        true,
        Some(rate_limiter_conf),
        None,
    )
    .await;

    let mut expected_num_parties_crashed =
        party_ids_to_crash_preproc.as_ref().map_or(0, |v| v.len());

    //Crash the parties that should be crashed during preproc
    for party_id in party_ids_to_crash_preproc.clone().unwrap_or_default() {
        tracing::warn!("Crashin party {party_id} during preproc (on purpose)");
        let kms_server = kms_servers.remove(&(party_id as u32)).unwrap();
        kms_server.assert_shutdown().await;
        let _kms_client = kms_clients.remove(&(party_id as u32)).unwrap();
    }

    if concurrent {
        use tfhe::core_crypto::commons::utils::ZipChecked;

        let arc_clients = Arc::new(kms_clients);
        let arc_internalclient = Arc::new(internal_client);
        let mut preprocset = JoinSet::new();
        for preproc_id in preproc_ids.iter() {
            let preproc_id = *preproc_id;
            preprocset.spawn({
                let clients_clone = Arc::clone(&arc_clients);
                let internalclient_clone = Arc::clone(&arc_internalclient);
                async move {
                    run_preproc(
                        amount_parties,
                        parameter,
                        &clients_clone,
                        &internalclient_clone,
                        &preproc_id,
                        None,
                        expected_num_parties_crashed,
                        partial_preproc,
                    )
                    .await
                }
            });
        }
        // Ensure preprocessing is done, otherwise we risk getting blocked by the rate limiter in keygen
        preprocset.join_all().await;

        // Taking back ownership of the clients to remove those we need to crash
        let mut kms_clients = Arc::try_unwrap(arc_clients).unwrap();
        // Now crash the parties that should be crashed during keygen
        for party_id in party_ids_to_crash_keygen.unwrap_or_default() {
            if party_ids_to_crash_preproc
                .clone()
                .unwrap_or_default()
                .contains(&party_id)
            {
                // party already crashed during preproc
                continue;
            }
            tracing::warn!("Crashin party {party_id} during keygen (on purpose)");
            let kms_server = kms_servers.remove(&(party_id as u32)).unwrap();
            kms_server.assert_shutdown().await;
            let _kms_client = kms_clients.remove(&(party_id as u32)).unwrap();
            expected_num_parties_crashed += 1;
        }

        let arc_clients = Arc::new(kms_clients);
        let mut keyset = JoinSet::new();
        for (key_id, preproc_id) in key_ids.iter().zip_checked(&preproc_ids) {
            let key_id = *key_id;
            let preproc_id = *preproc_id;
            let (keyset_config, keyset_added_info) = standard_keygen_config();
            keyset.spawn({
                let clients_clone = Arc::clone(&arc_clients);
                let internalclient_clone = Arc::clone(&arc_internalclient);
                async move {
                    // todo proper use of insecure to skip preproc
                    (
                        key_id,
                        run_threshold_keygen(
                            parameter,
                            &clients_clone,
                            &internalclient_clone,
                            &preproc_id,
                            &key_id,
                            keyset_config,
                            keyset_added_info,
                            insecure_key_gen,
                            None,
                            expected_num_parties_crashed,
                        )
                        .await
                        .0,
                    )
                }
            });
        }
        let all_key_sets = keyset.join_all().await;
        for (key_id, keyset) in all_key_sets {
            // blockchain parameters always have mod switch noise reduction key

            let (client_key, public_key, server_key) = keyset.get_standard();
            let tag: tfhe::Tag = key_id.into();
            assert_eq!(&tag, client_key.tag());
            assert_eq!(&tag, public_key.tag());
            assert_eq!(&tag, server_key.tag());
            crate::client::key_gen::tests::check_conformance(server_key, client_key);
        }
        tracing::info!("Finished concurrent preproc and keygen");
    } else {
        use tfhe::core_crypto::commons::utils::ZipChecked;

        for preproc_id in preproc_ids.iter() {
            run_preproc(
                amount_parties,
                parameter,
                &kms_clients,
                &internal_client,
                preproc_id,
                None,
                expected_num_parties_crashed,
                partial_preproc,
            )
            .await;
        }
        // Now crash the parties that should be crashed during keygen
        for party_id in party_ids_to_crash_keygen.unwrap_or_default() {
            if party_ids_to_crash_preproc
                .clone()
                .unwrap_or_default()
                .contains(&party_id)
            {
                // party already crashed during preproc
                continue;
            }
            tracing::warn!("Crashin party {party_id} during keygen (on purpose)");
            let kms_server = kms_servers.remove(&(party_id as u32)).unwrap();
            kms_server.assert_shutdown().await;
            let _kms_client = kms_clients.remove(&(party_id as u32)).unwrap();
            expected_num_parties_crashed += 1;
        }
        for (key_id, preproc_id) in key_ids.iter().zip_checked(&preproc_ids) {
            let (keyset_config, keyset_added_info) = if compressed {
                compressed_keygen_config()
            } else {
                standard_keygen_config()
            };
            let keyset = run_threshold_keygen(
                parameter,
                &kms_clients,
                &internal_client,
                preproc_id,
                key_id,
                keyset_config,
                keyset_added_info,
                insecure_key_gen,
                None,
                expected_num_parties_crashed,
            )
            .await
            .0;

            if compressed {
                // blockchain parameters always have mod switch noise reduction key
                let (client_key, public_key, server_key) = keyset.get_compressed();
                let tag: tfhe::Tag = (*key_id).into();
                assert_eq!(&tag, client_key.tag());
                assert_eq!(&tag, public_key.tag());
                assert_eq!(&tag, server_key.tag());
                crate::client::key_gen::tests::check_conformance_compressed(server_key, client_key);
            } else {
                // blockchain parameters always have mod switch noise reduction key
                let (client_key, public_key, server_key) = keyset.get_standard();
                let tag: tfhe::Tag = (*key_id).into();
                assert_eq!(&tag, client_key.tag());
                assert_eq!(&tag, public_key.tag());
                assert_eq!(&tag, server_key.tag());
                crate::client::key_gen::tests::check_conformance(server_key, client_key);
            }

            use crate::{
                client::tests::threshold::public_decryption_tests::run_decryption_threshold,
                util::key_setup::test_tools::{EncryptionConfig, TestingPlaintext},
            };
            // Run a DDec
            run_decryption_threshold(
                amount_parties,
                &mut kms_servers,
                &mut kms_clients,
                &mut internal_client,
                key_id,
                None,
                vec![TestingPlaintext::U8(u8::MAX)],
                EncryptionConfig {
                    compression: true,
                    precompute_sns: true,
                },
                None,
                1,
                None,
                compressed,
            )
            .await;
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_preproc(
    amount_parties: usize,
    parameter: FheParameter,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    preproc_req_id: &RequestId,
    decompression_keygen: Option<(RequestId, RequestId)>,
    expected_num_parties_crashed: usize,
    partial_preproc: Option<kms_grpc::kms::v1::PartialKeyGenPreprocParams>,
) {
    let keyset_config = decompression_keygen.map(|(_from, _to)| KeySetConfig {
        keyset_type: KeySetType::DecompressionOnly.into(),
        standard_keyset_config: None,
    });

    let domain = dummy_domain();

    let mut tasks_gen = JoinSet::new();
    let preproc_request = if let Some(partial_preproc) = partial_preproc {
        let preproc_request = internal_client
            .partial_preproc_request(
                preproc_req_id,
                Some(parameter),
                None,
                None,
                keyset_config,
                &domain,
                Some(partial_preproc),
            )
            .unwrap();

        // Execute partial preprocessing
        for (_, cur_client) in kms_clients.iter() {
            let mut cur_client = cur_client.clone();
            let req_clone = preproc_request.clone();
            tasks_gen.spawn(async move {
                cur_client
                    .partial_key_gen_preproc(tonic::Request::new(req_clone))
                    .await
            });
        }
        preproc_request.base_request.unwrap()
    } else {
        let preproc_request = internal_client
            .preproc_request(
                preproc_req_id,
                Some(parameter),
                None,
                None,
                keyset_config,
                &domain,
            )
            .unwrap();

        // Execute preprocessing
        for (_, cur_client) in kms_clients.iter() {
            let mut cur_client = cur_client.clone();
            let req_clone = preproc_request.clone();
            tasks_gen.spawn(async move {
                cur_client
                    .key_gen_preproc(tonic::Request::new(req_clone))
                    .await
            });
        }
        preproc_request
    };
    let preproc_res = tasks_gen.join_all().await;
    preproc_res.iter().for_each(|x| {
        assert!(x.is_ok());
    });
    assert_eq!(
        preproc_res.len() + expected_num_parties_crashed,
        amount_parties
    );

    // the responses should be empty
    let responses = poll_key_gen_preproc_result(preproc_request, kms_clients, MAX_TRIES).await;
    assert!(responses.len() + expected_num_parties_crashed == amount_parties);
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
                .glwe_dimension()
                .to_equivalent_lwe_dimension(dkg_sns_param.sns_params.polynomial_size())
                .0,
            threshold,
        )
        .into_iter()
        .map(|x| x as u128)
        .collect(),
        dkg_sns_param.sns_params.polynomial_size(),
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

/// Enum to hold either standard or compressed public keys during verification
// allow large enum variant for testing
#[allow(clippy::large_enum_variant)]
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
enum RetrievedKeysForVerification {
    Standard(tfhe::ServerKey, tfhe::CompactPublicKey),
    Compressed(tfhe::CompressedServerKey, tfhe::CompressedCompactPublicKey),
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
impl RetrievedKeysForVerification {
    fn serialize(&self) -> (Vec<u8>, Vec<u8>) {
        match self {
            RetrievedKeysForVerification::Standard(sk, pk) => (
                bc2wrap::serialize(sk).unwrap(),
                bc2wrap::serialize(pk).unwrap(),
            ),
            RetrievedKeysForVerification::Compressed(sk, pk) => (
                bc2wrap::serialize(sk).unwrap(),
                bc2wrap::serialize(pk).unwrap(),
            ),
        }
    }
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify_keygen_responses(
    finished: Vec<(u32, Result<Response<KeyGenResult>, Status>)>,
    data_root_path: Option<&Path>,
    internal_client: &Client,
    req_preproc: &RequestId,
    req_get_keygen: &RequestId,
    domain: &Eip712Domain,
    total_num_parties: usize,
    compressed: bool,
) -> Option<(TestKeyGenResult, HashMap<Role, ThresholdFheKeys>)> {
    use itertools::Itertools;

    let mut serialized_ref_pk = Vec::new();
    let mut serialized_ref_server_key = Vec::new();
    let mut all_threshold_fhe_keys = HashMap::new();
    let mut final_keys: Option<RetrievedKeysForVerification> = None;

    for (idx, kg_res) in finished.into_iter().sorted_by_key(|(idx, _)| *idx) {
        let pub_prefix = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[idx as usize - 1];
        let priv_prefix = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[idx as usize - 1];
        let role = Role::indexed_from_one(idx as usize);
        let kg_res = kg_res.unwrap().into_inner();
        let storage =
            FileStorage::new(data_root_path, StorageType::PUB, pub_prefix.as_deref()).unwrap();

        let keys = if compressed {
            let server_key: tfhe::CompressedServerKey = internal_client
                .retrieve_key_no_verification(&kg_res, PubDataType::CompressedServerKey, &storage)
                .await
                .unwrap()
                .unwrap();

            let public_key: tfhe::CompressedCompactPublicKey = internal_client
                .retrieve_key_no_verification(
                    &kg_res,
                    PubDataType::CompressedCompactPublicKey,
                    &storage,
                )
                .await
                .unwrap()
                .unwrap();

            assert_eq!(&tfhe::Tag::from(req_get_keygen), server_key.tag());
            assert_eq!(&tfhe::Tag::from(req_get_keygen), public_key.tag());

            RetrievedKeysForVerification::Compressed(server_key, public_key)
        } else {
            let (server_key, public_key) = internal_client
                .retrieve_server_key_and_public_key(
                    req_preproc,
                    req_get_keygen,
                    &kg_res,
                    domain,
                    &storage,
                )
                .await
                .inspect_err(|e| tracing::error!("error retrieving server and public key: {e}"))
                .unwrap()
                .unwrap();

            assert_eq!(&tfhe::Tag::from(req_get_keygen), server_key.tag());
            assert_eq!(&tfhe::Tag::from(req_get_keygen), public_key.tag());

            RetrievedKeysForVerification::Standard(server_key, public_key)
        };

        let key_id = RequestId::from_str(kg_res.request_id.unwrap().request_id.as_str()).unwrap();
        let priv_storage =
            FileStorage::new(data_root_path, StorageType::PRIV, priv_prefix.as_deref()).unwrap();
        let threshold_fhe_keys =
            ThresholdFheKeys::read_from_storage_at_epoch(&priv_storage, &key_id, &DEFAULT_EPOCH_ID)
                .await
                .unwrap();
        // Note: The sns_key is now part of PublicKeyMaterial enum and cannot be easily cleared.
        // This optimization is skipped, but the test should still work (with more memory usage).
        all_threshold_fhe_keys.insert(role, threshold_fhe_keys);

        // Compare serialized keys across parties
        let (serialized_server_key, serialized_pk) = keys.serialize();
        if role.one_based() == 1 {
            serialized_ref_pk = serialized_pk;
            serialized_ref_server_key = serialized_server_key;
        } else {
            assert_eq!(serialized_ref_pk, serialized_pk);
            assert_eq!(serialized_ref_server_key, serialized_server_key);
        }

        if final_keys.is_none() {
            final_keys = Some(keys);
        }
    }

    let threshold = total_num_parties.div_ceil(3) - 1;
    let (lwe_sk, glwe_sk, sns_glwe_sk, sns_compression_sk) = try_reconstruct_shares(
        internal_client.params,
        threshold,
        all_threshold_fhe_keys.clone(),
    );

    let client_key = to_hl_client_key(
        &internal_client.params,
        req_get_keygen.into(),
        lwe_sk,
        glwe_sk,
        None,
        None,
        Some(sns_glwe_sk),
        sns_compression_sk,
    )
    .unwrap();

    let result = match final_keys.unwrap() {
        RetrievedKeysForVerification::Standard(server_key, public_key) => {
            TestKeyGenResult::Standard((client_key, public_key, server_key))
        }
        RetrievedKeysForVerification::Compressed(server_key, public_key) => {
            TestKeyGenResult::Compressed((client_key, public_key, server_key))
        }
    };

    result.sanity_check();
    Some((result, all_threshold_fhe_keys))
}
