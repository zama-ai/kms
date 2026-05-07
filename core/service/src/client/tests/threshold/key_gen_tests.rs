// TODO(dp): the imports here are a noisy mess — two `cfg_if!` blocks plus
// dozens of individually `#[cfg(...)]`-gated `use` lines. Consolidate into
// a single `cfg_if!` per feature combo (or pull the shared imports up out
// of the gates) on a dedicated cleanup pass.
cfg_if::cfg_if! {
   if #[cfg(feature = "slow_tests")] {
    use crate::client::tests::common::default_isolated_extra_data;
    use crate::client::tests::threshold::common::threshold_handles;
    use crate::cryptography::internal_crypto_types::WrappedDKGParams;
    use crate::engine::base::{DSEP_PUBDATA_KEY, KeyGenMetadata, compute_info_uncompressed_keygen};
    use crate::util::key_setup::test_tools::purge;
    use crate::vault::storage::{
        delete_at_request_and_epoch_id, delete_at_request_id,
        read_versioned_at_request_and_epoch_id, read_versioned_at_request_id,
        store_versioned_at_request_and_epoch_id, store_versioned_at_request_id,
    };
    use crate::vault::storage::crypto_material::get_core_signing_key;

    use kms_grpc::rpc_types::PrivDataType;
}}
cfg_if::cfg_if! {
   if #[cfg(any(feature = "slow_tests", feature = "insecure"))] {
    use crate::client::key_gen::tests::check_conformance;
    use crate::client::tests::common::{OptKeySetConfigAccessor};
    use crate::client::client_wasm::Client;
    use crate::consts::MAX_TRIES;
    use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT};
    use crate::dummy_domain;
    use crate::engine::base::derive_request_id;
    use crate::engine::base::INSECURE_PREPROCESSING_ID;
    use crate::engine::threshold::service::ThresholdFheKeys;
    use crate::vault::storage::crypto_material::PrivateCryptoMaterialReader;
    use crate::vault::storage::{file::FileStorage, StorageType};
    use kms_grpc::kms::v1::{Empty, FheParameter, KeySetAddedInfo, KeySetConfig};
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use kms_grpc::rpc_types::PubDataType;
    use kms_grpc::RequestId;
    use std::collections::HashMap;
    use std::str::FromStr;
    use tfhe::integer::compression_keys::DecompressionKey;
    use tfhe::prelude::Tagged;
    use tfhe::shortint::list_compression::NoiseSquashingCompressionPrivateKey;
    use threshold_types::role::Role;
    use threshold_execution::tfhe_internals::parameters::DKGParams;
    use threshold_execution::tfhe_internals::test_feature::to_hl_client_key;
    use tokio::task::JoinSet;
    use tonic::transport::Channel;
}}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use crate::client::tests::common::keygen_config;
#[cfg(feature = "slow_tests")]
use crate::client::tests::common::{
    TIME_TO_SLEEP_MS, decompression_keygen_config, uncompressed_keygen_config,
};
#[cfg(feature = "insecure")]
use crate::client::tests::threshold::common::threshold_insecure_key_gen;
#[cfg(feature = "slow_tests")]
use crate::client::tests::threshold::common::threshold_key_gen_secure;
#[cfg(feature = "slow_tests")]
use crate::client::tests::threshold::public_decryption_tests::run_decryption_threshold;
#[cfg(any(feature = "insecure", feature = "slow_tests"))]
use crate::consts::TEST_PARAM;
#[cfg(feature = "slow_tests")]
use crate::consts::default_extra_data;
use crate::consts::{PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL};
#[cfg(feature = "insecure")]
use crate::engine::utils::make_extra_data;
#[cfg(feature = "slow_tests")]
use crate::testing::helpers::domain_to_msg;
#[cfg(any(feature = "insecure", feature = "slow_tests"))]
use crate::testing::material::{KeyType, TestMaterialSpec};
#[cfg(any(feature = "insecure", feature = "slow_tests"))]
use crate::testing::setup::threshold::ThresholdTestEnv;
#[cfg(any(feature = "insecure", feature = "slow_tests"))]
use crate::util::key_setup::max_threshold;
#[cfg(feature = "slow_tests")]
use crate::util::key_setup::test_tools::{EncryptionConfig, TestingPlaintext};
#[cfg(feature = "slow_tests")]
use crate::util::rate_limiter::RateLimiterConfig;
use alloy_dyn_abi::Eip712Domain;
use kms_grpc::kms::v1::KeyGenResult;
#[cfg(feature = "slow_tests")]
use kms_grpc::kms::v1::KeySetType;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use std::path::Path;
#[cfg(feature = "slow_tests")]
use std::sync::Arc;
#[cfg(feature = "slow_tests")]
use tfhe::core_crypto::commons::utils::ZipChecked;
#[cfg(feature = "slow_tests")]
use threshold_execution::tfhe_internals::test_feature::run_decompression_test;
use tonic::{Response, Status};

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(crate) enum TestKeyGenResult {
    DecompressionOnly(DecompressionKey),
    Uncompressed((tfhe::ClientKey, tfhe::CompactPublicKey, tfhe::ServerKey)),
    Compressed(
        (
            tfhe::ClientKey,
            tfhe::xof_key_set::CompressedXofKeySet,
            tfhe::CompactPublicKey,
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

    pub(crate) fn get_uncompressed(
        self,
    ) -> (tfhe::ClientKey, tfhe::CompactPublicKey, tfhe::ServerKey) {
        match self {
            TestKeyGenResult::Uncompressed(inner) => inner,
            _ => panic!("expected to find uncompressed keys"),
        }
    }

    pub(crate) fn get_compressed(
        self,
    ) -> (
        tfhe::ClientKey,
        tfhe::xof_key_set::CompressedXofKeySet,
        tfhe::CompactPublicKey,
    ) {
        match self {
            TestKeyGenResult::Compressed(inner) => inner,
            _ => panic!("expected to find compressed"),
        }
    }

    fn sanity_check(&self) {
        use tfhe::prelude::FheDecrypt;
        use threshold_execution::tfhe_internals::utils::expanded_encrypt;
        let (client_key, public_key, server_key) = match &self {
            TestKeyGenResult::DecompressionOnly(_) => {
                /* cannot sanity check */
                return;
            }
            TestKeyGenResult::Uncompressed((client_key, public_key, server_key)) => {
                (client_key, public_key.clone(), server_key.clone())
            }
            TestKeyGenResult::Compressed((client_key, keyset, public_key)) => {
                let (_derived_pk, server_key) = keyset.decompress().unwrap().into_raw_parts();
                (client_key, public_key.clone(), server_key)
            }
        };

        crate::client::key_gen::tests::check_oprf_correctness(&server_key, client_key);
        check_conformance(server_key.clone(), client_key.clone());

        let pt1 = 27u8;
        let pt2 = 2u8;

        tfhe::set_server_key(server_key);
        let ct1: tfhe::FheUint8 = expanded_encrypt(&public_key, pt1, 8).unwrap();
        let ct2: tfhe::FheUint8 = expanded_encrypt(&public_key, pt2, 8).unwrap();
        let ct3 = ct1 * ct2;

        let pt: u8 = ct3.decrypt(client_key);
        assert_eq!(pt, pt1 * pt2);
    }
}

/// Test insecure compressed keygen with Test parameters.
/// This tests the insecure `initialize_compressed_key_material` code path where
/// party 1 generates compressed keys locally and shares private key shares with other parties.
// TODO(dp): the migrated tests in this file (and in mpc_context_tests.rs,
// crs_gen_tests.rs, public_decryption_tests.rs, user_decryption_tests.rs)
// share a heavy `ThresholdTestEnv::builder()...build()` + spec-construction
// preamble. A second sweep should factor that out — e.g. a `with_test_setup!`
// macro or a `ThresholdTestEnv::for_test(name, parties, spec_kind)` helper —
// to shrink each test back down to the part that actually varies.
#[cfg(feature = "insecure")]
#[rstest::rstest]
#[case(4)]
#[tokio::test(flavor = "multi_thread")]
async fn test_insecure_compressed_dkg(#[case] amount_parties: usize) -> anyhow::Result<()> {
    let key_id: RequestId = derive_request_id(&format!(
        "test_insecure_compressed_dkg_key_{amount_parties}_{TEST_PARAM:?}"
    ))?;

    // Test generates its own FHE keys; only signing material + PRSS are needed pre-generated.
    let spec = {
        let mut s = TestMaterialSpec::threshold_signing_only(amount_parties);
        s.required_keys.insert(KeyType::PrssSetup);
        s
    };

    let env = ThresholdTestEnv::builder()
        .with_test_name("test_insecure_compressed_dkg")
        .with_party_count(amount_parties)
        .with_threshold(max_threshold(amount_parties) as u8)
        .with_material_spec(spec)
        .with_prss()
        .build()
        .await?;

    let internal_client = env.create_internal_client(&TEST_PARAM, None).await?;
    let (kms_clients, _kms_servers, material_path, _guards) = env.into_parts();

    let (keyset_config, keyset_added_info) = keygen_config();
    let keys = run_threshold_keygen(
        FheParameter::Test,
        &kms_clients,
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id,
        keyset_config,
        keyset_added_info,
        true,
        Some(&material_path),
        0,
    )
    .await
    .0;

    // Verify we got compressed keys
    let _ = keys.clone().get_compressed();

    // Verify it panics when trying to get as uncompressed or decompression
    let panic_res = std::panic::catch_unwind(|| keys.clone().get_uncompressed());
    assert!(panic_res.is_err());
    let panic_res = std::panic::catch_unwind(|| keys.get_decompression_only());
    assert!(panic_res.is_err());

    Ok(())
}

/// Test compressed keygen with test parameters and 4 parties.
/// This tests the `compressed_keygen` code path where keys are generated
/// using XOF-seeded compression instead of the standard keygen.
#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
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
    let extra_data = req_keygen.extra_data.clone();

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
        extra_data,
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
    extra_data: Vec<u8>,
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

    finished.sort_by_key(|(i, _)| *i);
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
            let (decompression_key, _digest): (DecompressionKey, Vec<u8>) = internal_client
                .retrieve_key_no_verification(&kg_res, PubDataType::DecompressionKey, &storage)
                .await
                .unwrap();
            if role.one_based() == 1 {
                serialized_ref_decompression_key = bc2wrap::serialize(&decompression_key).unwrap();
            } else {
                assert_eq!(
                    serialized_ref_decompression_key,
                    bc2wrap::serialize(&decompression_key).unwrap()
                )
            }
            if out.is_none() {
                out = Some(TestKeyGenResult::DecompressionOnly(decompression_key))
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
            extra_data,
            kms_clients.len() + expected_num_parties_crashed,
            None,
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

    let (keyset_config, keyset_added_info) = uncompressed_keygen_config();
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
    let (client_key_1, _public_key_1, server_key_1) = keys1.get_uncompressed();

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

    let (keyset_config, keyset_added_info) = uncompressed_keygen_config();
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
    let (client_key_2, _public_key_2, _server_key_2) = keys2.get_uncompressed();

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
    fn validate_keyset(keyset: TestKeyGenResult, key_id: &RequestId, compressed: bool) {
        let (client_key, public_key, server_key) = if compressed {
            let (client_key, keyset, public_key) = keyset.get_compressed();
            let (_derived_pk, server_key) = keyset.decompress().unwrap().into_raw_parts();
            (client_key, public_key, server_key)
        } else {
            keyset.get_uncompressed()
        };
        let tag: tfhe::Tag = (*key_id).into();
        assert_eq!(&tag, client_key.tag());
        assert_eq!(&tag, public_key.tag());
        assert_eq!(&tag, server_key.tag());
        crate::client::key_gen::tests::check_oprf_correctness(&server_key, &client_key);
        crate::client::key_gen::tests::check_conformance(server_key, client_key);
    }

    /// Crashes specified parties during keygen, returning the count of newly crashed parties.
    /// Skips parties that were already crashed during preprocessing.
    async fn crash_parties_for_keygen(
        party_ids_to_crash: Option<Vec<usize>>,
        party_ids_crashed_in_preproc: &Option<Vec<usize>>,
        kms_servers: &mut HashMap<u32, crate::testing::types::ServerHandle>,
        kms_clients: &mut HashMap<u32, CoreServiceEndpointClient<Channel>>,
    ) -> usize {
        let mut newly_crashed = 0;
        for party_id in party_ids_to_crash.unwrap_or_default() {
            if party_ids_crashed_in_preproc
                .clone()
                .unwrap_or_default()
                .contains(&party_id)
            {
                continue;
            }
            tracing::warn!("Crashin party {party_id} during keygen (on purpose)");
            let kms_server = kms_servers.remove(&(party_id as u32)).unwrap();
            kms_server.assert_shutdown().await;
            let _kms_client = kms_clients.remove(&(party_id as u32)).unwrap();
            newly_crashed += 1;
        }
        newly_crashed
    }

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
        new_epoch: 1,
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
        expected_num_parties_crashed += crash_parties_for_keygen(
            party_ids_to_crash_keygen,
            &party_ids_to_crash_preproc,
            &mut kms_servers,
            &mut kms_clients,
        )
        .await;

        let arc_clients = Arc::new(kms_clients);
        let mut keyset = JoinSet::new();
        for (key_id, preproc_id) in key_ids.iter().zip_checked(&preproc_ids) {
            let key_id = *key_id;
            let preproc_id = *preproc_id;
            let (keyset_config, keyset_added_info) = if compressed {
                keygen_config()
            } else {
                uncompressed_keygen_config()
            };
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
            validate_keyset(keyset, &key_id, compressed);
        }

        // Run decryption tests after keygen completes
        let mut kms_clients = Arc::try_unwrap(arc_clients).unwrap();
        let mut internal_client = Arc::try_unwrap(arc_internalclient).unwrap();
        for key_id in key_ids.iter() {
            run_decryption_threshold(
                amount_parties,
                &mut kms_servers,
                &mut kms_clients,
                &mut internal_client,
                None,
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
            )
            .await;
        }
        tracing::info!("Finished concurrent preproc and keygen");
    } else {
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
        expected_num_parties_crashed += crash_parties_for_keygen(
            party_ids_to_crash_keygen,
            &party_ids_to_crash_preproc,
            &mut kms_servers,
            &mut kms_clients,
        )
        .await;
        for (key_id, preproc_id) in key_ids.iter().zip_checked(&preproc_ids) {
            let (keyset_config, keyset_added_info) = if compressed {
                keygen_config()
            } else {
                uncompressed_keygen_config()
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

            validate_keyset(keyset, key_id, compressed);

            // Run a DDec
            run_decryption_threshold(
                amount_parties,
                &mut kms_servers,
                &mut kms_clients,
                &mut internal_client,
                None,
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
        for cur_client in kms_clients.values() {
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
        for cur_client in kms_clients.values() {
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
    let extra_data = preproc_request.extra_data.clone();
    let responses = poll_key_gen_preproc_result(preproc_request, kms_clients, MAX_TRIES).await;
    assert!(responses.len() + expected_num_parties_crashed == amount_parties);
    for response in responses {
        internal_client
            .process_preproc_response(preproc_req_id, &domain, &response, extra_data.clone())
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
    for client in kms_clients.values() {
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

#[expect(clippy::type_complexity)]
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
    Option<tfhe::core_crypto::prelude::LweSecretKeyOwned<u64>>,
) {
    use tfhe::core_crypto::prelude::GlweSecretKeyOwned;
    use threshold_execution::tfhe_internals::{
        private_keysets::GlweSecretKeyShareEnum, utils::reconstruct_bit_vec,
    };

    let param_handle = param.get_params_basics_handle();
    // Cast to Z64 before reconstruction
    let lwe_shares = all_threshold_fhe_keys
        .iter()
        .map(|(k, v)| {
            (
                *k,
                v.private_keys
                    .lwe_compute_secret_key_share
                    .clone()
                    .convert_to_z64()
                    .data,
            )
        })
        .collect();
    let lwe_secret_key = reconstruct_bit_vec(lwe_shares, param_handle.lwe_dimension().0, threshold);
    let lwe_secret_key =
        tfhe::core_crypto::prelude::LweSecretKeyOwned::from_container(lwe_secret_key);

    let lwe_enc_shares = all_threshold_fhe_keys
        .iter()
        .map(|(k, v)| {
            (
                *k,
                v.private_keys
                    .lwe_encryption_secret_key_share
                    .clone()
                    .convert_to_z64()
                    .data,
            )
        })
        .collect();
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

    let oprf_lwe_shares = all_threshold_fhe_keys
        .iter()
        .filter_map(|(k, v)| {
            v.private_keys
                .oprf_secret_key_share
                .clone()
                .map(|share| (*k, share.convert_to_z64().data))
        })
        .collect::<HashMap<_, _>>();
    let oprf_lwe_secret_key = if oprf_lwe_shares.len() == all_threshold_fhe_keys.len() {
        Some(
            tfhe::core_crypto::prelude::LweSecretKeyOwned::from_container(reconstruct_bit_vec(
                oprf_lwe_shares,
                param_handle.lwe_dimension().0,
                threshold,
            )),
        )
    } else {
        None
    };

    (
        lwe_secret_key,
        glwe_sk,
        sns_glwe_sk,
        sns_compression_private_key,
        oprf_lwe_secret_key,
    )
}

/// Enum to hold either standard or compressed public keys during verification
// allow large enum variant for testing
#[allow(clippy::large_enum_variant)]
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
enum RetrievedKeysForVerification {
    Standard(tfhe::ServerKey, tfhe::CompactPublicKey),
    Compressed(
        tfhe::xof_key_set::CompressedXofKeySet,
        tfhe::CompactPublicKey,
    ),
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
impl RetrievedKeysForVerification {
    fn to_bytes_for_verification(&self) -> Vec<u8> {
        match self {
            RetrievedKeysForVerification::Standard(sk, pk) => [
                bc2wrap::serialize(sk).unwrap(),
                bc2wrap::serialize(pk).unwrap(),
            ]
            .concat(),
            RetrievedKeysForVerification::Compressed(keyset, pk) => [
                bc2wrap::serialize(keyset).unwrap(),
                bc2wrap::serialize(pk).unwrap(),
            ]
            .concat(),
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
    extra_data: Vec<u8>,
    total_num_parties: usize,
    read_key_at_epoch: Option<kms_grpc::EpochId>,
    compressed: bool,
) -> Option<(TestKeyGenResult, HashMap<Role, ThresholdFheKeys>)> {
    use itertools::Itertools;

    let mut verification_bytes_ref = Vec::new();
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
            let (compressed_keyset, stored_public_key) = internal_client
                .retrieve_compressed_keyset(
                    req_preproc,
                    req_get_keygen,
                    &kg_res,
                    domain,
                    extra_data.clone(),
                    &storage,
                )
                .await
                .inspect_err(|e| tracing::error!("error retrieving compressed keyset: {e}"))
                .unwrap();

            RetrievedKeysForVerification::Compressed(compressed_keyset, stored_public_key)
        } else {
            let (server_key, public_key) = internal_client
                .retrieve_server_key_and_public_key(
                    req_preproc,
                    req_get_keygen,
                    &kg_res,
                    domain,
                    extra_data.clone(),
                    &storage,
                )
                .await
                .inspect_err(|e| tracing::error!("error retrieving server and public key: {e}"))
                .unwrap();

            assert_eq!(&tfhe::Tag::from(req_get_keygen), server_key.tag());
            assert_eq!(&tfhe::Tag::from(req_get_keygen), public_key.tag());

            RetrievedKeysForVerification::Standard(server_key, public_key)
        };

        let key_id = RequestId::from_str(kg_res.request_id.unwrap().request_id.as_str()).unwrap();
        let priv_storage =
            FileStorage::new(data_root_path, StorageType::PRIV, priv_prefix.as_deref()).unwrap();
        //Need to read at the correct epoch id
        let threshold_fhe_keys = ThresholdFheKeys::read_from_storage_at_epoch(
            &priv_storage,
            &key_id,
            &read_key_at_epoch.unwrap_or(*DEFAULT_EPOCH_ID),
        )
        .await
        .unwrap();
        // Note: The sns_key is a part of threshold_fhe_keys, consider optimizing this if it uses too much memory
        all_threshold_fhe_keys.insert(role, threshold_fhe_keys);

        // Compare serialized keys across parties
        let verification_bytes = keys.to_bytes_for_verification();
        if role.one_based() == 1 {
            verification_bytes_ref = verification_bytes;
        } else {
            assert_eq!(verification_bytes_ref, verification_bytes);
        }

        if final_keys.is_none() {
            final_keys = Some(keys);
        }
    }

    let threshold = total_num_parties.div_ceil(3) - 1;
    let (lwe_sk, glwe_sk, sns_glwe_sk, sns_compression_sk, oprf_lwe_sk) = try_reconstruct_shares(
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
        oprf_lwe_sk,
    )
    .unwrap();

    let result = match final_keys.unwrap() {
        RetrievedKeysForVerification::Standard(server_key, public_key) => {
            TestKeyGenResult::Uncompressed((client_key, public_key, server_key))
        }
        RetrievedKeysForVerification::Compressed(keyset, pk) => {
            TestKeyGenResult::Compressed((client_key, keyset, pk))
        }
    };

    result.sanity_check();
    Some((result, all_threshold_fhe_keys))
}

// =============================================================================
// Tests using the consolidated testing module — each test runs in its own
// temporary directory with pre-generated cryptographic material.
// =============================================================================

/// Test insecure threshold DKG with Test parameters.
///
/// Boots servers with PRSS, generates the default compressed keyset using insecure mode,
/// and verifies key generation succeeded on all parties.
///
/// **Requires:** `insecure` feature flag
#[tokio::test]
#[cfg(feature = "insecure")]
async fn test_insecure_dkg() -> anyhow::Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("insecure_dkg")
        .with_party_count(4)
        .with_threshold(1) // For 4 parties: threshold = ⌈4/3⌉ - 1 = 1
        .with_prss() // PRSS is required for threshold key generation even in insecure mode
        .build()
        .await?;

    let key_id = derive_request_id("test_insecure_dkg")?;

    // Generate key using insecure mode
    let responses = threshold_insecure_key_gen(&env.clients, &key_id, FheParameter::Test).await?;

    // Reconstruct ClientKey from shares and run encrypt/decrypt sanity check
    let internal_client = env.create_internal_client(&TEST_PARAM, None).await?;
    verify_keygen_responses(
        responses,
        Some(env.material_dir.path()),
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id,
        &crate::dummy_domain(),
        make_extra_data(2, Some(&DEFAULT_MPC_CONTEXT), Some(&DEFAULT_EPOCH_ID)).unwrap(),
        env.clients.len(),
        None,
        true,
    )
    .await
    .expect("keygen verification failed");

    for server in env.into_servers() {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test insecure threshold DKG with Default parameters.
///
/// Generates a compressed threshold FHE keyset using insecure mode
/// with Default parameters (larger keys, production-size) across 4 parties.
/// Verifies key generation succeeded on all parties.
///
/// **IMPORTANT:** Uses MaterialType::Default (production-like key sizes).
/// **Requires:**
/// - `insecure` feature flag
/// - `slow_tests` feature flag (to run this slow default-parameter test)
/// - Pre-generated secure material:
///   `generate-test-material --profile secure --parties 4,10,13`
#[tokio::test]
#[cfg(all(feature = "insecure", feature = "slow_tests"))]
async fn default_insecure_dkg() -> anyhow::Result<()> {
    // Use Default material spec for production-like keys.
    // PRSS is generated at server startup via `with_prss()`.
    let spec = TestMaterialSpec::threshold_default_no_prss(4);

    let env = ThresholdTestEnv::builder()
        .with_test_name("default_insecure_dkg")
        .with_party_count(4)
        .with_threshold(1) // For 4 parties: threshold = ⌈4/3⌉ - 1 = 1
        .with_prss() // PRSS is required for threshold key generation even in insecure mode
        .with_material_spec(spec)
        .build()
        .await?;

    let key_id = derive_request_id("default_insecure_dkg")?;

    // Use FheParameter::Default to match MaterialType::Default
    let responses =
        threshold_insecure_key_gen(&env.clients, &key_id, FheParameter::Default).await?;

    // Reconstruct ClientKey from shares and run encrypt/decrypt sanity check
    let internal_client = env
        .create_internal_client(&crate::consts::DEFAULT_PARAM, None)
        .await?;
    verify_keygen_responses(
        responses,
        Some(env.material_dir.path()),
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id,
        &crate::dummy_domain(),
        make_extra_data(2, Some(&DEFAULT_MPC_CONTEXT), Some(&DEFAULT_EPOCH_ID)).unwrap(),
        env.clients.len(),
        None,
        true,
    )
    .await
    .expect("keygen verification failed");

    for server in env.into_servers() {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test secure threshold key generation with preprocessing.
///
/// Generates a compressed threshold FHE keyset using secure mode
/// (with preprocessing) with Test parameters across 4 parties. Verifies key
/// generation succeeded on all parties.
///
/// **IMPORTANT:** Uses secure mode with preprocessing (not insecure mode).
/// **Requires:**
/// - `slow_tests` feature flag (PRSS generation at runtime)
///
/// **Note:** PRSS material is generated at runtime by `.with_prss()`
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn secure_threshold_keygen() -> anyhow::Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("secure_threshold_keygen")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .build()
        .await?;

    let preproc_id = derive_request_id("secure_threshold_keygen_preproc")?;
    let keygen_id = derive_request_id("secure_threshold_keygen")?;

    // Run secure key generation with preprocessing
    let responses = threshold_key_gen_secure(
        &env.clients,
        &preproc_id,
        &keygen_id,
        FheParameter::Test,
        None,
        None,
        None,
        None,
    )
    .await?;

    // Reconstruct ClientKey from shares and run encrypt/decrypt sanity check
    let internal_client = env.create_internal_client(&TEST_PARAM, None).await?;
    verify_keygen_responses(
        responses,
        Some(env.material_dir.path()),
        &internal_client,
        &preproc_id,
        &keygen_id,
        &crate::dummy_domain(),
        make_extra_data(2, Some(&DEFAULT_MPC_CONTEXT), Some(&DEFAULT_EPOCH_ID)).unwrap(),
        env.clients.len(),
        None,
        true,
    )
    .await
    .expect("keygen verification failed");

    for server in env.into_servers() {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test secure threshold key generation with crash during online phase.
///
/// Simulates party 2 crashing during the online (keygen) phase. Verifies that the remaining
/// parties (1, 3, 4) can still complete key generation successfully.
///
/// **IMPORTANT:** Tests crash recovery - party 2 excluded from keygen.
/// **Requires:**
/// - `slow_tests` feature flag (PRSS generation at runtime)
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn secure_threshold_keygen_crash_online() -> anyhow::Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("secure_keygen_crash_online")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .build()
        .await?;

    let preproc_id = derive_request_id("secure_keygen_crash_online_preproc")?;
    let keygen_id = derive_request_id("secure_keygen_crash_online")?;

    // Run preprocessing with all parties
    let mut preproc_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let preproc_req = kms_grpc::kms::v1::KeyGenPreprocRequest {
            request_id: Some(preproc_id.into()),
            params: FheParameter::Test as i32,
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: Some((*DEFAULT_EPOCH_ID).into()),
            extra_data: default_extra_data(),
        };
        preproc_tasks.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(preproc_req))
                .await
        });
    }

    while let Some(res) = preproc_tasks.join_next().await {
        res??;
    }

    // Wait for preprocessing to complete on all parties
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_preproc_result(tonic::Request::new(preproc_id.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_preproc_result(tonic::Request::new(preproc_id.into()))
                .await;
        }
        result?;
    }

    // Simulate crash: Run keygen WITHOUT party 2
    let crashed_party = 2u32;

    // Run keygen with only active parties (excluding crashed party 2)
    let mut keygen_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let keygen_req = kms_grpc::kms::v1::KeyGenRequest {
            request_id: Some(keygen_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(preproc_id.into()),
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: None,
            keyset_added_info: None,
            context_id: None,
            epoch_id: None,
            extra_data: vec![],
        };
        keygen_tasks
            .spawn(async move { cur_client.key_gen(tonic::Request::new(keygen_req)).await });
    }

    while let Some(res) = keygen_tasks.join_next().await {
        res??;
    }

    // Verify key generation completed on active parties (not crashed party)
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_result(tonic::Request::new(keygen_id.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_result(tonic::Request::new(keygen_id.into()))
                .await;
        }
        result?;
    }

    for server in env.into_servers() {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test secure threshold key generation with crash during preprocessing.
///
/// Simulates party 3 crashing during the preprocessing phase. Verifies that the remaining
/// parties (1, 2, 4) can still complete preprocessing and key generation successfully.
///
/// **IMPORTANT:** Tests crash recovery - party 3 excluded from preprocessing and keygen.
/// **Requires:**
/// - `slow_tests` feature flag (PRSS generation at runtime)
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn secure_threshold_keygen_crash_preprocessing() -> anyhow::Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("secure_keygen_crash_preproc")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .build()
        .await?;

    let preproc_id = derive_request_id("secure_keygen_crash_preproc_preproc")?;
    let keygen_id = derive_request_id("secure_keygen_crash_preproc")?;

    // Simulate crash: Run preprocessing WITHOUT party 3
    let crashed_party = 3u32;

    // Run preprocessing with only active parties
    let mut preproc_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let preproc_req = kms_grpc::kms::v1::KeyGenPreprocRequest {
            request_id: Some(preproc_id.into()),
            params: FheParameter::Test as i32,
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: Some((*DEFAULT_EPOCH_ID).into()),
            extra_data: default_extra_data(),
        };
        preproc_tasks.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(preproc_req))
                .await
        });
    }

    while let Some(res) = preproc_tasks.join_next().await {
        res??;
    }

    // Wait for preprocessing to complete on active parties
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_preproc_result(tonic::Request::new(preproc_id.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_preproc_result(tonic::Request::new(preproc_id.into()))
                .await;
        }
        result?;
    }

    // Run keygen with same active parties (crashed party stays crashed)
    let mut keygen_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let keygen_req = kms_grpc::kms::v1::KeyGenRequest {
            request_id: Some(keygen_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(preproc_id.into()),
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: None,
            keyset_added_info: None,
            context_id: None,
            epoch_id: None,
            extra_data: vec![],
        };
        keygen_tasks
            .spawn(async move { cur_client.key_gen(tonic::Request::new(keygen_req)).await });
    }

    while let Some(res) = keygen_tasks.join_next().await {
        res??;
    }

    // Verify key generation completed on active parties
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_result(tonic::Request::new(keygen_id.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_result(tonic::Request::new(keygen_id.into()))
                .await;
        }
        result?;
    }

    for server in env.into_servers() {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test secure threshold compressed key generation from existing secret shares
/// that already include the dedicated OPRF private-key share.
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn secure_threshold_compressed_keygen_from_existing_keeps_existing_oprf() -> anyhow::Result<()>
{
    run_secure_threshold_compressed_keygen_from_existing(false).await
}

/// Test secure threshold compressed key generation from legacy existing secret shares
/// that do not include the dedicated OPRF private-key share.
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn secure_threshold_compressed_keygen_from_existing_adds_missing_oprf() -> anyhow::Result<()>
{
    run_secure_threshold_compressed_keygen_from_existing(true).await
}

/// Run secure threshold compressed key generation from existing secret shares.
///
/// Generates an uncompressed keyset first, then performs compressed key generation
/// reusing the existing secret key shares from the first keygen. When `remove_oprf`
/// is true, the first keyset is rewritten to mimic legacy material with no
/// dedicated OPRF share before the servers are restarted.
///
/// **Workflow:**
/// 1. Uncompressed keygen (preprocessing + online) to produce the first keyset
/// 2. Preprocessing for compressed keygen from existing shares
/// 3. Compressed keygen from existing shares
/// 4. Verify both keygens completed on all parties using ddec
#[cfg(feature = "slow_tests")]
async fn run_secure_threshold_compressed_keygen_from_existing(
    remove_oprf: bool,
) -> anyhow::Result<()> {
    use crate::client::tests::common::keygen_config_from_existing;

    const NUM_PARTIES: usize = 4;

    let env = ThresholdTestEnv::builder()
        .with_test_name("compressed_from_existing_keygen")
        .with_party_count(NUM_PARTIES)
        .with_threshold(1)
        .with_prss()
        .build()
        .await?;

    // Step 1: Uncompressed keygen (preprocessing + online)
    let preproc_id_1 = derive_request_id("compressed_existing_preproc_1")?;
    let keygen_id_1 = derive_request_id("compressed_existing_keygen_1")?;
    let (uncompressed_keyset_config, uncompressed_keyset_added_info) = uncompressed_keygen_config();

    threshold_key_gen_secure(
        &env.clients,
        &preproc_id_1,
        &keygen_id_1,
        FheParameter::Test,
        uncompressed_keyset_config,
        uncompressed_keyset_added_info,
        None,
        None,
    )
    .await?;

    let (mut clients, mut servers, material_path, _guard) = env.into_parts();

    // Verify standard keygen completed on all parties
    for client in clients.values() {
        let mut cur_client = client.clone();
        let result = cur_client
            .get_key_gen_result(tonic::Request::new(keygen_id_1.into()))
            .await?;
        assert_eq!(result.into_inner().request_id, Some(keygen_id_1.into()));
    }

    if remove_oprf {
        let old_servers = std::mem::take(&mut servers);
        for (_, server) in old_servers {
            server.assert_shutdown().await;
        }
        remove_oprf_from_existing_keyset(NUM_PARTIES, &material_path, &keygen_id_1, &preproc_id_1)
            .await?;

        let (restarted_servers, restarted_clients) =
            restart_threshold_servers_from_material(NUM_PARTIES, &material_path).await?;
        servers = restarted_servers;
        clients = restarted_clients;
    }

    // Step 2: Compressed keygen from existing secret shares (preprocessing + online)
    let preproc_id_2 = derive_request_id("compressed_existing_preproc_2")?;
    let keygen_id_2 = derive_request_id("compressed_existing_keygen_2")?;

    let (keyset_config, keyset_added_info) = keygen_config_from_existing(&keygen_id_1, true, true);

    threshold_key_gen_secure(
        &clients,
        &preproc_id_2,
        &keygen_id_2,
        FheParameter::Test,
        keyset_config,
        keyset_added_info,
        None,
        None,
    )
    .await?;

    // Verify compressed keygen completed on all parties
    for client in clients.values() {
        let mut cur_client = client.clone();
        let result = cur_client
            .get_key_gen_result(tonic::Request::new(keygen_id_2.into()))
            .await?;
        assert_eq!(result.into_inner().request_id, Some(keygen_id_2.into()));
    }

    // Do distributed decryption to verify the generated key is ok
    let material_path = material_path.as_path();
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..NUM_PARTIES];

    // Create internal client for decryption
    let mut pub_storage_map = std::collections::HashMap::new();
    for (i, prefix) in pub_storage_prefixes.iter().enumerate() {
        pub_storage_map.insert(
            (i + 1) as u32,
            FileStorage::new(Some(material_path), StorageType::PUB, prefix.as_deref())?,
        );
    }

    // Verify tag propagation: keys from keygen_id_2 should carry keygen_id_1's tag.
    // Additionally verify that the stored CompactPublicKey for keygen_id_2 is the OLD one
    // from keygen_id_1 (migration semantics), not the one obtained by decompressing the
    // newly-generated CompressedXofKeySet.
    {
        use crate::engine::base::{DSEP_PUBDATA_KEY, safe_serialize_hash_element_versioned};
        use crate::vault::storage::crypto_material::CryptoMaterialReader;
        let expected_tag: tfhe::Tag = keygen_id_1.into();
        for (&party_id, storage) in &pub_storage_map {
            let compressed_keyset: tfhe::xof_key_set::CompressedXofKeySet =
                CryptoMaterialReader::read_from_storage(storage, &keygen_id_2).await?;

            let (pk, server_key) = compressed_keyset.decompress().unwrap().into_raw_parts();
            let (_, _, _, _, _, _, _, oprf_key, _) = server_key.clone().into_raw_parts();
            assert!(
                oprf_key.is_some(),
                "Party {party_id}: compressed UseExisting keygen must embed a dedicated OPRF key"
            );
            assert_eq!(
                pk.tag(),
                &expected_tag,
                "Public key for party {party_id} should have tag propagated from existing keyset"
            );
            assert_eq!(
                server_key.tag(),
                &expected_tag,
                "Server key for party {party_id} should have tag propagated from existing keyset"
            );

            // Read the standalone CompactPublicKey stored for keygen_id_2 (migration output).
            let stored_pk_new: tfhe::CompactPublicKey =
                CryptoMaterialReader::read_from_storage(storage, &keygen_id_2).await?;
            // Read the standalone CompactPublicKey from keygen_id_1 (the OLD keyset).
            let stored_pk_old: tfhe::CompactPublicKey =
                CryptoMaterialReader::read_from_storage(storage, &keygen_id_1).await?;

            // CompactPublicKey does not implement PartialEq, so compare via digests.
            let digest_stored_new =
                safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &stored_pk_new).unwrap();
            let digest_stored_old =
                safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &stored_pk_old).unwrap();
            let digest_derived_from_new_keyset =
                safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &pk).unwrap();

            assert_eq!(
                digest_stored_new, digest_stored_old,
                "Party {party_id}: migration must store the OLD CompactPublicKey for keygen_id_2"
            );
            assert_ne!(
                digest_stored_new, digest_derived_from_new_keyset,
                "Party {party_id}: stored CompactPublicKey must differ from the one derived from the new compressed keyset"
            );

            // The digest of the stored (old) CompactPublicKey must appear in the signed
            // KeyGenMetadata for keygen_id_2 under PubDataType::PublicKey.
            let priv_storage = FileStorage::new(
                Some(material_path),
                StorageType::PRIV,
                PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[(party_id as usize) - 1].as_deref(),
            )?;
            let threshold_keys: crate::engine::threshold::service::ThresholdFheKeys =
                read_versioned_at_request_and_epoch_id(
                    &priv_storage,
                    &keygen_id_2,
                    &DEFAULT_EPOCH_ID,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await?;
            let threshold_keys_old: crate::engine::threshold::service::ThresholdFheKeys =
                read_versioned_at_request_and_epoch_id(
                    &priv_storage,
                    &keygen_id_1,
                    &DEFAULT_EPOCH_ID,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await?;
            let old_oprf_share = &threshold_keys_old
                .private_keys
                .as_ref()
                .oprf_secret_key_share;
            let new_oprf_share = &threshold_keys.private_keys.as_ref().oprf_secret_key_share;
            assert!(
                old_oprf_share.is_some(),
                "Party {party_id}: migrated key must have OPRF private share"
            );
            assert_eq!(
                old_oprf_share, new_oprf_share,
                "Party {party_id}: UseExisting keygen must reuse the persisted OPRF private share"
            );
            match &threshold_keys.meta_data {
                KeyGenMetadata::Current(inner) => {
                    let signed_pk_digest = inner
                        .key_digest_map
                        .get(&PubDataType::PublicKey)
                        .expect("PublicKey digest must be present in signed metadata");
                    assert_eq!(
                        *signed_pk_digest, digest_stored_old,
                        "Party {party_id}: signed PublicKey digest must match the OLD CompactPublicKey"
                    );
                }
                KeyGenMetadata::LegacyV0(_) => {
                    panic!(
                        "Party {party_id}: unexpected LegacyV0 KeyGenMetadata for freshly generated key"
                    );
                }
            }
        }
    }

    let client_storage = FileStorage::new(Some(material_path), StorageType::CLIENT, None)?;
    let mut internal_client = crate::client::client_wasm::Client::new_client(
        client_storage,
        pub_storage_map,
        &TEST_PARAM,
        None,
    )
    .await?;

    // Run ddec with the new keyset
    run_decryption_threshold(
        NUM_PARTIES,
        &mut servers,
        &mut clients,
        &mut internal_client,
        None,
        &keygen_id_2,
        None,
        vec![TestingPlaintext::U32(66)],
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        None,
        1,
        Some(material_path),
    )
    .await;

    // Run ddec under keygen_id_1 to verify the migration: after
    // copy_compressed_key_to_original, keygen_id_1 holds the new compressed
    // keyset and the migrated private shares, so encryption + decryption can
    // both use the post-migration compressed material.
    run_decryption_threshold(
        NUM_PARTIES,
        &mut servers,
        &mut clients,
        &mut internal_client,
        None,
        &keygen_id_1,
        None,
        vec![TestingPlaintext::U32(55)],
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        None,
        1,
        Some(material_path),
    )
    .await;

    for (_, server) in servers {
        server.assert_shutdown().await;
    }

    Ok(())
}

#[cfg(feature = "slow_tests")]
async fn restart_threshold_servers_from_material(
    num_parties: usize,
    material_path: &Path,
) -> anyhow::Result<(
    HashMap<u32, crate::testing::types::ServerHandle>,
    HashMap<u32, CoreServiceEndpointClient<Channel>>,
)> {
    let mut pub_storages = Vec::new();
    let mut priv_storages = Vec::new();
    for (pub_prefix, priv_prefix) in PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..num_parties]
        .iter()
        .zip(PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..num_parties].iter())
    {
        pub_storages.push(FileStorage::new(
            Some(material_path),
            StorageType::PUB,
            pub_prefix.as_deref(),
        )?);
        priv_storages.push(FileStorage::new(
            Some(material_path),
            StorageType::PRIV,
            priv_prefix.as_deref(),
        )?);
    }

    let vaults: Vec<Option<crate::vault::Vault>> = (0..num_parties).map(|_| None).collect();
    Ok(crate::client::test_tools::setup_threshold(
        1,
        pub_storages,
        priv_storages,
        vaults,
        true,
        None,
        None,
    )
    .await)
}

#[cfg(feature = "slow_tests")]
async fn remove_oprf_from_existing_keyset(
    num_parties: usize,
    material_path: &Path,
    key_id: &RequestId,
    preproc_id: &RequestId,
) -> anyhow::Result<()> {
    for (party_idx, (pub_prefix, priv_prefix)) in PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL
        [0..num_parties]
        .iter()
        .zip(PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..num_parties].iter())
        .enumerate()
    {
        let party_id = party_idx + 1;
        let mut pub_storage =
            FileStorage::new(Some(material_path), StorageType::PUB, pub_prefix.as_deref())?;
        let mut priv_storage = FileStorage::new(
            Some(material_path),
            StorageType::PRIV,
            priv_prefix.as_deref(),
        )?;

        let signing_key = get_core_signing_key(&priv_storage).await?;
        let public_key: tfhe::CompactPublicKey =
            read_versioned_at_request_id(&pub_storage, key_id, &PubDataType::PublicKey.to_string())
                .await?;
        let server_key: tfhe::ServerKey =
            read_versioned_at_request_id(&pub_storage, key_id, &PubDataType::ServerKey.to_string())
                .await?;
        let (
            integer_server_key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key,
            oprf_key,
            tag,
        ) = server_key.into_raw_parts();
        assert!(
            oprf_key.is_some(),
            "Party {party_id}: first keygen should store an OPRF server key before legacy rewrite"
        );
        let server_key_without_oprf = tfhe::ServerKey::from_raw_parts(
            integer_server_key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key,
            None,
            tag,
        );

        let threshold_keys: ThresholdFheKeys = read_versioned_at_request_and_epoch_id(
            &priv_storage,
            key_id,
            &DEFAULT_EPOCH_ID,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await?;
        let mut private_keys = threshold_keys.private_keys.as_ref().clone();
        assert!(
            private_keys.oprf_secret_key_share.take().is_some(),
            "Party {party_id}: first keygen should store an OPRF private share before legacy rewrite"
        );

        let fhe_key_set = threshold_execution::tfhe_internals::public_keysets::FhePubKeySet {
            public_key,
            server_key: server_key_without_oprf.clone(),
        };
        let metadata = compute_info_uncompressed_keygen(
            &signing_key,
            &DSEP_PUBDATA_KEY,
            preproc_id,
            key_id,
            &fhe_key_set,
            &dummy_domain(),
            default_isolated_extra_data(),
        )?;
        let updated_threshold_keys = ThresholdFheKeys::new(
            Arc::new(private_keys),
            threshold_keys.public_material.clone(),
            metadata,
        );

        delete_at_request_id(
            &mut pub_storage,
            key_id,
            &PubDataType::ServerKey.to_string(),
        )
        .await?;
        store_versioned_at_request_id(
            &mut pub_storage,
            key_id,
            &server_key_without_oprf,
            &PubDataType::ServerKey.to_string(),
        )
        .await?;
        delete_at_request_and_epoch_id(
            &mut priv_storage,
            key_id,
            &DEFAULT_EPOCH_ID,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await?;
        store_versioned_at_request_and_epoch_id(
            &mut priv_storage,
            key_id,
            &DEFAULT_EPOCH_ID,
            &updated_threshold_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await?;
    }

    Ok(())
}

/// Test insecure threshold decompression key generation with decompression validation.
///
/// Generates two regular keysets using insecure mode, then generates a decompression key
/// between them using secure mode (required for decompression keys). Validates the keys
/// by running `run_decompression_test`, matching the work done by the non-isolated
/// `run_threshold_decompression_keygen`.
///
/// **Workflow:**
/// 1. Generate first compressed keyset (insecure mode), reconstruct ClientKey + ServerKey via verify_keygen_responses
/// 2. Generate second compressed keyset (insecure mode), reconstruct ClientKey via verify_keygen_responses
/// 3. Generate decompression key from keyset 1 to keyset 2 (secure mode with preprocessing)
/// 4. Retrieve decompression key from public storage
/// 5. Run run_decompression_test to validate key compatibility (mirrors non-isolated verification)
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn test_insecure_threshold_decompression_keygen() -> anyhow::Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("decompression_keygen")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .build()
        .await?;

    let material_path = env.material_dir.path().to_path_buf();
    let internal_client = env.create_internal_client(&TEST_PARAM, None).await?;

    // Step 1: Generate first keyset (insecure mode), reconstruct ClientKey + ServerKey
    let key_id_1 = derive_request_id("decom_dkg_key_1")?;
    let responses_1 =
        threshold_insecure_key_gen(&env.clients, &key_id_1, FheParameter::Test).await?;
    let (keys_1, _) = verify_keygen_responses(
        responses_1,
        Some(&material_path),
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id_1,
        &dummy_domain(),
        default_extra_data(),
        env.clients.len(),
        None,
        true,
    )
    .await
    .expect("keygen 1 verification failed");
    let (client_key_1, compressed_keyset_1, _public_key_1) = keys_1.get_compressed();
    let (_, server_key_1) = compressed_keyset_1
        .decompress()
        .expect("decompress keyset 1")
        .into_raw_parts();

    // Step 2: Generate second keyset (insecure mode), reconstruct ClientKey
    let key_id_2 = derive_request_id("decom_dkg_key_2")?;
    let responses_2 =
        threshold_insecure_key_gen(&env.clients, &key_id_2, FheParameter::Test).await?;
    let (keys_2, _) = verify_keygen_responses(
        responses_2,
        Some(&material_path),
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id_2,
        &dummy_domain(),
        default_extra_data(),
        env.clients.len(),
        None,
        true,
    )
    .await
    .expect("keygen 2 verification failed");
    let (client_key_2, _compressed_keyset_2, _public_key_2) = keys_2.get_compressed();

    // Step 3: Generate decompression key (secure mode - required for decompression)
    let preproc_id_3 = derive_request_id("decom_dkg_preproc_3")?;
    let key_id_3 = derive_request_id("decom_dkg_key_3")?;

    // Run preprocessing for decompression key generation
    let mut preproc_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let preproc_req = kms_grpc::kms::v1::KeyGenPreprocRequest {
            request_id: Some(preproc_id_3.into()),
            params: FheParameter::Test as i32,
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: Some(KeySetConfig {
                keyset_type: KeySetType::DecompressionOnly.into(),
                standard_keyset_config: None,
            }),
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: Some((*DEFAULT_EPOCH_ID).into()),
            extra_data: default_extra_data(),
        };
        preproc_tasks.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(preproc_req))
                .await
        });
    }

    while let Some(res) = preproc_tasks.join_next().await {
        res??;
    }

    // Wait for preprocessing to complete
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_preproc_result(tonic::Request::new(preproc_id_3.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_preproc_result(tonic::Request::new(preproc_id_3.into()))
                .await;
        }
        result?;
    }

    // Generate decompression key with proper configuration
    let mut keygen_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let keygen_req = kms_grpc::kms::v1::KeyGenRequest {
            request_id: Some(key_id_3.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(preproc_id_3.into()),
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: Some(KeySetConfig {
                keyset_type: KeySetType::DecompressionOnly.into(),
                standard_keyset_config: None,
            }),
            keyset_added_info: Some(KeySetAddedInfo {
                from_keyset_id_decompression_only: Some(key_id_1.into()),
                to_keyset_id_decompression_only: Some(key_id_2.into()),
                existing_keyset_id: None,
                use_existing_key_tag: false,
                copy_compressed_key_to_original: false,
            }),
            context_id: None,
            epoch_id: None,
            extra_data: vec![],
        };
        keygen_tasks
            .spawn(async move { cur_client.key_gen(tonic::Request::new(keygen_req)).await });
    }

    while let Some(res) = keygen_tasks.join_next().await {
        res??;
    }

    // Wait for decompression key generation to complete and collect the result
    let mut keygen_result_3 = None;
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_result(tonic::Request::new(key_id_3.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_result(tonic::Request::new(key_id_3.into()))
                .await;
        }
        // Only need one result to retrieve the decompression key from pub storage
        if keygen_result_3.is_none() {
            keygen_result_3 = Some(result?.into_inner());
        }
    }

    // Step 4: Retrieve the decompression key from public storage (party 1's storage)
    let pub_prefix = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0];
    let pub_storage = FileStorage::new(
        Some(&material_path),
        StorageType::PUB,
        pub_prefix.as_deref(),
    )?;
    let decompression_key = internal_client
        .retrieve_decompression_key(&keygen_result_3.unwrap(), &pub_storage)
        .await?;

    for (_, server) in env.servers {
        server.assert_shutdown().await;
    }

    // Step 5: Validate key compatibility — mirrors run_decompression_test in the non-isolated version
    run_decompression_test(
        &client_key_1,
        &client_key_2,
        Some(&server_key_1),
        decompression_key.into_raw_parts(),
    );

    Ok(())
}
