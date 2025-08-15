use crate::client::test_tools::check_port_is_closed;
use crate::client::test_tools::ServerHandle;
use crate::client::tests::threshold_handles;
use crate::client::Client;
#[cfg(feature = "wasm_tests")]
use crate::client::TestingUserDecryptionTranscript;
use crate::client::{await_server_ready, get_health_client, get_status};
use crate::client::{ParsedUserDecryptionRequest, ServerIdentities};
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use crate::consts::DEFAULT_PARAM;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use crate::consts::MAX_TRIES;
use crate::consts::TEST_THRESHOLD_KEY_ID_4P;
use crate::consts::{DEFAULT_AMOUNT_PARTIES, TEST_CENTRAL_KEY_ID};
#[cfg(feature = "slow_tests")]
use crate::consts::{DEFAULT_CENTRAL_KEY_ID, DEFAULT_THRESHOLD_KEY_ID_4P};
use crate::consts::{DEFAULT_THRESHOLD, TEST_THRESHOLD_KEY_ID_10P};
use crate::consts::{PRSS_INIT_REQ_ID, TEST_PARAM, TEST_THRESHOLD_KEY_ID};
use crate::cryptography::internal_crypto_types::{PrivateSigKey, Signature};
use crate::cryptography::internal_crypto_types::{
    UnifiedPrivateEncKey, UnifiedPublicEncKey, WrappedDKGParams,
};
use crate::dummy_domain;
use crate::engine::base::{compute_handle, derive_request_id, BaseKmsStruct, DSEP_PUBDATA_CRS};
#[cfg(feature = "slow_tests")]
use crate::engine::centralized::central_kms::tests::get_default_keys;
use crate::engine::centralized::central_kms::RealCentralizedKms;
use crate::engine::threshold::service::RealThresholdKms;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use crate::engine::threshold::service::ThresholdFheKeys;
use crate::engine::traits::BaseKms;
use crate::engine::validation::DSEP_USER_DECRYPTION;
#[cfg(feature = "wasm_tests")]
use crate::util::file_handling::write_element;
use crate::util::key_setup::max_threshold;
use crate::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, purge, EncryptionConfig, TestingPlaintext,
};
use crate::util::rate_limiter::RateLimiterConfig;
use crate::vault::storage::crypto_material::get_core_signing_key;
#[cfg(feature = "insecure")]
use crate::vault::storage::delete_all_at_request_id;
use crate::vault::storage::{file::FileStorage, StorageType};
use crate::vault::storage::{make_storage, StorageReader};
use crate::vault::Vault;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use kms_grpc::kms::v1::CrsGenRequest;
use kms_grpc::kms::v1::{
    Empty, FheParameter, InitRequest, KeySetAddedInfo, KeySetConfig, KeySetType, TypedCiphertext,
    TypedPlaintext, UserDecryptionRequest, UserDecryptionResponse,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::rpc_types::{fhe_types_to_num_blocks, PrivDataType};
use kms_grpc::rpc_types::{protobuf_to_alloy_domain, PubDataType};
use kms_grpc::RequestId;
use serial_test::serial;
use std::collections::{hash_map::Entry, HashMap};
use std::str::FromStr;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use std::sync::Arc;
use tfhe::core_crypto::prelude::{
    decrypt_lwe_ciphertext, divide_round, ContiguousEntityContainer, LweCiphertextOwned,
};
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::prelude::ParameterSetConformant;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use tfhe::shortint::list_compression::NoiseSquashingCompressionPrivateKey;
use tfhe::shortint::server_key::ModulusSwitchConfiguration;
use tfhe::zk::CompactPkeCrs;
use tfhe::Tag;
use tfhe::{FheTypes, ProvenCompactCiphertextList};
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
#[cfg(feature = "wasm_tests")]
use threshold_fhe::execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
use threshold_fhe::execution::tfhe_internals::test_feature::run_decompression_test;
use threshold_fhe::networking::grpc::GrpcServer;
use tokio::task::JoinSet;
use tonic::server::NamedService;
use tonic::transport::Channel;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::HealthCheckRequest;

// Time to sleep to ensure that previous servers and tests have shut down properly.
const TIME_TO_SLEEP_MS: u64 = 500;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_crs_gen_manual() {
    let crs_req_id = derive_request_id("test_crs_gen_manual").unwrap();
    // Delete potentially old data
    purge(None, None, None, &crs_req_id, 1).await;
    // TEST_PARAM uses V1 CRS
    crs_gen_centralized_manual(&TEST_PARAM, &crs_req_id, Some(FheParameter::Test)).await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_crs_gen_centralized() {
    let crs_req_id = derive_request_id("test_crs_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, None, &crs_req_id, 1).await;
    // TEST_PARAM uses V1 CRS
    crs_gen_centralized(&crs_req_id, FheParameter::Test, false).await;
}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_insecure_crs_gen_centralized() {
    let crs_req_id = derive_request_id("test_insecure_crs_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, None, &crs_req_id, 1).await;
    // TEST_PARAM uses V1 CRS
    crs_gen_centralized(&crs_req_id, FheParameter::Test, true).await;
}

/// test centralized crs generation and do all the reading, processing and verification manually
async fn crs_gen_centralized_manual(
    dkg_params: &DKGParams,
    request_id: &RequestId,
    params: Option<FheParameter>,
) {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, mut kms_client, internal_client) =
        crate::client::test_tools::centralized_handles(dkg_params, None).await;

    let max_num_bits = if params.unwrap() == FheParameter::Test {
        Some(1)
    } else {
        // The default is 2048 which is too slow for tests, so we switch to 256
        Some(256)
    };
    let domain = dummy_domain();
    let ceremony_req = internal_client
        .crs_gen_request(request_id, max_num_bits, params, domain)
        .unwrap();

    let client_request_id = ceremony_req.request_id.clone().unwrap();

    // response is currently empty
    let gen_response = kms_client
        .crs_gen(tonic::Request::new(ceremony_req.clone()))
        .await
        .unwrap();
    assert_eq!(gen_response.into_inner(), Empty {});
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    // Check that we can retrieve the CRS under that request id
    let mut get_response = kms_client
        .get_crs_gen_result(tonic::Request::new(client_request_id.clone()))
        .await;
    while get_response.is_err() {
        // Sleep to give the server some time to complete CRS generation
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        get_response = kms_client
            .get_crs_gen_result(tonic::Request::new((*request_id).into()))
            .await;
    }

    let resp = get_response.unwrap().into_inner();
    let rvcd_req_id = resp.request_id.unwrap();

    // // check that the received request id matches the one we sent in the request
    assert_eq!(rvcd_req_id, client_request_id);

    let crs_info = resp.crs_results.unwrap();
    let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
    // check that CRS signature is verified correctly for the current version
    let crs_unversioned: CompactPkeCrs = pub_storage
        .read_data(request_id, &PubDataType::CRS.to_string())
        .await
        .unwrap();
    let client_handle = compute_handle(&crs_unversioned).unwrap();
    assert_eq!(&client_handle, &crs_info.key_handle);

    // try verification with each of the server keys; at least one must pass
    let crs_sig: Signature = bc2wrap::deserialize(&crs_info.signature).unwrap();
    let mut verified = false;
    let server_pks = internal_client.get_server_pks().unwrap();
    for vk in server_pks.values() {
        let v = BaseKmsStruct::verify_sig(&DSEP_PUBDATA_CRS, &client_handle, &crs_sig, vk).is_ok();
        verified = verified || v;
    }

    // check that verification (with at least 1 server key) worked
    assert!(verified);

    kms_server.assert_shutdown().await;
}

/// test centralized crs generation via client interface
pub(crate) async fn crs_gen_centralized(
    crs_req_id: &RequestId,
    params: FheParameter,
    insecure: bool,
) {
    let dkg_param: WrappedDKGParams = params.into();
    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100,
        pub_decrypt: 1,
        user_decrypt: 1,
        crsgen: 100,
        preproc: 1,
        keygen: 1,
    };
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, mut kms_client, internal_client) =
        crate::client::test_tools::centralized_handles(&dkg_param, Some(rate_limiter_conf)).await;

    let max_num_bits = if params == FheParameter::Test {
        Some(1)
    } else {
        // The default is 2048 which is too slow for tests, so we switch to 256
        Some(256)
    };
    let domain = dummy_domain();
    let gen_req = internal_client
        .crs_gen_request(crs_req_id, max_num_bits, Some(params), domain)
        .unwrap();

    tracing::debug!("making crs request, insecure? {insecure}");
    match insecure {
        true => {
            #[cfg(feature = "insecure")]
            {
                let gen_response = kms_client
                    .insecure_crs_gen(tonic::Request::new(gen_req.clone()))
                    .await
                    .unwrap();
                assert_eq!(gen_response.into_inner(), Empty {});
            }
            #[cfg(not(feature = "insecure"))]
            {
                panic!("cannot perform insecure central crs gen")
            }
        }
        false => {
            let gen_response = kms_client
                .crs_gen(tonic::Request::new(gen_req.clone()))
                .await
                .unwrap();
            assert_eq!(gen_response.into_inner(), Empty {});
        }
    };

    let mut response = Err(tonic::Status::not_found(""));
    let mut ctr = 0;
    while response.is_err() && ctr < 5 {
        response = kms_client
            .get_crs_gen_result(tonic::Request::new((*crs_req_id).into()))
            .await;
        ctr += 1;
    }
    let inner_resp = response.unwrap().into_inner();
    let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
    let pp = internal_client
        .process_get_crs_resp(&inner_resp, &pub_storage)
        .await
        .unwrap()
        .unwrap();

    // Validate the CRS as a sanity check
    crate::client::crs_gen::tests::verify_pp(&dkg_param, &pp);

    kms_server.assert_shutdown().await;
}
