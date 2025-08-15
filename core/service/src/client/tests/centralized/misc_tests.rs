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

/// Check that the centralized health service is serving as soons as boot is completed.
#[tokio::test]
#[serial]
async fn test_central_health_endpoint_availability() {
    let (kms_server, _kms_client, _internal_client) =
        crate::client::test_tools::centralized_handles(&TEST_PARAM, None).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let mut health_client = get_health_client(kms_server.service_port)
        .await
        .expect("Failed to get health client");
    let service_name = <CoreServiceEndpointServer<
            RealCentralizedKms<FileStorage, FileStorage>,
        > as NamedService>::NAME;
    let request = tonic::Request::new(HealthCheckRequest {
        service: service_name.to_string(),
    });

    let response = health_client
        .check(request)
        .await
        .expect("Health check request failed");

    let status = response.into_inner().status;
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
        "Service is not in SERVING status. Got status: {status}"
    );
}

/// Validate that dropping the server signal triggers the server to shut down
#[tokio::test]
#[serial]
async fn test_central_close_after_drop() {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, kms_client, mut internal_client) =
        crate::client::test_tools::centralized_handles(&TEST_PARAM, None).await;
    let mut health_client = get_health_client(kms_server.service_port)
        .await
        .expect("Failed to get health client");
    let service_name = <CoreServiceEndpointServer<
            RealCentralizedKms<FileStorage, FileStorage>,
        > as NamedService>::NAME;
    let request = tonic::Request::new(HealthCheckRequest {
        service: service_name.to_string(),
    });

    let response = health_client
        .check(request)
        .await
        .expect("Health check request failed");

    let status = response.into_inner().status;
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
        "Service is not in SERVING status. Got status: {status}"
    );
    let client_map = HashMap::from([(1, kms_client)]);
    // Keep the server occupied so it won't shut down immidiately after dropping the handle
    let (tasks, req_id) = crate::client::tests::common::send_dec_reqs(
        3,
        &TEST_CENTRAL_KEY_ID,
        &client_map,
        &mut internal_client,
    )
    .await;
    // Drop server
    drop(kms_server);
    // Get status and validate that it is not serving
    let status = get_status(&mut health_client, service_name).await.unwrap();
    // Threshold servers will start serving as soon as they boot
    // WARNING there is a risk this check fails if the server is shut down before was can complete the status check
    assert_eq!(
        status,
        ServingStatus::NotServing as i32,
        "Service is not in NOT SERVING status. Got status: {status}"
    );
    // Wait for dec tasks to be done
    let dec_res = tasks.join_all().await;
    assert!(dec_res.iter().all(|res| res.is_ok()));
    // And wait for public decryption to also be done
    let dec_resp_tasks = crate::client::tests::common::get_pub_dec_resp(&req_id, &client_map).await;
    let dec_resp_res = dec_resp_tasks.join_all().await;
    // TODO the response for the server that were not dropped should actually be ok since we only drop one <=t server
    assert!(dec_resp_res.iter().all(|res| res.is_err()));
    // Check the server is no longer there
    assert!(get_status(&mut health_client, service_name).await.is_err());
}

// Validate bug-fix to ensure that the server fails gracefully when the ciphertext is too large
#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_largecipher() {
    use crate::{
        consts::DEFAULT_CENTRAL_KEY_ID,
        engine::centralized::central_kms::tests::{
            new_priv_ram_storage_from_existing_keys, new_pub_ram_storage_from_existing_keys,
        },
    };

    let keys = get_default_keys().await;
    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100,
        pub_decrypt: 1,
        user_decrypt: 100,
        crsgen: 1,
        preproc: 1,
        keygen: 1,
    };
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, mut kms_client) = crate::client::test_tools::setup_centralized(
        new_pub_ram_storage_from_existing_keys(&keys.pub_fhe_keys)
            .await
            .unwrap(),
        new_priv_ram_storage_from_existing_keys(&keys.centralized_kms_keys)
            .await
            .unwrap(),
        Some(rate_limiter_conf),
    )
    .await;
    let ct = Vec::from([1_u8; 100000]);
    let fhe_type = FheTypes::Uint32;
    let ct_format = kms_grpc::kms::v1::CiphertextFormat::default();
    let client_address = alloy_primitives::Address::from_public_key(keys.client_pk.pk());
    let mut internal_client = Client::new(
        HashMap::from_iter(
            keys.server_keys
                .iter()
                .enumerate()
                .map(|(i, key)| (i as u32 + 1, key.clone())),
        ),
        client_address,
        Some(keys.client_sk.clone()),
        keys.params,
        None,
    );
    let request_id = derive_request_id("TEST_USER_DECRYPT_ID_123").unwrap();
    let typed_ciphertexts = vec![TypedCiphertext {
        ciphertext: ct,
        fhe_type: fhe_type as i32,
        ciphertext_format: ct_format.into(),
        external_handle: vec![123],
    }];
    let (req, _enc_pk, _enc_sk) = internal_client
        .user_decryption_request(
            &dummy_domain(),
            typed_ciphertexts,
            &request_id,
            &DEFAULT_CENTRAL_KEY_ID,
        )
        .unwrap();
    let response = kms_client
        .user_decrypt(tonic::Request::new(req.clone()))
        .await
        .unwrap();
    assert_eq!(response.into_inner(), Empty {});

    let mut response = kms_client
        .get_user_decryption_result(req.request_id.clone().unwrap())
        .await;
    while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
        // Sleep to give the server some time to complete user decryption
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        response = kms_client
            .get_user_decryption_result(req.request_id.clone().unwrap())
            .await;
    }
    // Check that we get a server error instead of a server crash
    assert_eq!(response.as_ref().unwrap_err().code(), tonic::Code::Internal);
    assert!(response
        .err()
        .unwrap()
        .message()
        .contains("finished with an error"));
    tracing::info!("aborting");
    kms_server.assert_shutdown().await;
}
