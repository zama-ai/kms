//! Isolated versions of centralized misc tests
//!
//! This file demonstrates the migration pattern from shared test material
//! to isolated test material using TestMaterialManager.

use crate::client::test_tools::{get_health_client, get_status, setup_centralized_isolated};
use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::consts::{OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_KEY_ID, TEST_PARAM};
use crate::engine::centralized::central_kms::RealCentralizedKms;
use crate::util::key_setup::ensure_central_keys_exist;
use crate::util::key_setup::test_material_manager::TestMaterialManager;
use crate::util::key_setup::test_material_spec::TestMaterialSpec;
use crate::util::key_setup::test_tools::setup::ensure_testing_material_exists;
use crate::vault::storage::Storage;
use crate::vault::storage::{file::FileStorage, StorageType};
use anyhow::Result;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::rpc_types::PubDataType;
use std::collections::HashMap;
use tempfile::TempDir;
use tonic::server::NamedService;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::HealthCheckRequest;

cfg_if::cfg_if! {
    if #[cfg(feature = "slow_tests")] {
        use tfhe::FheTypes;
        use kms_grpc::kms::v1::TypedCiphertext;
        use crate::engine::base::derive_request_id;
        use crate::util::rate_limiter::RateLimiterConfig;
        use crate::engine::centralized::central_kms::tests::get_default_keys;
        use crate::dummy_domain;
        use crate::client::client_wasm::Client;
        use kms_grpc::kms::v1::Empty;
        use crate::consts::DEFAULT_CENTRAL_KEY_ID;
        use crate::cryptography::encryption::PkeSchemeType;
        use crate::engine::centralized::central_kms::tests::{
            new_priv_ram_storage_from_existing_keys, new_pub_ram_storage_from_existing_keys,
        };
    }
}

/// Helper to fix public key RequestIds for centralized tests.
/// Ensures public keys are stored with correct RequestIds that match private keys.
async fn fix_centralized_public_keys(
    pub_storage: &mut FileStorage,
    priv_storage: &mut FileStorage,
) -> Result<()> {
    // Clear existing public keys to force regeneration with correct RequestIds
    let _ = pub_storage
        .delete_data(&TEST_CENTRAL_KEY_ID, &PubDataType::PublicKey.to_string())
        .await;
    let _ = pub_storage
        .delete_data(&OTHER_CENTRAL_TEST_ID, &PubDataType::PublicKey.to_string())
        .await;

    ensure_central_keys_exist(
        pub_storage,
        priv_storage,
        TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        &OTHER_CENTRAL_TEST_ID,
        true, // deterministic
        true, // write_privkey
    )
    .await;

    Ok(())
}

/// Helper function to setup isolated centralized test environment
async fn setup_isolated_centralized_test(
    test_name: &str,
) -> Result<(
    TempDir,
    crate::client::test_tools::ServerHandle,
    kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient<
        tonic::transport::Channel,
    >,
)> {
    let manager = TestMaterialManager::new(None);
    let spec = TestMaterialSpec::centralized_basic();
    let material_dir = manager.setup_test_material(&spec, test_name).await?;

    // Generate material with correct RequestIds
    ensure_testing_material_exists(Some(material_dir.path())).await;

    let mut pub_storage = FileStorage::new(Some(material_dir.path()), StorageType::PUB, None)?;
    let mut priv_storage = FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;

    // Fix public key RequestIds
    fix_centralized_public_keys(&mut pub_storage, &mut priv_storage).await?;

    let (server, client) = crate::client::test_tools::setup_centralized(
        pub_storage,
        priv_storage,
        None, // No backup vault
        None, // No rate limiter
    )
    .await;

    Ok((material_dir, server, client))
}

/// Check that the centralized health service is serving as soon as boot is completed.
#[tokio::test]
async fn test_central_health_endpoint_availability_isolated() -> Result<()> {
    let (_material_dir, kms_server, _kms_client) =
        setup_isolated_centralized_test("health_endpoint").await?;

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

    Ok(())
}

/// Validate that dropping the server signal triggers the server to shut down
#[tokio::test]
async fn test_central_close_after_drop_isolated() -> Result<()> {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    let manager = TestMaterialManager::new(None);
    let spec = TestMaterialSpec::centralized_basic();
    let material_dir = manager
        .setup_test_material(&spec, "close_after_drop")
        .await?;

    ensure_testing_material_exists(Some(material_dir.path())).await;

    let mut pub_storage = FileStorage::new(Some(material_dir.path()), StorageType::PUB, None)?;
    let mut priv_storage = FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;
    let client_storage = FileStorage::new(Some(material_dir.path()), StorageType::CLIENT, None)?;

    // Fix public key RequestIds
    fix_centralized_public_keys(&mut pub_storage, &mut priv_storage).await?;

    let (kms_server, kms_client) = setup_centralized_isolated(
        pub_storage.clone(),
        priv_storage,
        None,
        None,
        Some(material_dir.path()),
    )
    .await;

    // Create internal client with isolated material
    let pub_storage_map = HashMap::from([(1, pub_storage)]);
    let mut internal_client = crate::client::client_wasm::Client::new_client(
        client_storage,
        pub_storage_map,
        &TEST_PARAM,
        None,
    )
    .await?;

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
    // Keep the server occupied so it won't shut down immediately after dropping the handle
    let (tasks, req_id) = crate::client::tests::common::send_dec_reqs(
        3,
        &TEST_CENTRAL_KEY_ID,
        None,
        &client_map,
        &mut internal_client,
    )
    .await;
    // Drop server
    drop(kms_server);
    // Get status and validate that it is not serving
    let status = get_status(&mut health_client, service_name).await.unwrap();
    // Threshold servers will start serving as soon as they boot
    // WARNING there is a risk this check fails if the server is shut down before we can complete the status check
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

    Ok(())
}

// ISOLATED VERSION: Validate bug-fix to ensure that the server fails gracefully when the ciphertext is too large
#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
async fn test_largecipher_isolated() -> Result<()> {
    let keys = get_default_keys().await;
    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100,
        pub_decrypt: 1,
        user_decrypt: 100,
        crsgen: 1,
        preproc: 1,
        keygen: 1,
        reshare: 1,
    };
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    // Use isolated setup with rate limiter
    let (kms_server, mut kms_client) = crate::client::test_tools::setup_centralized(
        new_pub_ram_storage_from_existing_keys(&keys.pub_fhe_keys)
            .await
            .unwrap(),
        new_priv_ram_storage_from_existing_keys(&keys.centralized_kms_keys)
            .await
            .unwrap(),
        None,
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
            PkeSchemeType::MlKem512,
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

    Ok(())
}
