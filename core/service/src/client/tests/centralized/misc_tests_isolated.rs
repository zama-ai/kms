//! Isolated versions of centralized misc tests
//!
//! This file uses the consolidated testing module for clean, maintainable tests.

use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::consts::TEST_CENTRAL_KEY_ID;
use crate::engine::centralized::central_kms::RealCentralizedKms;
use crate::testing::prelude::*;
use crate::testing::utils::{get_health_client, get_status};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use std::collections::HashMap;
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

/// Check that the centralized health service is serving as soon as boot is completed.
#[tokio::test]
async fn test_central_health_endpoint_availability_isolated() -> Result<()> {
    let env = CentralizedTestEnv::builder()
        .with_test_name("health_endpoint")
        .build()
        .await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let mut health_client = get_health_client(env.server.service_port)
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
    use crate::consts::TEST_PARAM;

    let env = CentralizedTestEnv::builder()
        .with_test_name("close_after_drop")
        .build()
        .await?;

    // Create additional storage instances for internal client
    let pub_storage = FileStorage::new(Some(env.material_dir.path()), StorageType::PUB, None)?;
    let client_storage =
        FileStorage::new(Some(env.material_dir.path()), StorageType::CLIENT, None)?;

    // Create internal client with isolated material
    let pub_storage_map = HashMap::from([(1, pub_storage)]);
    let mut internal_client = crate::client::client_wasm::Client::new_client(
        client_storage,
        pub_storage_map,
        &TEST_PARAM,
        None,
    )
    .await?;

    let kms_server = env.server;
    let kms_client = env.client;

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
        &[None],
        Some(env.material_dir.path()), // use isolated material path
    )
    .await;
    // Drop server
    drop(kms_server);
    // Get status and validate that it is not serving
    let status = get_status(&mut health_client, service_name).await.unwrap();
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
    // In centralized mode, dropping the single server means all responses should fail
    assert!(dec_resp_res.iter().all(|res| res.is_err()));
    // Check the server is no longer there
    assert!(get_status(&mut health_client, service_name).await.is_err());

    Ok(())
}

/// Validate bug-fix to ensure that the server fails gracefully when the ciphertext is too large.
///
/// This test uses RAM storage with custom rate limiter config (not the builder pattern)
/// because it needs fine-grained control over the rate limiter settings.
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
        new_epoch: 1,
    };

    // Setup with RAM storage and custom rate limiter
    let (kms_server, mut kms_client) = crate::client::test_tools::setup_centralized(
        new_pub_ram_storage_from_existing_keys(&keys.pub_fhe_keys)
            .await
            .unwrap(),
        new_priv_ram_storage_from_existing_keys(
            &keys.centralized_kms_keys,
            &crate::consts::DEFAULT_EPOCH_ID,
        )
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
            None, // context_id
            None, // epoch_id
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
    assert!(
        response.is_err(),
        "Expected error response for large ciphertext, got Ok"
    );
    let err = response.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal);
    assert!(
        err.message().contains("finished with an error")
            || err.message().contains("Failed on requestID"),
        "Expected error message to indicate failure, got: {}",
        err.message()
    );
    tracing::info!("aborting");
    kms_server.assert_shutdown().await;

    Ok(())
}
