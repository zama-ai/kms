#[cfg(feature = "slow_tests")]
use crate::client::client_wasm::Client;
use crate::client::test_tools::{get_health_client, get_status};
use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::consts::TEST_CENTRAL_KEY_ID;
use crate::consts::TEST_PARAM;
#[cfg(feature = "slow_tests")]
use crate::dummy_domain;
#[cfg(feature = "slow_tests")]
use crate::engine::centralized::central_kms::tests::get_default_keys;
use crate::engine::centralized::central_kms::RealCentralizedKms;
#[cfg(feature = "slow_tests")]
use crate::util::rate_limiter::RateLimiterConfig;
use crate::vault::storage::file::FileStorage;
#[cfg(feature = "slow_tests")]
use kms_grpc::kms::v1::TypedCiphertext;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use serial_test::serial;
use std::collections::HashMap;
#[cfg(feature = "slow_tests")]
use tfhe::FheTypes;
use tonic::server::NamedService;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::HealthCheckRequest;
cfg_if::cfg_if! {
   if #[cfg(feature = "insecure")] {
        use crate::{
            cryptography::internal_crypto_types::WrappedDKGParams, engine::base::derive_request_id,
            util::key_setup::test_tools::purge,
        };
        use kms_grpc::{kms::v1::FheParameter, RequestId};
        use crate::util::key_setup::test_tools::EncryptionConfig;
        use kms_grpc::kms::v1::Empty;
        use crate::{
            client::tests::centralized::{
                key_gen_tests::key_gen_centralized, public_decryption_tests::decryption_centralized,
            },
            util::key_setup::test_tools::TestingPlaintext,
            vault::storage::{delete_all_at_request_id, StorageType},
        };
        use kms_grpc::rpc_types::{BackupDataType, PrivDataType};
        use crate::{vault::storage::make_storage};
        use crate::{client::tests::centralized::crs_gen_tests::crs_gen_centralized, vault::storage::StorageReader};
   }
}
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

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_central_dkg_backup() {
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();
    let key_id_1 = derive_request_id("default_insecure_central_dkg_backup-1").unwrap();
    let key_id_2 = derive_request_id("default_insecure_central_dkg_backup-2").unwrap();
    // Delete potentially old data
    purge(None, None, None, &key_id_1, 1).await;
    purge(None, None, None, &key_id_2, 1).await;

    key_gen_centralized(&key_id_1, param, None, None).await;
    key_gen_centralized(&key_id_2, param, None, None).await;
    // Generated key, delete private storage
    let mut priv_storage: FileStorage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
    delete_all_at_request_id(&mut priv_storage, &key_id_1).await;
    delete_all_at_request_id(&mut priv_storage, &key_id_2).await;

    // Now try to restore both keys
    let (kms_server, mut kms_client, internal_client) =
        crate::client::test_tools::centralized_handles(&dkg_param, None).await;

    let req = Empty {};
    // send query
    match kms_client.backup_restore(tonic::Request::new(req)).await {
        Ok(res) => tracing::info!("Backup restore response: {res:?}"),
        Err(e) => {
            panic!("Error while restoring: {e}");
        }
    }

    drop(kms_server);
    drop(kms_client);
    drop(internal_client);
    // Sleep to ensure the servers are properly shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    decryption_centralized(
        &dkg_param.get_params_without_sns(),
        &key_id_1,
        vec![TestingPlaintext::U8(u8::MAX)],
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        1,
    )
    .await;
}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_central_autobackup_after_deletion() {
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();
    let key_id = derive_request_id("default_insecure_autobackup_after_deletion").unwrap();
    // Delete potentially old data
    purge(None, None, None, &key_id, 1).await;
    key_gen_centralized(&key_id, param, None, None).await;
    // Sleep to ensure the servers are properly shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // Start the servers again
    let (_kms_server, _kms_client, _internal_client) =
        crate::client::test_tools::centralized_handles(&dkg_param, None).await;
    // Check the storage
    let backup_storage = make_storage(None, StorageType::BACKUP, None, None, None).unwrap();
    // Validate that the backup is constructed again
    assert!(backup_storage
        .data_exists(
            &key_id,
            &BackupDataType::PrivData(PrivDataType::FheKeyInfo).to_string()
        )
        .await
        .unwrap());
    panic!("check that insecure gets executed by CI!")
}

#[tracing_test::traced_test]
#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_central_crs_backup() {
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();

    let req_id: RequestId =
        derive_request_id(&format!("default_insecure_central_crs_backup_{param:?}",)).unwrap();
    crs_gen_centralized(&req_id, param, true).await;

    // Generated crs, delete it from private storage

    let mut priv_storage: FileStorage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
    delete_all_at_request_id(&mut priv_storage, &req_id).await;
    // Check that is has been removed
    assert!(!priv_storage
        .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
        .await
        .unwrap());

    // Now try to restore
    let (_kms_server, mut kms_client, _internal_client) =
        crate::client::test_tools::centralized_handles(&dkg_param, None).await;

    let req = Empty {};
    // send query
    let query_res = kms_client.backup_restore(tonic::Request::new(req)).await;
    match query_res {
        Ok(resp) => {
            tracing::info!("Backup restore response: {resp:?}");
        }
        Err(e) => {
            panic!("Error while restoring: {e}");
        }
    }

    let backup_storage: FileStorage = FileStorage::new(None, StorageType::BACKUP, None).unwrap();
    // Check the back up is still there
    assert!(backup_storage
        .data_exists(
            &req_id,
            &BackupDataType::PrivData(PrivDataType::CrsInfo).to_string()
        )
        .await
        .unwrap());
    // Check that the file has been restored
    let priv_storage: FileStorage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
    // Check the back up is still there
    assert!(priv_storage
        .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
        .await
        .unwrap());
}
