use crate::client::test_tools::check_port_is_closed;
use crate::client::test_tools::ServerHandle;
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

/// Test that the health endpoint is available for the threshold service only *after* they have been initialized.
/// Also check that shutdown of the servers triggers the health endpoint to stop serving as expected.
/// This tests validates the availability of both the core service but also the internal service between the MPC parties.
///
/// The crux of the test is based on the fact that the MPC servers serve immidiately but the core server only serves after
/// the PRSS initialization has been completed.
#[tokio::test]
#[serial]
async fn test_threshold_health_endpoint_availability() {
    // make sure the store does not contain any PRSS info (currently stored under ID PRSS_INIT_REQ_ID)
    let req_id = &derive_request_id(&format!(
        "PRSSSetup_Z128_ID_{PRSS_INIT_REQ_ID}_{DEFAULT_AMOUNT_PARTIES}_{DEFAULT_THRESHOLD}"
    ))
    .unwrap();
    purge(None, None, None, req_id, DEFAULT_AMOUNT_PARTIES).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    // DON'T setup PRSS in order to ensure the server is not ready yet
    let (kms_servers, kms_clients, mut internal_client) =
        crate::client::tests::threshold::common::threshold_handles(
            TEST_PARAM,
            DEFAULT_AMOUNT_PARTIES,
            false,
            None,
            None,
        )
        .await;

    // Validate that the core server is not ready
    let (dec_tasks, req_id) = crate::client::tests::common::send_dec_reqs(
        1,
        &TEST_THRESHOLD_KEY_ID,
        &kms_clients,
        &mut internal_client,
    )
    .await;
    let dec_res = dec_tasks.join_all().await;
    // Even though servers are not initialized they will accept the requests
    assert!(dec_res.iter().all(|res| res.is_ok()));
    // But the response will result in an error
    let dec_resp_tasks =
        crate::client::tests::common::get_pub_dec_resp(&req_id, &kms_clients).await;
    let dec_resp_res = dec_resp_tasks.join_all().await;
    assert!(dec_resp_res.iter().all(|res| res.is_err()));

    // Get health client for main server 1
    let mut main_health_client = get_health_client(kms_servers.get(&1).unwrap().service_port)
        .await
        .expect("Failed to get core health client");
    let core_service_name = <CoreServiceEndpointServer<
            RealThresholdKms<FileStorage, FileStorage>,
        > as NamedService>::NAME;
    let status = get_status(&mut main_health_client, core_service_name)
        .await
        .unwrap();
    // Check that the main server is not serving since it has not been initialized yet
    assert_eq!(
        status,
        ServingStatus::NotServing as i32,
        "Service is not in NOT_SERVING status. Got status: {status}"
    );
    // Get health client for main server 1
    let mut threshold_health_client =
        get_health_client(kms_servers.get(&1).unwrap().mpc_port.unwrap())
            .await
            .expect("Failed to get threshold health client");
    let threshold_service_name = <GrpcServer as NamedService>::NAME;
    let status = get_status(&mut threshold_health_client, threshold_service_name)
        .await
        .unwrap();
    // Threshold servers will start serving as soon as they boot
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
        "Service is not in SERVING status. Got status: {status}"
    );

    // Now initialize and check that the server is serving
    let mut req_tasks = JoinSet::new();
    for i in 1..=DEFAULT_AMOUNT_PARTIES as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        req_tasks.spawn(async move {
            let req_id = RequestId::from_str(PRSS_INIT_REQ_ID).unwrap();
            cur_client
                .init(tonic::Request::new(InitRequest {
                    request_id: Some(req_id.into()),
                }))
                .await
        });
    }
    while let Some(inner) = req_tasks.join_next().await {
        assert!(inner.unwrap().is_ok());
    }
    let status = get_status(&mut main_health_client, core_service_name)
        .await
        .unwrap();
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
        "Service is not in SERVING status. Got status: {status}"
    );

    // Shutdown the servers and check that the health endpoint is no longer serving
    for (_, server) in kms_servers {
        // Shut down MPC servers triggers a shutdown of the core server
        server.mpc_shutdown_tx.unwrap().send(()).unwrap();
    }
    //  The core server should not be serving
    let mut status = get_status(&mut main_health_client, core_service_name).await;
    // As long as the server is open check that it is not serving
    while status.is_ok() {
        assert_eq!(
            status.clone().unwrap(),
            ServingStatus::NotServing as i32,
            "Service is not in NOT_SERVING status. Got status: {}",
            status.unwrap()
        );
        // Sleep a bit and check whether the server has shut down
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        status = get_status(&mut main_health_client, core_service_name).await;
    }

    // The MPC servers should be closed at this point
    let status = get_status(&mut threshold_health_client, threshold_service_name).await;
    assert!(status.is_err(),);
}

/// Validate that dropping the server signal triggers the server to shut down
#[tokio::test]
#[serial]
async fn test_threshold_close_after_drop() {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (mut kms_servers, _kms_clients, _internal_client) =
        crate::client::tests::threshold::common::threshold_handles(
            TEST_PARAM,
            DEFAULT_AMOUNT_PARTIES,
            true,
            None,
            None,
        )
        .await;

    // Get health client for main server 1
    let mut core_health_client = get_health_client(kms_servers.get(&1).unwrap().service_port)
        .await
        .expect("Failed to get core health client");
    let core_service_name = <CoreServiceEndpointServer<
            RealThresholdKms<FileStorage, FileStorage>,
        > as NamedService>::NAME;
    // Get health client for main server 1
    let mut threshold_health_client =
        get_health_client(kms_servers.get(&1).unwrap().mpc_port.unwrap())
            .await
            .expect("Failed to get threshold health client");
    let threshold_service_name = <GrpcServer as NamedService>::NAME;
    // Check things are working
    let status = get_status(&mut core_health_client, core_service_name)
        .await
        .unwrap();
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
        "Service is not in SERVING status. Got status: {status}"
    );
    let status = get_status(&mut threshold_health_client, threshold_service_name)
        .await
        .unwrap();
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
        "Service is not in SERVING status. Got status: {status}"
    );
    let res = kms_servers.remove(&1).unwrap();
    // Trigger the shutdown
    drop(res);
    // Sleep to allow completion of the shut down which should be quick since we waited for existing tasks to be done
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    // Check the server is no longer there
    assert!(get_status(&mut core_health_client, core_service_name)
        .await
        .is_err());
    assert!(
        get_status(&mut threshold_health_client, threshold_service_name)
            .await
            .is_err()
    );
}

/// Validate that shutdown signals work
#[tokio::test]
#[serial]
async fn test_threshold_shutdown() {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (mut kms_servers, kms_clients, mut internal_client) =
        crate::client::tests::threshold::common::threshold_handles(
            TEST_PARAM,
            DEFAULT_AMOUNT_PARTIES,
            true,
            None,
            None,
        )
        .await;
    // Ensure that the servers are ready
    for cur_handle in kms_servers.values() {
        let service_name = <CoreServiceEndpointServer<
                RealThresholdKms<FileStorage, FileStorage>,
            > as NamedService>::NAME;
        await_server_ready(service_name, cur_handle.service_port).await;
    }
    let mpc_port = kms_servers.get(&1).unwrap().mpc_port.unwrap();
    let service_port = kms_servers.get(&1).unwrap().service_port;
    // Get health client for main server 1
    let mut core_health_client = get_health_client(kms_servers.get(&1).unwrap().service_port)
        .await
        .expect("Failed to get core health client");
    let core_service_name = <CoreServiceEndpointServer<
            RealThresholdKms<FileStorage, FileStorage>,
        > as NamedService>::NAME;
    let status = get_status(&mut core_health_client, core_service_name)
        .await
        .unwrap();
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
        "Service is not in SERVING status. Got status: {status}"
    );
    // Get health client for main server 1
    let mut threshold_health_client = get_health_client(mpc_port)
        .await
        .expect("Failed to get threshold health client");
    let threshold_service_name = <GrpcServer as NamedService>::NAME;
    let status = get_status(&mut threshold_health_client, threshold_service_name)
        .await
        .unwrap();
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
        "Service is not in SERVING status. Got status: {status}"
    );
    // Keep the server occupied so it won't shut down immidiately after dropping the handle
    let (tasks, _req_id) = crate::client::tests::common::send_dec_reqs(
        3,
        &TEST_THRESHOLD_KEY_ID,
        &kms_clients,
        &mut internal_client,
    )
    .await;
    let dec_res = tasks.join_all().await;
    assert!(dec_res.iter().all(|res| res.is_ok()));
    let server_handle = kms_servers.remove(&1).unwrap();
    // Shut down the Core server (which also shuts down the MPC server)
    server_handle.service_shutdown_tx.send(()).unwrap();
    // Get status and validate that it is not serving
    // Observe that the server should already have set status to net serving while it is finishing the decryption requests.
    // Sleep to give the server some time to set the health reporter to not serving. To fix we need to add shutdown that takes care of thread_group is finished before finishing
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let status = get_status(&mut core_health_client, core_service_name)
        .await
        .unwrap();
    // Threshold servers will start serving as soon as they boot
    // WARNING there is a risk this check fails if the server is shut down before was can complete the status check
    assert_eq!(
        status,
        ServingStatus::NotServing as i32,
        "Service is not in NOT SERVING status. Got status: {status}"
    );
    let shutdown_handle = server_handle.server.shutdown().unwrap();
    shutdown_handle.await.unwrap();
    check_port_is_closed(mpc_port).await;
    check_port_is_closed(service_port).await;
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(feature = "slow_tests")]
#[serial]
async fn test_ratelimiter() {
    let req_id: RequestId = derive_request_id("test_ratelimiter").unwrap();
    let domain = dummy_domain();
    purge(None, None, None, &req_id, 4).await;
    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100,
        pub_decrypt: 1,
        user_decrypt: 1,
        crsgen: 100,
        preproc: 1,
        keygen: 1,
    };
    let (_kms_servers, kms_clients, internal_client) =
        crate::client::tests::threshold::common::threshold_handles(
            TEST_PARAM,
            4,
            true,
            Some(rate_limiter_conf),
            None,
        )
        .await;

    let req_id = derive_request_id("test rate limiter 1").unwrap();
    let req = internal_client
        .crs_gen_request(&req_id, Some(16), Some(FheParameter::Test), domain.clone())
        .unwrap();
    let mut cur_client = kms_clients.get(&1).unwrap().clone();
    let res = cur_client.crs_gen(req).await;
    // Check that first request is ok and accepted
    assert!(res.is_ok());
    // Try to do another request during preproc,
    // the request should be rejected due to rate limiter.
    // This should be done after the requests above start being
    // processed in the kms.
    let req_id_2 = derive_request_id("test rate limiter2").unwrap();
    let req_2 = internal_client
        .crs_gen_request(&req_id_2, Some(1), Some(FheParameter::Test), domain)
        .unwrap();
    let res = cur_client.crs_gen(req_2).await;
    assert_eq!(res.unwrap_err().code(), tonic::Code::ResourceExhausted);
}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_dkg_backup() {
    // NOTE: amount_parties must not be too high
    // because every party will load all the keys and each ServerKey is 1.5 GB
    // and each private key share is 1 GB. Using 7 parties fails on a 32 GB machine.

    let amount_parties = 4;
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();

    let key_id_1: RequestId = derive_request_id(&format!(
        "default_insecure_dkg_backup_1_{amount_parties}_{param:?}",
    ))
    .unwrap();
    let key_id_2: RequestId = derive_request_id(&format!(
        "default_insecure_dkg_backup_2_{amount_parties}_{param:?}",
    ))
    .unwrap();

    let test_path = None;
    purge(test_path, test_path, test_path, &key_id_1, amount_parties).await;
    purge(test_path, test_path, test_path, &key_id_2, amount_parties).await;
    let (kms_servers, kms_clients, internal_client) =
        crate::client::tests::threshold::common::threshold_handles(
            *dkg_param,
            amount_parties,
            true,
            None,
            None,
        )
        .await;

    let _keys_1 = crate::client::tests::threshold::key_gen_tests::run_threshold_keygen(
        param,
        &kms_clients,
        &internal_client,
        None,
        &key_id_1,
        None,
        None,
        true,
    )
    .await;

    let _keys_2 = crate::client::tests::threshold::key_gen_tests::run_threshold_keygen(
        param,
        &kms_clients,
        &internal_client,
        None,
        &key_id_2,
        None,
        None,
        true,
    )
    .await;

    // Generated key, delete private storage
    for i in 1..=amount_parties {
        let mut priv_storage: FileStorage = FileStorage::new(
            test_path,
            StorageType::PRIV,
            Some(Role::indexed_from_one(i)),
        )
        .unwrap();
        delete_all_at_request_id(&mut priv_storage, &key_id_1).await;
        delete_all_at_request_id(&mut priv_storage, &key_id_2).await;
    }

    // Now try to restore both keys
    let mut resp_tasks = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        resp_tasks.spawn(async move {
            let req = Empty {};
            // send query
            cur_client
                .custodian_backup_restore(tonic::Request::new(req))
                .await
        });
    }
    while let Some(res) = resp_tasks.join_next().await {
        match res {
            Ok(res) => match res {
                Ok(resp) => {
                    tracing::info!("Custodian backup restore response: {resp:?}");
                }
                Err(e) => {
                    panic!("Error while restoring: {e}");
                }
            },
            Err(e) => {
                panic!("Error while restoring: {e}");
            }
        }
    }
    drop(kms_servers);
    drop(kms_clients);
    drop(internal_client);
    // Sleep to ensure the servers are properly shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // And validate that we can still decrypt
    crate::client::tests::threshold::public_decryption_tests::decryption_threshold(
        DEFAULT_PARAM,
        &key_id_2,
        vec![TestingPlaintext::U8(42)],
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        1,
        amount_parties,
        None,
        Some(DecryptionMode::NoiseFloodSmall),
    )
    .await;
}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_autobackup_after_deletion() {
    // NOTE: amount_parties must not be too high
    // because every party will load all the keys and each ServerKey is 1.5 GB
    // and each private key share is 1 GB. Using 7 parties fails on a 32 GB machine.
    use crate::conf::FileStorage as FileStorageConf;
    use crate::conf::Storage as StorageConf;

    let amount_parties = 4;
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();

    let key_id: RequestId = derive_request_id(&format!(
        "default_insecure_autobackup_after_deletion_{amount_parties}_{param:?}",
    ))
    .unwrap();
    let test_path = None;

    purge(test_path, test_path, test_path, &key_id, amount_parties).await;
    let (kms_servers, kms_clients, internal_client) =
        crate::client::tests::threshold::common::threshold_handles(
            *dkg_param,
            amount_parties,
            true,
            None,
            None,
        )
        .await;

    let _keys = crate::client::tests::threshold::key_gen_tests::run_threshold_keygen(
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

    // Reboot the servers
    drop(kms_servers);
    drop(kms_clients);
    drop(internal_client);
    // Sleep to ensure the servers are properly shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Start the servers again
    let (_kms_servers, _kms_clients, _internal_client) =
        crate::client::tests::threshold::common::threshold_handles(
            *dkg_param,
            amount_parties,
            true,
            None,
            None,
        )
        .await;
    // Check the storage
    let vault_storage_option = test_path.map(|path| {
        StorageConf::File(FileStorageConf {
            path: path.to_path_buf(),
        })
    });
    for cur_party in 1..=amount_parties {
        let backup_storage = make_storage(
            vault_storage_option.clone(),
            StorageType::BACKUP,
            Some(Role::indexed_from_one(cur_party)),
            None,
            None,
        )
        .unwrap();
        assert!(backup_storage
            .data_exists(&key_id, &PrivDataType::FheKeyInfo.to_string())
            .await
            .unwrap());
    }
}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_crs_backup() {
    let amount_parties = 4;
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();

    let req_id: RequestId = derive_request_id(&format!(
        "default_insecure_crs_backup{amount_parties}_{param:?}",
    ))
    .unwrap();
    let test_path = None;
    purge(test_path, test_path, test_path, &req_id, amount_parties).await;
    let (_kms_servers, kms_clients, internal_client) =
        crate::client::tests::threshold::common::threshold_handles(
            *dkg_param,
            amount_parties,
            true,
            None,
            None,
        )
        .await;
    crate::client::tests::threshold::crs_gen_tests::run_crs(
        param,
        &kms_clients,
        &internal_client,
        true, // insecure execution
        &req_id,
        Some(16),
    )
    .await;
    // Generated crs, delete it from private storage
    for i in 1..=amount_parties {
        let mut priv_storage: FileStorage = FileStorage::new(
            test_path,
            StorageType::PRIV,
            Some(Role::indexed_from_one(i)),
        )
        .unwrap();
        delete_all_at_request_id(&mut priv_storage, &req_id).await;
    }
    // Now try to restore
    let mut resp_tasks = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        resp_tasks.spawn(async move {
            let req = Empty {};
            // send query
            cur_client
                .custodian_backup_restore(tonic::Request::new(req))
                .await
        });
    }
    while let Some(res) = resp_tasks.join_next().await {
        match res {
            Ok(res) => match res {
                Ok(resp) => {
                    tracing::info!("Custodian backup restore response: {resp:?}");
                }
                Err(e) => {
                    panic!("Error while restoring: {e}");
                }
            },
            Err(e) => {
                panic!("Error while joining threads: {e}");
            }
        }
    }
    // Check the file is restored
    for i in 1..=amount_parties {
        let backup_storage: FileStorage = FileStorage::new(
            test_path,
            StorageType::BACKUP,
            Some(Role::indexed_from_one(i)),
        )
        .unwrap();
        assert!(backup_storage
            .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
            .await
            .unwrap());
    }
}
