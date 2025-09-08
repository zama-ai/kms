use crate::client::test_tools::{
    await_server_ready, check_port_is_closed, get_health_client, get_status,
};
use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::client::tests::threshold::common::threshold_handles;
#[cfg(feature = "insecure")]
use crate::client::tests::threshold::crs_gen_tests::run_crs;
#[cfg(feature = "insecure")]
use crate::consts::DEFAULT_PARAM;
use crate::consts::{PRSS_INIT_REQ_ID, TEST_PARAM, TEST_THRESHOLD_KEY_ID};
#[cfg(feature = "insecure")]
use crate::cryptography::internal_crypto_types::WrappedDKGParams;
#[cfg(feature = "slow_tests")]
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::engine::threshold::service::RealThresholdKms;
use crate::util::key_setup::test_tools::purge;
#[cfg(feature = "insecure")]
use crate::util::key_setup::test_tools::{EncryptionConfig, TestingPlaintext};
#[cfg(feature = "slow_tests")]
use crate::util::rate_limiter::RateLimiterConfig;
#[cfg(feature = "insecure")]
use crate::vault::storage::delete_all_at_request_id;
use crate::vault::storage::file::FileStorage;
#[cfg(feature = "insecure")]
use crate::vault::storage::StorageType;
#[cfg(feature = "insecure")]
use crate::vault::storage::{make_storage, StorageReader};
#[cfg(feature = "insecure")]
use kms_grpc::kms::v1::Empty;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use kms_grpc::kms::v1::FheParameter;
use kms_grpc::kms::v1::InitRequest;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
#[cfg(feature = "insecure")]
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::RequestId;
use serial_test::serial;
use std::str::FromStr;
#[cfg(feature = "insecure")]
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
#[cfg(feature = "insecure")]
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::networking::grpc::GrpcServer;
use tokio::task::JoinSet;
use tonic::server::NamedService;
use tonic_health::pb::health_check_response::ServingStatus;

/// Test that the health endpoint is available for the threshold service only *after* they have been initialized.
/// Also check that shutdown of the servers triggers the health endpoint to stop serving as expected.
/// This tests validates the availability of both the core service but also the internal service between the MPC parties.
///
/// The crux of the test is based on the fact that the MPC servers serve immidiately but the core server only serves after
/// the PRSS initialization has been completed.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_threshold_health_endpoint_availability() {
    // make sure the store does not contain any PRSS info (currently stored under ID PRSS_INIT_REQ_ID)
    let req_id = &derive_request_id(&format!("PRSSSetup_Z128_ID_{PRSS_INIT_REQ_ID}_4_1")).unwrap();
    purge(None, None, None, req_id, 4).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    // DON'T setup PRSS in order to ensure the server is not ready yet
    let (kms_servers, kms_clients, mut internal_client) =
        threshold_handles(TEST_PARAM, 4, false, None, None).await;

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
    for i in 1..=4 {
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
        match inner {
            Ok(resp) => match resp {
                Ok(resp) => tracing::info!("Init response: {resp:?}"),
                Err(e) => panic!("Init request failed: {e}"),
            },
            Err(e) => panic!("Init request failed: {e}"),
        }
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
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_threshold_close_after_drop() {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (mut kms_servers, _kms_clients, _internal_client) =
        threshold_handles(TEST_PARAM, 4, true, None, None).await;

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
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_threshold_shutdown() {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (mut kms_servers, kms_clients, mut internal_client) =
        threshold_handles(TEST_PARAM, 4, true, None, None).await;
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
        threshold_handles(TEST_PARAM, 4, true, Some(rate_limiter_conf), None).await;

    let req_id = derive_request_id("test rate limiter 1").unwrap();
    let req = internal_client
        .crs_gen_request(&req_id, Some(16), Some(FheParameter::Test), &domain)
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
        .crs_gen_request(&req_id_2, Some(1), Some(FheParameter::Test), &domain)
        .unwrap();
    let res = cur_client.crs_gen(req_2).await;
    assert_eq!(res.unwrap_err().code(), tonic::Code::ResourceExhausted);
}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_threshold_dkg_backup() {
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
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;

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
            cur_client.backup_restore(tonic::Request::new(req)).await
        });
    }
    while let Some(res) = resp_tasks.join_next().await {
        match res {
            Ok(res) => match res {
                Ok(resp) => {
                    tracing::info!("Backup restore response: {resp:?}");
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
async fn default_insecure_threshold_autobackup_after_deletion() {
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
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;

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
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;
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
        // Validate that the backup is constructed again
        assert!(backup_storage
            .data_exists(&key_id, &PrivDataType::FheKeyInfo.to_string())
            .await
            .unwrap());
    }
}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_threshold_crs_backup() {
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
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;
    run_crs(
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
        // Check that is has been removed
        assert!(!priv_storage
            .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
            .await
            .unwrap());
    }
    // Now try to restore
    let mut resp_tasks = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        resp_tasks.spawn(async move {
            let req = Empty {};
            // send query
            cur_client.backup_restore(tonic::Request::new(req)).await
        });
    }
    while let Some(res) = resp_tasks.join_next().await {
        match res {
            Ok(res) => match res {
                Ok(resp) => {
                    tracing::info!("Backup restore response: {resp:?}");
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
    println!("req id is {req_id}");
    for i in 1..=amount_parties {
        let backup_storage: FileStorage = FileStorage::new(
            test_path,
            StorageType::BACKUP,
            Some(Role::indexed_from_one(i)),
        )
        .unwrap();
        // Check the back up is still there
        assert!(backup_storage
            .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
            .await
            .unwrap());
        // Check that the file has been restored
        let priv_storage: FileStorage = FileStorage::new(
            test_path,
            StorageType::PRIV,
            Some(Role::indexed_from_one(i)),
        )
        .unwrap();
        // Check the back up is still there
        assert!(priv_storage
            .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
            .await
            .unwrap());
    }
}
