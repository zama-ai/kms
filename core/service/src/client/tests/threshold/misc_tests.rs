use crate::client::test_tools::{
    await_server_ready, check_port_is_closed, get_health_client, get_status,
};
use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::client::tests::threshold::common::threshold_handles;
use crate::consts::{
    DEFAULT_EPOCH_ID, PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL,
    TEST_PARAM, TEST_THRESHOLD_KEY_ID,
};
use crate::engine::threshold::service::RealThresholdKms;
use crate::util::key_setup::test_tools::purge;
use crate::vault::storage::file::FileStorage;
cfg_if::cfg_if! {
    if #[cfg(feature = "slow_tests")] {
        use kms_grpc::kms::v1::FheParameter;
        use crate::dummy_domain;
        use crate::engine::base::derive_request_id;
        use crate::util::rate_limiter::RateLimiterConfig;
    }
}
use kms_grpc::kms::v1::NewMpcEpochRequest;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::RequestId;
use serial_test::serial;
use threshold_fhe::networking::grpc::GrpcServer;
use tokio::task::JoinSet;
use tonic::server::NamedService;
use tonic_health::pb::health_check_response::ServingStatus;

/// Test that the health endpoint is available for the threshold service only *after* they have been initialized.
/// Also check that shutdown of the servers triggers the health endpoint to stop serving as expected.
/// This tests validates the availability of both the core service but also the internal service between the MPC parties.
///
/// The crux of the test is based on the fact that the MPC servers serve immediately but the core server only serves after
/// the PRSS initialization has been completed.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_threshold_health_endpoint_availability() {
    let amount_parties = 4;
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    // make sure the store does not contain any PRSS info
    let epoch_id = *DEFAULT_EPOCH_ID;
    purge(
        None,
        None,
        &epoch_id.into(),
        pub_storage_prefixes,
        priv_storage_prefixes,
    )
    .await;
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    // DON'T setup PRSS in order to ensure the server is not ready yet
    let (kms_servers, kms_clients, mut internal_client) =
        threshold_handles(TEST_PARAM, amount_parties, false, None, None).await;

    // Validate that the core server is not ready
    let (dec_tasks, req_id) = crate::client::tests::common::send_dec_reqs(
        1,
        &TEST_THRESHOLD_KEY_ID,
        None,
        &kms_clients,
        &mut internal_client,
        pub_storage_prefixes,
        None,
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
            let req_id: RequestId = (*DEFAULT_EPOCH_ID).into();
            cur_client
                .new_mpc_epoch(tonic::Request::new(NewMpcEpochRequest {
                    epoch_id: Some(req_id.into()),
                    context_id: None,
                    previous_epoch: None,
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
    let amount_parties = 4;
    let storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (mut kms_servers, kms_clients, mut internal_client) =
        threshold_handles(TEST_PARAM, amount_parties, true, None, None).await;
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
        None,
        &kms_clients,
        &mut internal_client,
        storage_prefixes,
        None,
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
    let amount_parties = 4;
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let req_id: RequestId = derive_request_id("test_ratelimiter").unwrap();
    let domain = dummy_domain();
    purge(
        None,
        None,
        &req_id,
        pub_storage_prefixes,
        priv_storage_prefixes,
    )
    .await;
    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100,
        pub_decrypt: 1,
        user_decrypt: 1,
        crsgen: 100,
        preproc: 1,
        keygen: 1,
        reshare: 1,
    };
    let (_kms_servers, kms_clients, internal_client) = threshold_handles(
        TEST_PARAM,
        amount_parties,
        true,
        Some(rate_limiter_conf),
        None,
    )
    .await;

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
