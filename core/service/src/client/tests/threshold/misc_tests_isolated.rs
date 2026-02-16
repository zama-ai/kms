//! Isolated versions of threshold misc tests
//!
//! These tests mirror the originals in `misc_tests.rs` with identical testing
//! concepts and crypto work, but use isolated test material instead of shared storage.

use crate::client::test_tools::{await_server_ready, check_port_is_closed};
use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::consts::TEST_THRESHOLD_KEY_ID;
use crate::engine::threshold::service::RealThresholdKms;
use crate::testing::prelude::*;
use crate::testing::utils::{get_health_client, get_status};
use crate::vault::storage::file::FileStorage;
use kms_grpc::kms::v1::NewMpcEpochRequest;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::RequestId;
use threshold_fhe::networking::grpc::GrpcServer;
use tokio::task::JoinSet;
use tonic::server::NamedService;
use tonic_health::pb::health_check_response::ServingStatus;

/// ISOLATED VERSION of test_threshold_health_endpoint_availability
///
/// Mirrors the original: boots servers WITHOUT PRSS, sends decryption requests
/// (verifies they are accepted but results fail), checks both core + MPC health,
/// initializes PRSS via new_mpc_epoch, then shuts down and verifies NotServing.
#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_health_endpoint_availability_isolated() -> Result<()> {
    let amount_parties = 4;

    // Boot servers WITHOUT PRSS (run_prss=false is the default)
    // Use a custom material spec that excludes PrssSetup so no PRSS data
    // is loaded from storage at startup (init_all_prss_from_storage would
    // otherwise load pre-generated PRSS, making decryption succeed).
    let mut no_prss_spec = TestMaterialSpec::threshold_basic(amount_parties);
    no_prss_spec.required_keys.remove(&KeyType::PrssSetup);

    let env = ThresholdTestEnv::builder()
        .with_test_name("health_endpoint")
        .with_party_count(amount_parties)
        .with_threshold(1)
        .with_material_spec(no_prss_spec)
        .build()
        .await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    // Create internal client before destructuring env
    let pub_storage_prefixes =
        &crate::consts::PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let mut internal_client = env
        .create_internal_client(&crate::consts::TEST_PARAM, None)
        .await?;
    let material_path = env.material_dir.path().to_path_buf();
    let _material_dir = env.material_dir; // keep alive for temp dir cleanup
    let clients = env.clients;
    let servers = env.servers;

    // Validate that decryption requests are accepted but results fail (no PRSS yet)
    let (dec_tasks, req_id) = crate::client::tests::common::send_dec_reqs(
        1,
        &TEST_THRESHOLD_KEY_ID,
        None,
        &clients,
        &mut internal_client,
        pub_storage_prefixes,
        Some(&material_path),
    )
    .await;
    let dec_res = dec_tasks.join_all().await;
    assert!(dec_res.iter().all(|res| res.is_ok()));
    // But the response will result in an error (no PRSS initialized)
    let dec_resp_tasks = crate::client::tests::common::get_pub_dec_resp(&req_id, &clients).await;
    let dec_resp_res = dec_resp_tasks.join_all().await;
    assert!(dec_resp_res.iter().all(|res| res.is_err()));

    // Check core service health for server 1
    let mut main_health_client = get_health_client(servers.get(&1).unwrap().service_port)
        .await
        .expect("Failed to get core health client");
    let core_service_name = <CoreServiceEndpointServer<
        RealThresholdKms<FileStorage, FileStorage>,
    > as NamedService>::NAME;
    let status = get_status(&mut main_health_client, core_service_name)
        .await
        .unwrap();
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
        "Service is not in NOT_SERVING status. Got status: {status}"
    );

    // Check MPC threshold health for server 1
    let mut threshold_health_client = get_health_client(servers.get(&1).unwrap().mpc_port.unwrap())
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

    // Initialize PRSS via new_mpc_epoch on all parties
    let mut req_tasks = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = clients.get(&i).unwrap().clone();
        req_tasks.spawn(async move {
            let req_id: RequestId = (*crate::consts::DEFAULT_EPOCH_ID).into();
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

    // Shutdown the servers and check that the health endpoint is no longer serving
    for (_, server) in servers {
        server.mpc_shutdown_tx.unwrap().send(()).unwrap();
    }
    // The core server should transition to NotServing
    let mut status = get_status(&mut main_health_client, core_service_name).await;
    while status.is_ok() {
        assert_eq!(
            status.clone().unwrap(),
            ServingStatus::NotServing as i32,
            "Service is not in NOT_SERVING status. Got status: {}",
            status.unwrap()
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        status = get_status(&mut main_health_client, core_service_name).await;
    }

    // The MPC servers should be closed at this point
    let status = get_status(&mut threshold_health_client, threshold_service_name).await;
    assert!(status.is_err());

    Ok(())
}

/// ISOLATED VERSION of test_threshold_close_after_drop
///
/// Mirrors the original: boots servers with PRSS, checks both core + MPC health,
/// drops server 1, sleeps 300ms, verifies both services are unreachable.
#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_close_after_drop_isolated() -> Result<()> {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    let env = ThresholdTestEnv::builder()
        .with_test_name("close_after_drop")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .build()
        .await?;

    let mut servers = env.servers;

    // Get health client for core service on server 1
    let mut core_health_client = get_health_client(servers.get(&1).unwrap().service_port)
        .await
        .expect("Failed to get core health client");
    let core_service_name = <CoreServiceEndpointServer<
        RealThresholdKms<FileStorage, FileStorage>,
    > as NamedService>::NAME;

    // Get health client for MPC threshold service on server 1
    let mut threshold_health_client = get_health_client(servers.get(&1).unwrap().mpc_port.unwrap())
        .await
        .expect("Failed to get threshold health client");
    let threshold_service_name = <GrpcServer as NamedService>::NAME;

    // Check both services are serving
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

    // Drop server 1 to trigger shutdown
    let res = servers.remove(&1).unwrap();
    drop(res);

    // Sleep to allow completion of the shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    // Check both services are no longer reachable
    assert!(get_status(&mut core_health_client, core_service_name)
        .await
        .is_err());
    assert!(
        get_status(&mut threshold_health_client, threshold_service_name)
            .await
            .is_err()
    );

    Ok(())
}

/// ISOLATED VERSION of test_threshold_shutdown
///
/// Mirrors the original: boots servers with PRSS, awaits ready, sends 3 decryption
/// requests to keep server busy, shuts down server 1 via service_shutdown_tx,
/// verifies NotServing status, then verifies ports are closed.
#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_shutdown_isolated() -> Result<()> {
    let amount_parties = 4;
    let pub_storage_prefixes =
        &crate::consts::PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    let env = ThresholdTestEnv::builder()
        .with_test_name("shutdown")
        .with_party_count(amount_parties)
        .with_threshold(1)
        .with_prss()
        .build()
        .await?;

    // Create internal client before destructuring env
    let mut internal_client = env
        .create_internal_client(&crate::consts::TEST_PARAM, None)
        .await?;
    let material_path = env.material_dir.path().to_path_buf();
    let _material_dir = env.material_dir; // keep alive for temp dir cleanup
    let clients = env.clients;
    let mut servers = env.servers;

    // Ensure that the servers are ready
    let core_service_name = <CoreServiceEndpointServer<
        RealThresholdKms<FileStorage, FileStorage>,
    > as NamedService>::NAME;
    for cur_handle in servers.values() {
        await_server_ready(core_service_name, cur_handle.service_port).await;
    }

    let mpc_port = servers.get(&1).unwrap().mpc_port.unwrap();
    let service_port = servers.get(&1).unwrap().service_port;

    // Get health clients for server 1
    let mut core_health_client = get_health_client(service_port)
        .await
        .expect("Failed to get core health client");
    let status = get_status(&mut core_health_client, core_service_name)
        .await
        .unwrap();
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
        "Service is not in SERVING status. Got status: {status}"
    );

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

    // Keep the server occupied so it won't shut down immediately after dropping the handle
    let (tasks, _req_id) = crate::client::tests::common::send_dec_reqs(
        3,
        &TEST_THRESHOLD_KEY_ID,
        None,
        &clients,
        &mut internal_client,
        pub_storage_prefixes,
        Some(&material_path),
    )
    .await;
    let dec_res = tasks.join_all().await;
    assert!(dec_res.iter().all(|res| res.is_ok()));

    let server_handle = servers.remove(&1).unwrap();
    // Shut down the Core server (which also shuts down the MPC server)
    server_handle.service_shutdown_tx.send(()).unwrap();

    // Sleep to give the server some time to set the health reporter to not serving
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let status = get_status(&mut core_health_client, core_service_name)
        .await
        .unwrap();
    assert_eq!(
        status,
        ServingStatus::NotServing as i32,
        "Service is not in NOT SERVING status. Got status: {status}"
    );

    let shutdown_handle = server_handle.server.shutdown().unwrap();
    shutdown_handle.await.unwrap();
    check_port_is_closed(mpc_port).await;
    check_port_is_closed(service_port).await;

    Ok(())
}

/// ISOLATED VERSION: Test rate limiter functionality
///
/// Validates that the rate limiter correctly rejects requests when the bucket is exhausted.
#[tokio::test(flavor = "multi_thread")]
#[cfg(feature = "slow_tests")]
async fn test_ratelimiter_isolated() -> Result<()> {
    use crate::consts::TEST_PARAM;
    use crate::dummy_domain;
    use crate::engine::base::derive_request_id;
    use crate::util::rate_limiter::RateLimiterConfig;
    use kms_grpc::kms::v1::FheParameter;

    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100,
        pub_decrypt: 1,
        user_decrypt: 1,
        crsgen: 100, // Consume entire bucket on first request
        preproc: 1,
        keygen: 1,
        new_epoch: 1,
    };

    let env = ThresholdTestEnv::builder()
        .with_test_name("ratelimiter")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss() // Need PRSS for CRS gen
        .with_rate_limiter(rate_limiter_conf)
        .build()
        .await?;

    let domain = dummy_domain();

    // Create internal client using the helper method
    let internal_client = env.create_internal_client(&TEST_PARAM, None).await?;

    // First request should succeed
    let req_id_1 = derive_request_id("test_ratelimiter_isolated_1")?;
    let req =
        internal_client.crs_gen_request(&req_id_1, Some(16), Some(FheParameter::Test), &domain)?;

    let mut client = env.clients.get(&1).expect("Client 1 should exist").clone();
    let res = client.crs_gen(req).await;
    assert!(res.is_ok(), "First CRS gen request should succeed");

    // Second request should be rejected due to rate limiter
    let req_id_2 = derive_request_id("test_ratelimiter_isolated_2")?;
    let req_2 =
        internal_client.crs_gen_request(&req_id_2, Some(1), Some(FheParameter::Test), &domain)?;
    let res_2 = client.crs_gen(req_2).await;

    assert!(res_2.is_err(), "Second CRS gen request should be rejected");
    assert_eq!(
        res_2.unwrap_err().code(),
        tonic::Code::ResourceExhausted,
        "Should get ResourceExhausted error from rate limiter"
    );

    Ok(())
}
