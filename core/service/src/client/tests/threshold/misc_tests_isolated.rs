//! Isolated versions of threshold misc tests
//!
//! These tests mirror the originals in `misc_tests.rs` with identical testing
//! concepts and crypto work, but use isolated test material instead of shared storage.

use crate::client::test_tools::{await_server_ready, check_port_is_closed};
use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::consts::TEST_THRESHOLD_KEY_ID_4P;
use crate::engine::threshold::service::RealThresholdKms;
use crate::testing::prelude::*;
use crate::testing::utils::{get_health_client, get_status};
use crate::vault::storage::file::FileStorage;
use kms_grpc::kms::v1::NewMpcEpochRequest;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::RequestId;
#[cfg(feature = "slow_tests")]
use serial_test::serial;
use threshold_fhe::networking::grpc::GrpcServer;
use tokio::task::JoinSet;
use tonic::server::NamedService;
use tonic_health::pb::health_check_response::ServingStatus;

/// ISOLATED VERSION of test_threshold_health_endpoint_availability
///
/// Mirrors the original: boots servers WITHOUT PRSS, sends decryption requests
/// (verifies they are accepted but results fail), checks both core + MPC health,
/// initializes PRSS via new_mpc_epoch, then shuts down and verifies NotServing.
#[tokio::test]
async fn test_threshold_health_endpoint_availability_isolated() -> Result<()> {
    let amount_parties = 4;

    // Boot servers WITHOUT PRSS and without pre-generated PRSS material,
    // so decryption requests fail (no epoch initialized). FHE keys are still
    // needed so send_dec_reqs can encrypt ciphertexts for the request.
    let spec = {
        use crate::testing::material::KeyType;
        let mut s = TestMaterialSpec::threshold_signing_only(amount_parties);
        s.required_keys.insert(KeyType::FheKeys);
        s
    };
    let env = ThresholdTestEnv::builder()
        .with_test_name("health_endpoint")
        .with_party_count(amount_parties)
        .with_threshold(1)
        .with_material_spec(spec)
        .force_isolated() // Must use isolated material: shared mode includes PRSS data
        // which would cause the epoch to load, making decrypt succeed
        // instead of returning NotFound.
        .build()
        .await?;

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

    // Wait for all core servers to be ready before sending requests
    let core_service_name = <CoreServiceEndpointServer<
        RealThresholdKms<FileStorage, FileStorage>,
    > as NamedService>::NAME;
    for cur_handle in servers.values() {
        await_server_ready(core_service_name, cur_handle.service_port).await;
    }

    // Validate that the send itself fails since there is no PRSS (no epoch initialized)
    let (dec_tasks, _req_id) = crate::client::tests::common::send_dec_reqs(
        1,
        &TEST_THRESHOLD_KEY_ID_4P,
        None,
        &clients,
        &mut internal_client,
        pub_storage_prefixes,
        Some(&material_path),
    )
    .await;
    let dec_res = dec_tasks.join_all().await;
    assert!(dec_res
        .iter()
        .all(|res| res.is_err() && res.as_ref().err().unwrap().code() == tonic::Code::NotFound));

    // Check core service health for server 1
    let mut main_health_client = get_health_client(servers.get(&1).unwrap().service_port)
        .await
        .expect("Failed to get core health client");
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

    // Shutdown the servers and check that the threshold health endpoint is no longer serving
    for (_, server) in servers {
        server.assert_shutdown().await;
    }
    let status = get_status(&mut threshold_health_client, threshold_service_name).await;
    assert!(status.is_err());

    Ok(())
}

/// ISOLATED VERSION of test_threshold_close_after_drop
///
/// Mirrors the original: boots servers with PRSS, checks both core + MPC health,
/// drops server 1, sleeps 300ms, verifies both services are unreachable.
#[tokio::test]
async fn test_threshold_close_after_drop_isolated() -> Result<()> {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    let env = ThresholdTestEnv::builder()
        .with_test_name("close_after_drop")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .force_isolated() // Prevent writing PRSS data to the shared test-material source
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
#[tokio::test]
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
        .force_isolated() // Prevent writing PRSS/context data to shared test-material source
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
        &TEST_THRESHOLD_KEY_ID_4P,
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
#[tokio::test]
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
        .force_isolated() // Prevent writing PRSS/context data to shared test-material source
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

/// ISOLATED VERSION: Validates the fix that ensures that a party is notified
/// if it starts a session the others consider completed.
///
/// The test:
/// 1. Sets up 4 threshold parties with PRSS
/// 2. Encrypts messages using stored keys
/// 3. Sends decrypt requests to all parties except party 3 (simulating a skipped party)
/// 4. Verifies the other 3 parties complete successfully
/// 5. Waits for session timeout, then sends the request to party 3
/// 6. Verifies party 3 gets an Internal error (session already completed by others)
#[tracing_test::traced_test]
#[tokio::test(flavor = "current_thread")]
#[cfg(feature = "slow_tests")]
#[serial]
async fn nightly_test_complete_session_notification_isolated() -> Result<()> {
    use crate::consts::{PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL, TEST_PARAM};
    use crate::dummy_domain;
    use crate::engine::base::derive_request_id;
    use crate::util::key_setup::max_threshold;
    use crate::util::key_setup::test_tools::{
        compute_cipher_from_stored_key, EncryptionConfig, TestingPlaintext,
    };
    use kms_grpc::kms::v1::TypedCiphertext;
    use std::env;
    use tokio::task::JoinSet;

    let amount_parties = 4;
    let key_id = &TEST_THRESHOLD_KEY_ID_4P;
    let enc_config = EncryptionConfig {
        compression: true,
        precompute_sns: true,
    };
    let msg_amount = 10;
    let parallel_reqs = 1;
    let wait_time = 4;

    // Ensure inactive session discard interval is small for the test
    env::set_var(
        "KMS_CORE__THRESHOLD__CORE_TO_CORE_NET__SESSION_UPDATE_INTERVAL_SECS",
        format!("{}", wait_time),
    );
    // Ensure that the session status update interval is small s.t. aborted sessions get removed quickly
    env::set_var(
        "KMS_CORE__THRESHOLD__CORE_TO_CORE_NET__DISCARD_INACTIVE_SESSIONS_INTERVAL",
        format!("{}", wait_time + 1),
    );
    // And ensure that checking for abort and received values will happen quickly
    env::set_var(
        "KMS_CORE__THRESHOLD__CORE_TO_CORE_NET__MAX_WAITING_TIME_FOR_MESSAGE_QUEUE",
        format!("{}", wait_time + 2),
    );

    let env = ThresholdTestEnv::builder()
        .with_test_name("complete_session_notification")
        .with_party_count(amount_parties)
        .with_threshold(1) // For 4 parties: threshold = ⌈4/3⌉ - 1 = 1
        .with_prss()
        .force_isolated() // Prevent writing PRSS/context data to shared test-material source
        .build()
        .await?;

    let mut internal_client = env.create_internal_client(&TEST_PARAM, None).await?;

    let mut msgs = Vec::new();
    let mut cts = Vec::new();
    for i in 0_usize..msg_amount {
        let msg = TestingPlaintext::U64(i as u64);
        let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
            Some(env.material_dir.path()),
            msg,
            key_id,
            PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0].as_deref(),
            enc_config,
            false,
        )
        .await;

        let ctt = TypedCiphertext {
            ciphertext: ct,
            fhe_type: fhe_type as i32,
            ciphertext_format: ct_format.into(),
            external_handle: i.to_be_bytes().to_vec(),
        };
        cts.push(ctt);
        msgs.push(msg);
    }

    for j in 1..=parallel_reqs {
        // make parallel requests by calling [decrypt] in a thread
        let mut req_tasks = JoinSet::new();

        // Make it unique wrt key_id as well to be sure there's no clash when running
        // the dec test with multiple keys.
        let request_id = derive_request_id(&format!("TEST_COMPLETE_SESSION{j}")).unwrap();

        let req = internal_client
            .public_decryption_request(
                cts.clone(),
                &dummy_domain(),
                &request_id,
                None,
                key_id,
                None,
            )
            .unwrap();

        // Either send the request, or skip the party if it's in party_ids_to_skip
        let party_ids_to_skip = [3];
        let kms_servers_keys: Vec<u32> = env.servers.keys().copied().collect();
        for i in kms_servers_keys.iter() {
            if !party_ids_to_skip.contains(&(*i as usize)) {
                let req_clone = req.clone();
                let mut cur_client = env.clients.get(i).unwrap().clone();
                req_tasks.spawn(async move {
                    cur_client
                        .public_decrypt(tonic::Request::new(req_clone))
                        .await
                });
            }
        }
        println!("Sending requests...");
        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner.unwrap().unwrap().into_inner());
        }
        assert_eq!(
            req_response_vec.len(),
            env.clients.len() - party_ids_to_skip.len()
        );
        println!("Requests received by server");

        // get all responses
        let mut resp_tasks = JoinSet::new();
        for i in kms_servers_keys.iter() {
            if party_ids_to_skip.contains(&(*i as usize)) {
                continue;
            }
            let mut cur_client = env.clients.get(i).unwrap().clone();
            let req_id_clone = req.request_id.as_ref().unwrap().clone();
            resp_tasks.spawn(async move {
                let mut response = cur_client
                    .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                    .await;
                while response.is_err()
                    && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    response = cur_client
                        .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                }
                (req_id_clone, response.unwrap().into_inner())
            });
        }
        println!("sent responses...");
        let mut resp_response_vec = Vec::new();
        while let Some(resp) = resp_tasks.join_next().await {
            resp_response_vec.push(resp.unwrap());
        }
        println!("received responses");
        let responses: Vec<_> = resp_response_vec
            .iter()
            .filter_map(|(req_id, resp)| {
                if req_id == req.request_id.as_ref().unwrap() {
                    Some(resp.clone())
                } else {
                    None
                }
            })
            .collect();
        // Compute threshold < amount_parties/3
        let threshold = max_threshold(amount_parties);
        let min_count_agree = (threshold + 1) as u32;
        let received_plaintexts = internal_client
            .process_decryption_resp(Some(req.clone()), &responses, min_count_agree)
            .unwrap();

        // check that the plaintexts are correct
        for i in 0..msg_amount {
            crate::client::tests::common::assert_plaintext(&msgs[i], &received_plaintexts[i]);
        }

        // Now decrypt with the party that skipped the session.
        // Ensure we sleep longer than the update interval s.t. the active session gets processed
        tokio::time::sleep(tokio::time::Duration::from_secs(wait_time + 4)).await;
        println!("Starting decryption for the party that skipped the session");
        for i in kms_servers_keys.iter() {
            if party_ids_to_skip.contains(&(*i as usize)) {
                let mut cur_client = env.clients.get(i).unwrap().clone();
                let req_clone = req.clone();
                req_tasks.spawn(async move {
                    cur_client
                        .public_decrypt(tonic::Request::new(req_clone))
                        .await
                });
            }
        }

        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner.unwrap().unwrap().into_inner());
        }
        assert_eq!(req_response_vec.len(), party_ids_to_skip.len());

        // get all responses
        let mut resp_tasks = JoinSet::new();
        for i in kms_servers_keys.iter() {
            if !party_ids_to_skip.contains(&(*i as usize)) {
                continue;
            }
            let mut cur_client = env.clients.get(i).unwrap().clone();
            let req_id_clone = req.request_id.as_ref().unwrap().clone();
            resp_tasks.spawn(async move {
                let mut response = cur_client
                    .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                    .await;
                while response.is_err()
                    && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    response = cur_client
                        .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                }

                (req_id_clone, response.as_ref().unwrap_err().code())
            });
        }

        while let Some(resp) = resp_tasks.join_next().await {
            // Check for an internal failure since the other servers have already completed the session
            // The test will fail if the session basically stalls instead of aborting
            assert_eq!(resp.unwrap().1, tonic::Code::Internal); // TODO in theory Aborted should be returned but it is a mess to propagate this through the threshold library
        }
    }

    Ok(())
}
