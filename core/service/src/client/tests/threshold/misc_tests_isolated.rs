//! Isolated versions of threshold misc tests
//!
//! This file uses the consolidated testing module for clean, maintainable tests.

use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::testing::prelude::*;
use crate::testing::utils::{get_health_client, get_status};
#[cfg(feature = "slow_tests")]
use serial_test::serial;
use threshold_fhe::networking::grpc::GrpcServer;
use tonic::server::NamedService;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::HealthCheckRequest;

/// ISOLATED VERSION: Check that the threshold health service is serving as soon as boot is completed.
///
/// - Each test gets its own temporary directory with pre-generated material
#[tokio::test]
async fn test_threshold_health_endpoint_availability_isolated() -> Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("health_endpoint")
        .with_party_count(4)
        .with_threshold(1) // For 4 parties: threshold = ⌈4/3⌉ - 1 = 1
        .with_prss() // PRSS is required for the server to be able to serve
        .build()
        .await?;

    // Give threshold servers more time to initialize
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS * 3)).await;

    // Test health endpoint for the first server
    let server = env.servers.get(&1).expect("Server 1 should exist");
    let health_port = server.mpc_port.unwrap_or(server.service_port);
    let mut health_client = get_health_client(health_port)
        .await
        .expect("Failed to get health client");
    let service_name = <GrpcServer as NamedService>::NAME;
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

/// ISOLATED VERSION: Validate that dropping the server signal triggers the server to shut down
///
/// - Creates internal client with isolated material
#[tokio::test]
async fn test_threshold_close_after_drop_isolated() -> Result<()> {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    let env = ThresholdTestEnv::builder()
        .with_test_name("close_after_drop")
        .with_party_count(4)
        .with_threshold(1) // For 4 parties: threshold = ⌈4/3⌉ - 1 = 1
        .with_prss() // PRSS is required for the server to be able to serve
        .build()
        .await?;

    // Test with the first server
    let mut servers = env.servers;
    let server = servers.remove(&1).expect("Server 1 should exist");
    let health_port = server.mpc_port.unwrap_or(server.service_port);
    let mut health_client = get_health_client(health_port)
        .await
        .expect("Failed to get health client");
    let service_name = <GrpcServer as NamedService>::NAME;
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

    // Drop server to trigger shutdown
    drop(server);

    // Wait for server to fully shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

    // After shutdown, the server should no longer be reachable
    assert!(
        get_status(&mut health_client, service_name).await.is_err(),
        "Server should not be reachable after shutdown"
    );

    Ok(())
}

/// ISOLATED VERSION: Test threshold server shutdown
#[tokio::test]
async fn test_threshold_shutdown_isolated() -> Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("shutdown")
        .with_party_count(4)
        .with_threshold(1) // For 4 parties: threshold = ⌈4/3⌉ - 1 = 1
        .build()
        .await?;

    // Test shutdown for all servers
    for (party_id, server) in env.into_servers_with_id() {
        tracing::info!("Testing shutdown for party {}", party_id);
        server.assert_shutdown().await;
    }

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
    use crate::consts::{
        PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL, TEST_PARAM, TEST_THRESHOLD_KEY_ID_4P,
    };
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
