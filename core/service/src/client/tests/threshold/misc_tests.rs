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
        use std::env;
        use kms_grpc::kms::v1::{FheParameter, TypedCiphertext};
        use crate::util::key_setup::max_threshold;
        use crate::consts::TEST_THRESHOLD_KEY_ID_4P;
        use crate::dummy_domain;
        use crate::engine::base::derive_request_id;
        use crate::util::rate_limiter::RateLimiterConfig;
        use crate::util::key_setup::test_tools::{compute_cipher_from_stored_key, EncryptionConfig, TestingPlaintext};
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
    // Check that the main server is serving since it should be running
    assert_eq!(
        status,
        ServingStatus::Serving as i32,
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
        new_epoch: 1,
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

/// Validates the fix that ensures that a party is notified if it starts a session the others consider completed.
#[tracing_test::traced_test]
#[tokio::test(flavor = "current_thread")]
#[cfg(feature = "slow_tests")]
#[serial]
async fn nightly_test_complete_session_notification() {
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

    let (kms_servers, kms_clients, mut internal_client) =
        threshold_handles(TEST_PARAM, amount_parties, true, None, None).await;
    assert_eq!(kms_clients.len(), kms_servers.len());
    let mut msgs = Vec::new();
    let mut cts = Vec::new();
    for i in 0_usize..msg_amount {
        let msg = TestingPlaintext::U64(i as u64);
        let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
            None,
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

        // Make it unique wrt key_id as well do be sure there's no clash when running
        // the dec test with multiple keys.
        // Also, make it depend on the messages because we may use the same function
        // to decrypt multiple messages.
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

        // Either send the request, or skip the party if it's in
        // party_ids_to_skip
        let party_ids_to_skip = [3];
        let kms_servers_keys: Vec<u32> = kms_servers.keys().copied().collect();
        for i in kms_servers_keys.iter() {
            if !party_ids_to_skip.contains(&(*i as usize)) {
                let req_clone = req.clone();
                let mut cur_client = kms_clients.get(i).unwrap().clone();
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
            kms_clients.len() - party_ids_to_skip.len()
        );
        println!("Reqests received by server");
        // get all responses
        let mut resp_tasks = JoinSet::new();
        for i in kms_servers_keys.iter() {
            if party_ids_to_skip.contains(&(*i as usize)) {
                continue;
            }
            let mut cur_client = kms_clients.get(i).unwrap().clone();
            let req_id_clone = req.request_id.as_ref().unwrap().clone();
            resp_tasks.spawn(async move {
                let mut response = cur_client
                    .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                    .await;
                while response.is_err()
                    && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                {
                    // wait for 4*bits ms before the next query, but at least 100ms and at most 1s.
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

        // Now decrypt with the party that skipped the session. Ensure we sleep longer than the update interval s.t. the active session gets processed
        tokio::time::sleep(tokio::time::Duration::from_secs(wait_time + 4)).await;
        println!("Starting decryption for the party that skipped the session");
        for i in kms_servers_keys.iter() {
            if party_ids_to_skip.contains(&(*i as usize)) {
                let mut cur_client = kms_clients.get(i).unwrap().clone();
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
            let mut cur_client = kms_clients.get(i).unwrap().clone();
            let req_id_clone = req.request_id.as_ref().unwrap().clone();
            resp_tasks.spawn(async move {
                let mut response = cur_client
                    .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                    .await;
                while response.is_err()
                    && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                {
                    // wait for 4*bits ms before the next query, but at least 100ms and at most 1s.
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    response = cur_client
                        .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                }

                (req_id_clone, response.as_ref().unwrap_err().code())
            });
        }

        // let mut resp_response_vec = Vec::new();
        while let Some(resp) = resp_tasks.join_next().await {
            // Check for an internal failure since the other servers have already completed the session
            // The test will fail if the session basically stalls instead of aborting
            assert_eq!(resp.unwrap().1, tonic::Code::Internal); // TODO in theory Aborted should be returned but it is a mess to propagate this through the threshold library
        }
    }
}
