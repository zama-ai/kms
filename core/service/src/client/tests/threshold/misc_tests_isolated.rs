//! Isolated versions of threshold misc tests
//!
//! This file uses the consolidated testing module for clean, maintainable tests.

use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::testing::prelude::*;
use crate::testing::utils::{get_health_client, get_status};
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
