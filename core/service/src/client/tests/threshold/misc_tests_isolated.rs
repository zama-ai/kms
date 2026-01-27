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

    // Drop server
    drop(server);

    // Get status and validate that it is not serving
    let status = get_status(&mut health_client, service_name).await.unwrap();
    assert_eq!(
        status,
        ServingStatus::NotServing as i32,
        "Service is not in NOT SERVING status. Got status: {status}"
    );

    // Check the server is no longer there
    assert!(get_status(&mut health_client, service_name).await.is_err());

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
