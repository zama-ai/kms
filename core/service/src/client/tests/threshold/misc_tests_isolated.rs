//! Isolated versions of threshold misc tests
//!
//! This file demonstrates the migration pattern from shared test material
//! to isolated test material using TestMaterialManager.

use crate::client::test_tools::{get_health_client, get_status, setup_threshold_isolated};
use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::consts::TEST_PARAM;
use crate::util::key_setup::test_material_manager::TestMaterialManager;
use crate::util::key_setup::test_material_spec::TestMaterialSpec;
use crate::vault::storage::{file::FileStorage, StorageType};
use anyhow::Result;
use std::collections::HashMap;
use tempfile::TempDir;
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::networking::grpc::GrpcServer;
use tonic::server::NamedService;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::HealthCheckRequest;

/// Helper function to setup isolated threshold test environment
async fn setup_isolated_threshold_test(test_name: &str, party_count: usize) -> Result<(TempDir, HashMap<u32, crate::client::test_tools::ServerHandle>, HashMap<u32, kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient<tonic::transport::Channel>>)> {
    // Use the test-material directory where we generated the material
    // Need to go up two levels from core/service to reach the root
    let source_path = std::env::current_dir()?.parent().unwrap().parent().unwrap().join("test-material");
    let manager = TestMaterialManager::new(Some(source_path));
    let spec = TestMaterialSpec::threshold_basic(party_count);
    let material_dir = manager.setup_test_material(&spec, test_name).await?;
    
    let mut pub_storages = Vec::new();
    let mut priv_storages = Vec::new();
    for i in 1..=party_count {
        let role = Role::indexed_from_one(i);
        pub_storages.push(FileStorage::new(Some(material_dir.path()), StorageType::PUB, Some(role))?);
        priv_storages.push(FileStorage::new(Some(material_dir.path()), StorageType::PRIV, Some(role))?);
    }
    
    let (servers, clients) = setup_threshold_isolated(
        2, // threshold
        pub_storages,
        priv_storages,
        (0..party_count).map(|_| None).collect(), // No vaults
        false, // No PRSS
        None, // No rate limiter
        None, // No decryption mode
        Some(material_dir.path()),
    ).await;
    
    Ok((material_dir, servers, clients))
}

/// ISOLATED VERSION: Check that the threshold health service is serving as soon as boot is completed.
/// 
/// - Each test gets its own temporary directory with pre-generated material
#[tokio::test]
async fn test_threshold_health_endpoint_availability_isolated() -> Result<()> {
    let (_material_dir, servers, _clients) = setup_isolated_threshold_test("health_endpoint", 4).await?;
    
    // Give threshold servers more time to initialize
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS * 3)).await;
    
    // Test health endpoint for the first server
    let server = servers.get(&1).expect("Server 1 should exist");
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
    
    let (_material_dir, mut servers, _clients) = setup_isolated_threshold_test("close_after_drop", 4).await?;
    
    // Test with the first server
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
    let (_material_dir, servers, _clients) = setup_isolated_threshold_test("shutdown", 4).await?;
    
    // Test shutdown for all servers
    for (party_id, server) in servers {
        tracing::info!("Testing shutdown for party {}", party_id);
        server.assert_shutdown().await;
    }
    
    Ok(())
}
