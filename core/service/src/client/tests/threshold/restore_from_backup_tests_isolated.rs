//! Isolated threshold backup and restore tests
//!
//! These tests use isolated test material (TestMaterialManager). Each test runs
//! in its own temporary directory with pre-generated cryptographic material.
//!
//! ## Tests Included
//! - DKG backup and restore flow
//! - Auto-backup after server restart
//! - CRS backup and restore flow
//!
//! ## Key Features
//! - No Docker dependency
//! - Each test uses isolated temporary directory
//! - Pre-generated material copied per test
//! - Native KMS servers spawned in-process
//! - Automatic cleanup via RAII (Drop trait)

use crate::client::test_tools::{domain_to_msg, setup_threshold_isolated, ThresholdTestConfig};
#[cfg(feature = "insecure")]
use crate::client::tests::threshold::common::threshold_key_gen_isolated;
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::util::key_setup::test_material_manager::TestMaterialManager;
use crate::util::key_setup::test_material_spec::TestMaterialSpec;
use crate::vault::storage::{
    delete_all_at_request_id, file::FileStorage, StorageReader, StorageType,
};
use crate::vault::Vault;
use anyhow::Result;
use kms_grpc::kms::v1::{Empty, FheParameter};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PrivDataType;
use std::collections::HashMap;
use tempfile::TempDir;
use threshold_fhe::execution::runtime::party::Role;
use tokio::task::JoinSet;
use tonic::transport::Channel;

/// Helper function to setup isolated threshold test environment for backup tests
async fn setup_isolated_threshold_backup_test(
    test_name: &str,
    party_count: usize,
) -> Result<(
    TempDir,
    HashMap<u32, crate::client::test_tools::ServerHandle>,
    HashMap<u32, CoreServiceEndpointClient<Channel>>,
)> {
    use crate::vault::storage::make_storage;

    let source_path = std::env::current_dir()?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test-material");
    let manager = TestMaterialManager::new(Some(source_path));
    let spec = TestMaterialSpec::threshold_basic(party_count);
    let material_dir = manager.setup_test_material(&spec, test_name).await?;

    let mut pub_storages = Vec::new();
    let mut priv_storages = Vec::new();
    let mut backup_vaults = Vec::new();

    for i in 1..=party_count {
        let role = Role::indexed_from_one(i);
        pub_storages.push(FileStorage::new(
            Some(material_dir.path()),
            StorageType::PUB,
            Some(role),
        )?);
        priv_storages.push(FileStorage::new(
            Some(material_dir.path()),
            StorageType::PRIV,
            Some(role),
        )?);

        // Create backup vault for each party
        let backup_storage = make_storage(
            Some(crate::conf::Storage::File(crate::conf::FileStorage {
                path: material_dir.path().to_path_buf(),
            })),
            StorageType::BACKUP,
            Some(role),
            None,
            None,
        )?;
        backup_vaults.push(Some(Vault {
            storage: backup_storage,
            keychain: None,
        }));
    }

    let threshold = ((party_count - 1) / 3).max(1);
    let (servers, clients) = setup_threshold_isolated(
        threshold as u8,
        pub_storages,
        priv_storages,
        backup_vaults,
        ThresholdTestConfig {
            test_material_path: Some(material_dir.path()),
            ..Default::default()
        },
    )
    .await;

    Ok((material_dir, servers, clients))
}

/// Test threshold DKG backup and restore flow.
///
/// Generates two threshold FHE keys, deletes them from private storage on all parties,
/// restores from backup, and verifies restoration succeeded. Tests the complete
/// backup/restore cycle for threshold key material.
///
/// **Flow:**
/// 1. Generate two keys using insecure DKG
/// 2. Delete both keys from private storage (all parties)
/// 3. Verify deletion
/// 4. Restore from backup (all parties)
/// 5. Verify restoration (checks FheKeyInfo exists)
///
/// **Requires:** `insecure` feature flag
/// **Run with:** `cargo test --lib --features insecure,testing nightly_test_insecure_threshold_dkg_backup_isolated`
#[tokio::test]
#[cfg(feature = "insecure")]
async fn nightly_test_insecure_threshold_dkg_backup_isolated() -> Result<()> {
    let party_count = 4;
    let (material_dir, servers, clients) =
        setup_isolated_threshold_backup_test("threshold_dkg_backup", party_count).await?;

    let key_id_1 = derive_request_id("isolated-threshold-dkg-backup-1")?;
    let key_id_2 = derive_request_id("isolated-threshold-dkg-backup-2")?;

    threshold_key_gen_isolated(&clients, &key_id_1, FheParameter::Test).await?;
    threshold_key_gen_isolated(&clients, &key_id_2, FheParameter::Test).await?;

    // Delete private storage for both keys on all parties
    for i in 1..=party_count {
        let mut priv_storage = FileStorage::new(
            Some(material_dir.path()),
            StorageType::PRIV,
            Some(Role::indexed_from_one(i)),
        )?;
        let _ = delete_all_at_request_id(&mut priv_storage, &key_id_1).await;
        let _ = delete_all_at_request_id(&mut priv_storage, &key_id_2).await;
    }

    // Verify deletion
    let priv_storage = FileStorage::new(
        Some(material_dir.path()),
        StorageType::PRIV,
        Some(Role::indexed_from_one(1)),
    )?;
    assert!(
        !priv_storage
            .data_exists(&key_id_1, &PrivDataType::FhePrivateKey.to_string())
            .await?
    );

    // Restore from backup on all parties
    let mut restore_tasks = JoinSet::new();
    for client in clients.values() {
        let mut cur_client = client.clone();
        restore_tasks.spawn(async move {
            cur_client
                .restore_from_backup(tonic::Request::new(Empty {}))
                .await
        });
    }

    while let Some(res) = restore_tasks.join_next().await {
        let resp = res??;
        tracing::info!("Backup restore response: {:?}", resp);
    }

    // Verify restoration (threshold uses FheKeyInfo, not FhePrivateKey)
    for i in 1..=party_count {
        let priv_storage = FileStorage::new(
            Some(material_dir.path()),
            StorageType::PRIV,
            Some(Role::indexed_from_one(i)),
        )?;
        assert!(
            priv_storage
                .data_exists(&key_id_1, &PrivDataType::FheKeyInfo.to_string())
                .await?
        );
    }

    for (_, server) in servers {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test threshold auto-backup after server restart.
///
/// Generates a threshold FHE key, shuts down servers, restarts them with the same
/// storage, and verifies that backup was automatically created on restart. Tests
/// the auto-backup mechanism that protects against key loss.
///
/// **Flow:**
/// 1. Generate key using insecure DKG
/// 2. Shutdown all servers
/// 3. Restart servers with same storage
/// 4. Verify backup was auto-created (checks FheKeyInfo in backup storage)
///
/// **Requires:** `insecure` feature flag
/// **Run with:** `cargo test --lib --features insecure,testing nightly_test_insecure_threshold_autobackup_after_deletion_isolated`
#[tokio::test]
#[cfg(feature = "insecure")]
async fn nightly_test_insecure_threshold_autobackup_after_deletion_isolated() -> Result<()> {
    let party_count = 4;
    let (material_dir, servers, clients) =
        setup_isolated_threshold_backup_test("threshold_autobackup", party_count).await?;

    let key_id = derive_request_id("isolated-threshold-autobackup")?;

    threshold_key_gen_isolated(&clients, &key_id, FheParameter::Test).await?;

    // Shutdown servers
    drop(clients);
    for (_, server) in servers {
        server.assert_shutdown().await;
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Restart servers with same storage
    let mut pub_storages = Vec::new();
    let mut priv_storages = Vec::new();
    for i in 1..=party_count {
        let role = Role::indexed_from_one(i);
        pub_storages.push(FileStorage::new(
            Some(material_dir.path()),
            StorageType::PUB,
            Some(role),
        )?);
        priv_storages.push(FileStorage::new(
            Some(material_dir.path()),
            StorageType::PRIV,
            Some(role),
        )?);
    }

    let threshold = ((party_count - 1) / 3).max(1);
    let (_new_servers, _new_clients) = setup_threshold_isolated(
        threshold as u8,
        pub_storages,
        priv_storages,
        (0..party_count).map(|_| None).collect(),
        ThresholdTestConfig {
            test_material_path: Some(material_dir.path()),
            ..Default::default()
        },
    )
    .await;

    // Verify backup was auto-created on restart (threshold uses FheKeyInfo)
    for i in 1..=party_count {
        let backup_storage = FileStorage::new(
            Some(material_dir.path()),
            StorageType::BACKUP,
            Some(Role::indexed_from_one(i)),
        )?;
        assert!(
            backup_storage
                .data_exists(&key_id, &PrivDataType::FheKeyInfo.to_string())
                .await?
        );
    }

    Ok(())
}

/// Test threshold CRS backup and restore flow.
///
/// Generates CRS (Common Reference String) on all parties, deletes it from private
/// storage, restores from backup, and verifies restoration. Tests the complete
/// backup/restore cycle for CRS material.
///
/// **Flow:**
/// 1. Generate CRS on all parties
/// 2. Wait for CRS generation to complete
/// 3. Delete CRS from private storage (all parties)
/// 4. Verify deletion
/// 5. Restore from backup (all parties)
/// 6. Verify both backup and restored CRS exist
///
/// **Run with:** `cargo test --lib --features testing test_insecure_threshold_crs_backup_isolated`
#[tokio::test]
async fn test_insecure_threshold_crs_backup_isolated() -> Result<()> {
    use kms_grpc::kms::v1::CrsGenRequest;

    let party_count = 4;
    let (material_dir, servers, clients) =
        setup_isolated_threshold_backup_test("threshold_crs_backup", party_count).await?;

    let req_id = derive_request_id("isolated-threshold-crs-backup")?;

    // Generate CRS on all parties
    let domain_msg = domain_to_msg(&dummy_domain());
    let mut crs_tasks = JoinSet::new();
    for client in clients.values() {
        let mut cur_client = client.clone();
        let req = CrsGenRequest {
            request_id: Some(req_id.into()),
            params: FheParameter::Test as i32,
            max_num_bits: Some(16),
            domain: Some(domain_msg.clone()),
            context_id: None,
        };
        crs_tasks.spawn(async move { cur_client.crs_gen(tonic::Request::new(req)).await });
    }

    while let Some(res) = crs_tasks.join_next().await {
        res??;
    }

    // Wait for CRS generation to complete
    for client in clients.values() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_crs_gen_result(tonic::Request::new(req_id.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_crs_gen_result(tonic::Request::new(req_id.into()))
                .await;
        }
        result?;
    }

    // Delete CRS from private storage on all parties
    for i in 1..=party_count {
        let mut priv_storage = FileStorage::new(
            Some(material_dir.path()),
            StorageType::PRIV,
            Some(Role::indexed_from_one(i)),
        )?;
        let _ = delete_all_at_request_id(&mut priv_storage, &req_id).await;

        assert!(
            !priv_storage
                .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
                .await?
        );
    }

    // Restore from backup on all parties
    let mut restore_tasks = JoinSet::new();
    for client in clients.values() {
        let mut cur_client = client.clone();
        restore_tasks.spawn(async move {
            cur_client
                .restore_from_backup(tonic::Request::new(Empty {}))
                .await
        });
    }

    while let Some(res) = restore_tasks.join_next().await {
        let resp = res??;
        tracing::info!("Backup restore response: {:?}", resp);
    }

    // Verify backup still exists and CRS was restored
    for i in 1..=party_count {
        let backup_storage = FileStorage::new(
            Some(material_dir.path()),
            StorageType::BACKUP,
            Some(Role::indexed_from_one(i)),
        )?;
        assert!(
            backup_storage
                .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
                .await?
        );

        let priv_storage = FileStorage::new(
            Some(material_dir.path()),
            StorageType::PRIV,
            Some(Role::indexed_from_one(i)),
        )?;
        assert!(
            priv_storage
                .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
                .await?
        );
    }

    for (_, server) in servers {
        server.assert_shutdown().await;
    }

    Ok(())
}
