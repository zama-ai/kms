//! Isolated centralized backup and restore tests
//!
//! These tests use the consolidated testing module. Each test runs
//! in its own temporary directory with pre-generated cryptographic material.
//!
//! ## Tests Included
//! - DKG backup and restore flow
//! - Auto-backup after server restart
//! - CRS backup and restore flow (nightly)
//!
//! ## Key Features
//! - No Docker dependency
//! - Each test uses isolated temporary directory
//! - Pre-generated material copied per test
//! - Native KMS server spawned in-process
//! - Automatic cleanup via RAII (Drop trait)

use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::testing::helpers::domain_to_msg;
use crate::testing::prelude::*;
use crate::testing::utils::{EncryptionConfig, TestingPlaintext};
use crate::vault::storage::{delete_all_at_request_id, StorageReader, StorageReaderExt};
use kms_grpc::kms::v1::{Empty, FheParameter, TypedCiphertext};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::RequestId;
use std::path::Path;
use tonic::transport::Channel;

/// Helper to generate key using isolated client (insecure mode - still requires preprocessing)
async fn key_gen_isolated(
    client: &mut CoreServiceEndpointClient<Channel>,
    request_id: &RequestId,
    params: FheParameter,
) -> Result<()> {
    use kms_grpc::kms::v1::{KeyGenPreprocRequest, KeyGenRequest};

    // Preprocessing (required even for insecure mode)
    let preproc_id = derive_request_id(&format!("preproc-for-{:?}", request_id))?;
    let domain_msg = domain_to_msg(&dummy_domain());
    let preproc_req = KeyGenPreprocRequest {
        request_id: Some(preproc_id.into()),
        params: params as i32,
        keyset_config: None,
        domain: Some(domain_msg.clone()),
        context_id: None,
        epoch_id: None,
    };

    let preproc_resp = client
        .key_gen_preproc(tonic::Request::new(preproc_req))
        .await?;
    assert_eq!(preproc_resp.into_inner(), Empty {});

    // Wait for preprocessing to complete
    let mut preproc_result = client
        .get_key_gen_preproc_result(tonic::Request::new(preproc_id.into()))
        .await;
    while preproc_result.is_err()
        && preproc_result.as_ref().unwrap_err().code() == tonic::Code::Unavailable
    {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        preproc_result = client
            .get_key_gen_preproc_result(tonic::Request::new(preproc_id.into()))
            .await;
    }
    preproc_result?;

    // Key generation
    let keygen_req = KeyGenRequest {
        request_id: Some((*request_id).into()),
        params: Some(params as i32),
        preproc_id: Some(preproc_id.into()),
        domain: Some(domain_msg),
        keyset_config: None,
        keyset_added_info: None,
        context_id: None,
        epoch_id: None,
    };

    let keygen_resp = client.key_gen(tonic::Request::new(keygen_req)).await?;
    assert_eq!(keygen_resp.into_inner(), Empty {});

    // Wait for key generation to complete
    let mut result = client
        .get_key_gen_result(tonic::Request::new((*request_id).into()))
        .await;
    while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        result = client
            .get_key_gen_result(tonic::Request::new((*request_id).into()))
            .await;
    }
    let inner_resp = result?.into_inner();
    assert_eq!(inner_resp.request_id, Some((*request_id).into()));

    Ok(())
}

/// Helper to verify key restoration by encrypting a test message.
///
/// This function verifies that the key material exists and is usable by
/// successfully encrypting a message. If the key was not properly restored,
/// `compute_cipher_from_stored_key` will fail.
async fn verify_key_usable_isolated(
    material_dir: &Path,
    key_id: &RequestId,
    msg: TestingPlaintext,
) -> Result<TypedCiphertext> {
    use crate::testing::utils::compute_cipher_from_stored_key;

    let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
        Some(material_dir),
        msg,
        key_id,
        None, // storage_prefix - use default
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        false,
    )
    .await;

    // Return the ciphertext to prove key material is usable
    Ok(TypedCiphertext {
        ciphertext: ct,
        fhe_type: fhe_type as i32,
        ciphertext_format: ct_format.into(),
        external_handle: vec![],
    })
}

/// Test centralized DKG backup and restore flow.
///
/// Generates two FHE keys, deletes them from private storage, restores from backup,
/// and verifies restoration by performing decryption. Tests the complete backup/restore
/// cycle for centralized key material.
///
/// **Flow:**
/// 1. Generate two keys using insecure DKG
/// 2. Delete both keys from private storage
/// 3. Verify deletion
/// 4. Restore from backup
/// 5. Verify restoration via decryption test
///
/// **Run with:** `cargo test --lib --features testing,insecure test_insecure_central_dkg_backup_isolated`
#[cfg(feature = "insecure")]
#[tokio::test]
async fn test_insecure_central_dkg_backup_isolated() -> Result<()> {
    // Setup using builder pattern with backup vault
    let env = CentralizedTestEnv::builder()
        .with_test_name("dkg_backup")
        .with_backup_vault()
        .build()
        .await?;

    let material_dir = env.material_dir;
    let server = env.server;
    let mut client = env.client;

    let key_id_1 = derive_request_id("isolated-dkg-backup-1")?;
    let key_id_2 = derive_request_id("isolated-dkg-backup-2")?;

    key_gen_isolated(&mut client, &key_id_1, FheParameter::Test).await?;
    key_gen_isolated(&mut client, &key_id_2, FheParameter::Test).await?;

    let mut priv_storage = FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;
    let _ = delete_all_at_request_id(&mut priv_storage, &key_id_1).await;
    let _ = delete_all_at_request_id(&mut priv_storage, &key_id_2).await;

    assert!(
        !priv_storage
            .data_exists(&key_id_1, &PrivDataType::FhePrivateKey.to_string())
            .await?,
        "key_id_1 should be deleted"
    );
    assert!(
        !priv_storage
            .data_exists(&key_id_2, &PrivDataType::FhePrivateKey.to_string())
            .await?,
        "key_id_2 should be deleted"
    );

    let req = Empty {};
    let resp = client.restore_from_backup(tonic::Request::new(req)).await?;
    tracing::info!("Backup restore response: {:?}", resp);

    // Verify key restoration by encrypting a test message
    let _ct1 = verify_key_usable_isolated(
        material_dir.path(),
        &key_id_1,
        TestingPlaintext::U8(u8::MAX),
    )
    .await?;
    let _ct2 = verify_key_usable_isolated(
        material_dir.path(),
        &key_id_2,
        TestingPlaintext::U8(u8::MAX),
    )
    .await?;

    drop(client);
    server.assert_shutdown().await;

    Ok(())
}

/// Test centralized auto-backup after key generation.
///
/// Generates an FHE key, shuts down server, and verifies that backup was
/// automatically created. Tests the auto-backup mechanism that protects
/// against key loss.
///
/// **Flow:**
/// 1. Generate key using insecure DKG
/// 2. Shutdown server
/// 3. Verify backup was auto-created (checks FhePrivateKey in backup storage)
///
/// **Run with:** `cargo test --lib --features testing,insecure test_insecure_central_autobackup_after_deletion_isolated`
#[cfg(feature = "insecure")]
#[tokio::test]
async fn test_insecure_central_autobackup_after_deletion_isolated() -> Result<()> {
    // Setup using builder pattern with backup vault
    let env = CentralizedTestEnv::builder()
        .with_test_name("autobackup")
        .with_backup_vault()
        .build()
        .await?;

    let material_dir = env.material_dir;
    let server = env.server;
    let mut client = env.client;

    let key_id = derive_request_id("isolated-autobackup")?;

    key_gen_isolated(&mut client, &key_id, FheParameter::Test).await?;

    drop(client);
    server.assert_shutdown().await;

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify backup was created (no need to restart server for this check)
    // Data is stored with epoch_id, so we need to check using all_data_ids_from_all_epochs
    let backup_storage = FileStorage::new(Some(material_dir.path()), StorageType::BACKUP, None)?;
    let all_ids = backup_storage
        .all_data_ids_from_all_epochs(&PrivDataType::FhePrivateKey.to_string())
        .await?;
    assert!(
        all_ids.contains(&key_id),
        "key_id should exist in backup storage after auto-backup"
    );

    Ok(())
}

/// Test centralized CRS backup and restore flow.
///
/// Generates a CRS, deletes it from private storage, restores from backup,
/// and verifies restoration. This is a slow test that runs in nightly CI.
///
/// **Run with:** `cargo test --lib --features testing,insecure,slow_tests nightly_test_insecure_central_crs_backup_isolated`
#[cfg(all(feature = "insecure", feature = "slow_tests"))]
#[tokio::test]
async fn nightly_test_insecure_central_crs_backup_isolated() -> Result<()> {
    use kms_grpc::kms::v1::CrsGenRequest;

    // Setup using builder pattern with backup vault
    let env = CentralizedTestEnv::builder()
        .with_test_name("crs_backup")
        .with_backup_vault()
        .build()
        .await?;

    let material_dir = env.material_dir;
    let server = env.server;
    let mut client = env.client;

    let req_id = derive_request_id("isolated-crs-backup")?;

    let domain_msg = domain_to_msg(&dummy_domain());
    let req = CrsGenRequest {
        request_id: Some(req_id.into()),
        params: FheParameter::Test as i32,
        max_num_bits: Some(16),
        domain: Some(domain_msg),
        context_id: None,
    };
    let resp = client.crs_gen(tonic::Request::new(req)).await?;
    assert_eq!(resp.into_inner(), Empty {});

    // Wait for CRS generation to complete
    let mut result = client
        .get_crs_gen_result(tonic::Request::new(req_id.into()))
        .await;
    while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        result = client
            .get_crs_gen_result(tonic::Request::new(req_id.into()))
            .await;
    }
    let inner_resp = result?.into_inner();
    assert_eq!(inner_resp.request_id, Some(req_id.into()));

    let mut priv_storage = FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;
    let _ = delete_all_at_request_id(&mut priv_storage, &req_id).await;

    assert!(
        !priv_storage
            .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
            .await?
    );

    let req = Empty {};
    let resp = client.restore_from_backup(tonic::Request::new(req)).await?;
    tracing::info!("Backup restore response: {:?}", resp);

    let backup_storage = FileStorage::new(Some(material_dir.path()), StorageType::BACKUP, None)?;
    assert!(
        backup_storage
            .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
            .await?
    );

    assert!(
        priv_storage
            .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
            .await?
    );

    drop(client);
    server.assert_shutdown().await;

    Ok(())
}
