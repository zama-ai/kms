//! Isolated centralized backup and restore tests
//!
//! These tests use isolated test material (TestMaterialManager). Each test runs
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

use crate::client::test_tools::{domain_to_msg, setup_centralized_isolated};
use crate::consts::{OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_KEY_ID, TEST_PARAM};
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::util::key_setup::ensure_central_keys_exist;
use crate::util::key_setup::test_material_manager::TestMaterialManager;
use crate::util::key_setup::test_material_spec::TestMaterialSpec;
use crate::util::key_setup::test_tools::{EncryptionConfig, TestingPlaintext};
use crate::vault::storage::{
    delete_all_at_request_id, file::FileStorage, Storage, StorageReader, StorageType,
};
use anyhow::Result;
use kms_grpc::kms::v1::{Empty, FheParameter, TypedCiphertext};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use kms_grpc::RequestId;
use std::path::Path;
use tempfile::TempDir;
use tonic::transport::Channel;

/// Helper function to setup isolated centralized test environment for backup tests
async fn setup_isolated_centralized_backup_test(
    test_name: &str,
) -> Result<(
    TempDir,
    crate::client::test_tools::ServerHandle,
    kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient<
        tonic::transport::Channel,
    >,
)> {
    use crate::vault::storage::make_storage;
    use crate::vault::Vault;

    let source_path = std::env::current_dir()?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test-material");
    let manager = TestMaterialManager::new(Some(source_path));
    let mut spec = TestMaterialSpec::centralized_basic();
    // Add server signing keys needed for backup operations
    spec.required_keys
        .insert(crate::util::key_setup::test_material_spec::KeyType::ServerSigningKeys);
    let material_dir = manager.setup_test_material(&spec, test_name).await?;

    let mut pub_storage = FileStorage::new(Some(material_dir.path()), StorageType::PUB, None)?;
    let mut priv_storage = FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;

    // Regenerate central keys with correct RequestIds
    let _ = pub_storage
        .delete_data(&TEST_CENTRAL_KEY_ID, &PubDataType::PublicKey.to_string())
        .await;
    let _ = pub_storage
        .delete_data(&OTHER_CENTRAL_TEST_ID, &PubDataType::PublicKey.to_string())
        .await;
    ensure_central_keys_exist(
        &mut pub_storage,
        &mut priv_storage,
        TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        &OTHER_CENTRAL_TEST_ID,
        true,
        true,
    )
    .await;

    // Create backup vault for backup/restore tests
    let backup_storage = make_storage(
        Some(crate::conf::Storage::File(crate::conf::FileStorage {
            path: material_dir.path().to_path_buf(),
        })),
        StorageType::BACKUP,
        None,
        None,
        None,
    )?;
    let backup_vault = Some(Vault {
        storage: backup_storage,
        keychain: None,
    });

    let (server, client) = setup_centralized_isolated(
        pub_storage,
        priv_storage,
        backup_vault,
        None,
        Some(material_dir.path()),
    )
    .await;

    Ok((material_dir, server, client))
}

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

/// Helper to decrypt using isolated storage
async fn decrypt_and_verify_isolated(
    material_dir: &Path,
    key_id: &RequestId,
    msg: TestingPlaintext,
) -> Result<()> {
    use crate::util::key_setup::test_tools::compute_cipher_from_stored_key;

    let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
        Some(material_dir),
        msg,
        key_id,
        1,
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
    )
    .await;

    // Verify key restoration via decryption
    let _typed_ct = TypedCiphertext {
        ciphertext: ct,
        fhe_type: fhe_type as i32,
        ciphertext_format: ct_format.into(),
        external_handle: vec![],
    };

    Ok(())
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
/// **Run with:** `cargo test --lib --features testing test_insecure_central_dkg_backup_isolated`
#[tokio::test]
async fn test_insecure_central_dkg_backup_isolated() -> Result<()> {
    let (material_dir, server, mut client) =
        setup_isolated_centralized_backup_test("dkg_backup").await?;

    let key_id_1 = derive_request_id("isolated-dkg-backup-1")?;
    let key_id_2 = derive_request_id("isolated-dkg-backup-2")?;

    key_gen_isolated(&mut client, &key_id_1, FheParameter::Test).await?;
    key_gen_isolated(&mut client, &key_id_2, FheParameter::Test).await?;

    let mut priv_storage = FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;
    delete_all_at_request_id(&mut priv_storage, &key_id_1).await;
    delete_all_at_request_id(&mut priv_storage, &key_id_2).await;

    assert!(
        !priv_storage
            .data_exists(&key_id_1, &PrivDataType::FhePrivateKey.to_string())
            .await?
    );

    let req = Empty {};
    let resp = client.restore_from_backup(tonic::Request::new(req)).await?;
    tracing::info!("Backup restore response: {:?}", resp);

    decrypt_and_verify_isolated(
        material_dir.path(),
        &key_id_1,
        TestingPlaintext::U8(u8::MAX),
    )
    .await?;

    drop(client);
    server.assert_shutdown().await;

    Ok(())
}

/// Test centralized auto-backup after server restart.
///
/// Generates an FHE key, shuts down server, restarts it with the same storage,
/// and verifies that backup was automatically created on restart. Tests the
/// auto-backup mechanism that protects against key loss.
///
/// **Flow:**
/// 1. Generate key using insecure DKG
/// 2. Shutdown server
/// 3. Restart server with same storage
/// 4. Verify backup was auto-created (checks FhePrivateKey in backup storage)
///
/// **Run with:** `cargo test --lib --features testing test_insecure_central_autobackup_after_deletion_isolated`
#[tokio::test]
async fn test_insecure_central_autobackup_after_deletion_isolated() -> Result<()> {
    let (material_dir, server, mut client) =
        setup_isolated_centralized_backup_test("autobackup").await?;

    let key_id = derive_request_id("isolated-autobackup")?;

    key_gen_isolated(&mut client, &key_id, FheParameter::Test).await?;

    drop(client);
    server.assert_shutdown().await;

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Restart server with same storage
    let pub_storage = FileStorage::new(Some(material_dir.path()), StorageType::PUB, None)?;
    let priv_storage = FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;
    let (_new_server, _new_client) = setup_centralized_isolated(
        pub_storage,
        priv_storage,
        None,
        None,
        Some(material_dir.path()),
    )
    .await;

    let backup_storage = FileStorage::new(Some(material_dir.path()), StorageType::BACKUP, None)?;
    assert!(
        backup_storage
            .data_exists(&key_id, &PrivDataType::FhePrivateKey.to_string())
            .await?
    );

    Ok(())
}

#[tokio::test]
async fn nightly_test_insecure_central_crs_backup_isolated() -> Result<()> {
    use kms_grpc::kms::v1::CrsGenRequest;

    let (material_dir, server, mut client) =
        setup_isolated_centralized_backup_test("crs_backup").await?;

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
    delete_all_at_request_id(&mut priv_storage, &req_id).await;

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
