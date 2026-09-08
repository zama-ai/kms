//! This module will be deprecated and replaced
//! by ./core/service/src/testing/utils.rs

use crate::backup::BackupCiphertext;
pub use crate::client::local_crypto::{
    EncryptionConfig, TestingPlaintext, compute_cipher, compute_cipher_from_stored_key,
    load_material_from_pub_storage, load_pk_from_pub_storage,
};
use crate::conf::{self, Keychain};
use crate::util::file_handling::safe_read_element_versioned;
use crate::vault::keychain::make_keychain_proxy;
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{
    StorageReaderExt, StorageType, delete_all_at_request_id, delete_at_request_and_epoch_id,
    make_storage,
};
use crate::vault::{Vault, VaultDataType};
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::{EpochId, RequestId};
use std::path::Path;

/// Purge any kind of public or private data, regardless of type, for a specific request ID.
///
/// This function should be used for testing only and it can panic.
pub async fn purge(
    pub_path: Option<&Path>,
    priv_path: Option<&Path>,
    id: &RequestId,
    public_storage_prefixes: &[Option<String>],
    priv_storage_prefixes: &[Option<String>],
) {
    for storage_prefix in public_storage_prefixes.iter() {
        let mut threshold_pub =
            FileStorage::new(pub_path, StorageType::PUB, storage_prefix.as_deref()).unwrap();
        delete_all_at_request_id(&mut threshold_pub, id)
            .await
            .unwrap();
    }
    for storage_prefix in priv_storage_prefixes.iter() {
        let mut threshold_priv =
            FileStorage::new(priv_path, StorageType::PRIV, storage_prefix.as_deref()).unwrap();
        delete_all_at_request_id(&mut threshold_priv, id)
            .await
            .unwrap();

        // Also delete epoch-specific data types that delete_all_at_request_id skips
        use PrivDataType::*;
        for data_type in [FhePrivateKey, FheKeyInfo, CrsInfo] {
            let data_type_str = data_type.to_string();
            if let Ok(epoch_ids) = threshold_priv.all_epoch_ids_for_data(&data_type_str).await {
                for epoch_id in epoch_ids {
                    let _ = delete_at_request_and_epoch_id(
                        &mut threshold_priv,
                        id,
                        &epoch_id,
                        &data_type_str,
                    )
                    .await;
                }
            }
        }
    }
}

/// Purge the entire content of the private storage.
/// This is useful for testing backup
pub async fn purge_priv(priv_path: Option<&Path>, storage_prefixes: &[Option<String>]) {
    // Purge for the max amount of parties we may have in tests
    for storage_prefix in storage_prefixes.iter() {
        let storage =
            FileStorage::new(priv_path, StorageType::PRIV, storage_prefix.as_deref()).unwrap();
        // Ignore if the dir does not exist
        let _ = tokio::fs::remove_dir_all(&storage.root_dir()).await;
    }
}

/// Purge the entire content of the public storage.
/// This is useful for testing backup
pub async fn purge_pub(pub_path: Option<&Path>, storage_prefixes: &[Option<String>]) {
    // Purge for the max amount of parties we may have in tests
    for storage_prefix in storage_prefixes.iter() {
        let storage =
            FileStorage::new(pub_path, StorageType::PUB, storage_prefix.as_deref()).unwrap();
        // Ignore if the dir does not exist
        let _ = tokio::fs::remove_dir_all(&storage.root_dir()).await;
    }
}

/// Purge _all_ backed up data. Both custodian and non-custodian based backups.
/// Note however that this method does _not_ purge anything in the private or public storage.
pub async fn purge_backup(backup_path: Option<&Path>, storage_prefixes: &[Option<String>]) {
    for storage_prefix in storage_prefixes.iter() {
        let storage =
            FileStorage::new(backup_path, StorageType::BACKUP, storage_prefix.as_deref()).unwrap();
        // Ignore if the dir does not exist
        let _ = tokio::fs::remove_dir_all(&storage.root_dir()).await;
    }
}

/// Validate that a backup exists
pub async fn backup_exists(
    backup_path: Option<&Path>,
    storage_prefixes: &[Option<String>],
) -> bool {
    let mut backup_exists = true;
    for storage_prefix in storage_prefixes.iter() {
        let storage =
            FileStorage::new(backup_path, StorageType::BACKUP, storage_prefix.as_deref()).unwrap();
        let base_path = storage.root_dir();
        let mut files = tokio::fs::read_dir(base_path).await.unwrap();
        if files.next_entry().await.unwrap().is_none() {
            backup_exists = false;
        }
    }
    backup_exists
}

/// Helper method to construct a backup vault for testing. That is either without encryption (no `Keychain`) or using custodians.
pub async fn file_backup_vault(
    keychain_conf: Option<&Keychain>,
    pub_path: Option<&Path>,
    backup_path: Option<&Path>,
    pub_storage_prefix: Option<&str>,
    backup_storage_prefix: Option<&str>,
) -> Vault {
    let create_storage_conf =
        |path: Option<&Path>, storage_prefix: Option<&str>| match (path, storage_prefix) {
            (None, None) => None,
            (None, Some(prefix)) => Some(conf::Storage::File(conf::FileStorage {
                path: std::env::current_dir()
                    .unwrap()
                    .join(crate::consts::KEY_PATH_PREFIX),
                prefix: Some(prefix.to_string()),
            })),
            (Some(path), None) => Some(conf::Storage::File(conf::FileStorage {
                path: path.to_path_buf(),
                prefix: None,
            })),
            (Some(path), Some(prefix)) => Some(conf::Storage::File(conf::FileStorage {
                path: path.to_path_buf(),
                prefix: Some(prefix.to_string()),
            })),
        };
    let backup_storage_conf = create_storage_conf(backup_path, backup_storage_prefix);
    let pub_storage_conf = create_storage_conf(pub_path, pub_storage_prefix);

    let pub_proxy_storage = make_storage(pub_storage_conf, StorageType::PUB, None).unwrap();
    let backup_proxy_storage =
        make_storage(backup_storage_conf, StorageType::BACKUP, None).unwrap();
    let keychain = match keychain_conf {
        Some(conf) => Some(
            make_keychain_proxy(conf, None, None, Some(&pub_proxy_storage), false)
                .await
                .unwrap(),
        ),
        None => None,
    };
    Vault {
        storage: backup_proxy_storage,
        keychain,
    }
}

/// Helper method for tests to read the plain custodian backup files without going through the Vault API, and hence decryption.
pub async fn read_custodian_backup_files(
    test_path: Option<&Path>,
    backup_id: &RequestId,
    file_req: &RequestId,
    data_type: &str,
    storage_prefixes: &[Option<String>],
) -> Vec<BackupCiphertext> {
    read_custodian_backup_files_impl(
        test_path,
        backup_id,
        file_req,
        None,
        data_type,
        storage_prefixes,
    )
    .await
}

pub async fn read_custodian_backup_files_with_epoch(
    test_path: Option<&Path>,
    backup_id: &RequestId,
    file_req: &RequestId,
    epoch_id: EpochId,
    data_type: &str,
    storage_prefixes: &[Option<String>],
) -> Vec<BackupCiphertext> {
    read_custodian_backup_files_impl(
        test_path,
        backup_id,
        file_req,
        Some(epoch_id),
        data_type,
        storage_prefixes,
    )
    .await
}

async fn read_custodian_backup_files_impl(
    test_path: Option<&Path>,
    backup_id: &RequestId,
    file_req: &RequestId,
    epoch_id: Option<EpochId>,
    data_type: &str,
    storage_prefixes: &[Option<String>],
) -> Vec<BackupCiphertext> {
    let mut files = Vec::new();
    for storage_prefix in storage_prefixes.iter() {
        let storage =
            FileStorage::new(test_path, StorageType::BACKUP, storage_prefix.as_deref()).unwrap();
        let mut coerced_path = storage.root_dir().join(
            VaultDataType::CustodianBackupData(*backup_id, data_type.try_into().unwrap())
                .to_string(),
        );
        if let Some(epoch_id) = epoch_id {
            coerced_path = coerced_path.join(epoch_id.to_string());
        }
        coerced_path = coerced_path.join(file_req.to_string());
        // Attempt to read the file
        if let Ok(file) = safe_read_element_versioned(coerced_path).await {
            files.push(file);
        }
    }
    files
}
