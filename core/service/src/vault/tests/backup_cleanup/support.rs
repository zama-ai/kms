//! Fixture support for retired custodian backup removal tests.

use super::super::{Vault, make_secret_share_keychain};
use crate::{
    cryptography::encryption::UnifiedPublicEncKey,
    engine::base::derive_request_id,
    vault::{
        keychain::KeychainProxy,
        storage::{
            Storage, StorageExt, StorageProxy, StorageReader, StorageReaderExt,
            test_support::BackupEntry,
        },
    },
};
use kms_grpc::{EpochId, RequestId, rpc_types::PrivDataType};

/// Holds one retired backup and two control namespaces.
pub(super) struct BackupRemovalFixture {
    pub(super) vault: Vault,
    pub(super) retired_id: RequestId,
    pub(super) current_id: RequestId,
    pub(super) retired_entries: [BackupEntry; 2],
    pub(super) current_entries: [BackupEntry; 2],
    pub(super) control_entries: [BackupEntry; 2],
}

impl BackupRemovalFixture {
    pub(super) async fn new(storage: StorageProxy) -> Self {
        let retired_id = derive_request_id("old_custodian_context").unwrap();
        let current_id = derive_request_id("current_custodian_context").unwrap();
        let control_id = derive_request_id("unrelated_custodian_context").unwrap();
        let data_id = derive_request_id("test_backup_data").unwrap();
        let epoch_id = EpochId::from_bytes([43; 32]);
        let entries = |backup_id| {
            [
                BackupEntry::new(backup_id, data_id, None, PrivDataType::SigningKey),
                BackupEntry::new(backup_id, data_id, Some(epoch_id), PrivDataType::FheKeyInfo),
            ]
        };
        let retired_entries = entries(retired_id);
        let current_entries = entries(current_id);
        let control_entries = entries(control_id);
        let mut vault = Vault {
            storage,
            keychain: Some(make_secret_share_keychain(retired_id).await),
        };
        let enc_key = match vault.keychain.as_ref() {
            Some(KeychainProxy::SecretSharing(keychain)) => keychain.get_backup_enc_key().unwrap(),
            _ => panic!("expected a secret-sharing keychain"),
        };

        store_backup_entries(&mut vault, &retired_entries).await;
        set_current_backup_id(&mut vault, current_id, enc_key.clone());
        store_backup_entries(&mut vault, &current_entries).await;
        set_current_backup_id(&mut vault, control_id, enc_key.clone());
        store_backup_entries(&mut vault, &control_entries).await;
        set_current_backup_id(&mut vault, current_id, enc_key);

        Self {
            vault,
            retired_id,
            current_id,
            retired_entries,
            current_entries,
            control_entries,
        }
    }

    /// Panics if an entry is absent.
    pub(super) async fn assert_entries_present(&self, entries: &[BackupEntry]) {
        self.assert_entry_presence(entries, true).await;
    }

    /// Panics if an entry is present.
    pub(super) async fn assert_entries_absent(&self, entries: &[BackupEntry]) {
        self.assert_entry_presence(entries, false).await;
    }

    async fn assert_entry_presence(&self, entries: &[BackupEntry], expected: bool) {
        for entry in entries {
            let storage_entry = entry.storage_entry();
            let exists = match entry.epoch_id {
                Some(epoch_id) => self
                    .vault
                    .storage
                    .data_exists_at_epoch(&entry.data_id, &epoch_id, &storage_entry.data_type)
                    .await
                    .unwrap(),
                None => self
                    .vault
                    .storage
                    .data_exists(&entry.data_id, &storage_entry.data_type)
                    .await
                    .unwrap(),
            };
            assert_eq!(exists, expected, "unexpected entry state: {entry:?}");
        }
    }
}

async fn store_backup_entries(vault: &mut Vault, entries: &[BackupEntry]) {
    for entry in entries {
        match entry.epoch_id {
            Some(epoch_id) => vault
                .store_bytes_at_epoch(
                    b"backup data",
                    &entry.data_id,
                    &epoch_id,
                    &entry.data_type.to_string(),
                )
                .await
                .unwrap(),
            None => vault
                .store_bytes(b"backup data", &entry.data_id, &entry.data_type.to_string())
                .await
                .unwrap(),
        };
    }
}

/// Points the vault's keychain at `backup_id`.
pub(super) fn set_current_backup_id(
    vault: &mut Vault,
    backup_id: RequestId,
    enc_key: UnifiedPublicEncKey,
) {
    match vault.keychain.as_mut() {
        Some(KeychainProxy::SecretSharing(keychain)) => {
            keychain.set_backup_enc_key(backup_id, enc_key)
        }
        _ => panic!("expected a secret-sharing keychain"),
    }
}
