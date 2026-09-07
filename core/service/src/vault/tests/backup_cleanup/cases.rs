use super::super::{Vault, VaultDataType, make_secret_share_keychain};
use super::support::*;
use crate::{
    cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType},
    engine::base::derive_request_id,
    vault::{
        keychain::{KeychainProxy, secretsharing::SecretShareKeychain},
        storage::{
            Storage, StorageExt, StorageProxy, StorageReader, StorageReaderExt, StorageType,
            file::FileStorage,
            ram::{FailingRamStorage, RamStorage},
            test_support::{
                BackupEntry, FaultPhase, StorageEvent, StorageOp, StorageOutcome,
                failing_ram_storage_mut,
            },
        },
    },
};
use aes_prng::AesRng;
use kms_grpc::{EpochId, rpc_types::PrivDataType};
use rand::SeedableRng;

/// `purge_backup` on a custodian vault deletes only the requested backup namespace.
///
/// Unlike `remove_old_backup`, it may delete the current namespace because it is also the cleanup
/// path for a failed backup setup.
#[tokio::test]
async fn test_purge_backup_custodian_vault_scoped_to_backup_id() {
    let current_id = derive_request_id("purge_backup_current").unwrap();
    let old_id = derive_request_id("purge_backup_old").unwrap();
    let mut vault = Vault {
        storage: StorageProxy::from(RamStorage::new()),
        keychain: Some(make_secret_share_keychain(current_id).await),
    };

    let data_id = derive_request_id("purge_backup_data").unwrap();
    let data_type = PrivDataType::SigningKey;
    // Entry under the current backup id, written through the vault.
    vault
        .store_bytes(b"current", &data_id, &data_type.to_string())
        .await
        .unwrap();
    // Epoched entry under the current backup id.
    let mut rng = AesRng::seed_from_u64(44);
    let epoch_id = EpochId::new_random(&mut rng);
    vault
        .store_bytes_at_epoch(
            b"current_epoched",
            &data_id,
            &epoch_id,
            &data_type.to_string(),
        )
        .await
        .unwrap();
    // Entry under an old backup id, written directly at its per-context path.
    let old_path = VaultDataType::CustodianBackupData(old_id, data_type).to_string();
    vault
        .storage
        .store_bytes(b"old", &data_id, &old_path)
        .await
        .unwrap();

    // Purging the old backup must not touch the current one.
    vault.purge_backup(&old_id).await.unwrap();
    assert!(
        !vault
            .storage
            .data_exists(&data_id, &old_path)
            .await
            .unwrap()
    );
    let current_path = VaultDataType::CustodianBackupData(current_id, data_type).to_string();
    assert!(
        vault
            .storage
            .data_exists(&data_id, &current_path)
            .await
            .unwrap()
    );

    // `remove_old_backup` refuses the current backup id, but `purge_backup` handles it.
    assert!(vault.remove_old_backup(&current_id).await.is_err());
    vault.purge_backup(&current_id).await.unwrap();
    assert!(
        !vault
            .storage
            .data_exists(&data_id, &current_path)
            .await
            .unwrap()
    );
    assert!(
        !vault
            .storage
            .data_exists_at_epoch(&data_id, &epoch_id, &current_path)
            .await
            .unwrap()
    );

    // Purging an id with no data is not an error.
    vault.purge_backup(&current_id).await.unwrap();
}

/// On a vault without a custodian keychain, `purge_backup` deletes data stored directly under the
/// requested id and leaves other ids intact.
#[tokio::test]
async fn test_purge_backup_unencrypted_vault() {
    let backup_id = derive_request_id("purge_backup_unencrypted").unwrap();
    let other_id = derive_request_id("purge_backup_unencrypted_other").unwrap();
    let mut vault = Vault {
        storage: StorageProxy::from(RamStorage::new()),
        keychain: None,
    };
    let data_type = PrivDataType::SigningKey.to_string();
    vault
        .store_bytes(b"mine", &backup_id, &data_type)
        .await
        .unwrap();
    vault
        .store_bytes(b"other", &other_id, &data_type)
        .await
        .unwrap();

    vault.purge_backup(&backup_id).await.unwrap();
    assert!(
        !vault
            .storage
            .data_exists(&backup_id, &data_type)
            .await
            .unwrap()
    );
    assert!(
        vault
            .storage
            .data_exists(&other_id, &data_type)
            .await
            .unwrap()
    );
}

/// Shared success scenario for the file, RAM, and S3 storage implementations.
async fn remove_old_backup_scenario(storage: StorageProxy) {
    let mut fixture = BackupRemovalFixture::new(storage).await;
    assert!(
        fixture
            .vault
            .remove_old_backup(&fixture.current_id)
            .await
            .is_err()
    );

    fixture
        .vault
        .remove_old_backup(&fixture.retired_id)
        .await
        .unwrap();

    fixture
        .assert_entries_absent(&fixture.retired_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.current_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.control_entries)
        .await;
}

#[tokio::test]
async fn remove_old_backup_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(Some(temp_dir.path()), StorageType::BACKUP, None).unwrap();
    remove_old_backup_scenario(StorageProxy::from(storage)).await;
}

#[tokio::test]
async fn remove_old_backup_ram() {
    remove_old_backup_scenario(StorageProxy::from(RamStorage::new())).await;
}

/// A partial erasure returns an error, preserves other contexts, and permits a retry.
#[rstest::rstest]
#[case(FaultPhase::BeforeMutation)]
#[case(FaultPhase::AfterMutation)]
#[tokio::test]
async fn remove_old_backup_failure_is_retryable(#[case] fault_phase: FaultPhase) {
    let mut fixture = BackupRemovalFixture::new(StorageProxy::from(FailingRamStorage::new())).await;
    let failed_entry = fixture.retired_entries[1];
    let storage = failing_ram_storage_mut(&mut fixture.vault);
    match fault_phase {
        FaultPhase::BeforeMutation => storage.set_fail_delete_at(failed_entry.storage_entry()),
        FaultPhase::AfterMutation => {
            storage.set_fail_delete_after_mutation_at(failed_entry.storage_entry())
        }
    }
    storage.clear_events();

    assert!(
        fixture
            .vault
            .remove_old_backup(&fixture.retired_id)
            .await
            .is_err()
    );
    fixture
        .assert_entries_present(&fixture.current_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.control_entries)
        .await;
    match fault_phase {
        FaultPhase::BeforeMutation => fixture.assert_entries_present(&[failed_entry]).await,
        FaultPhase::AfterMutation => fixture.assert_entries_absent(&[failed_entry]).await,
    }

    let storage = failing_ram_storage_mut(&mut fixture.vault);
    let faults = storage.faults();
    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].entry, failed_entry.storage_entry());
    let expected_outcome = match fault_phase {
        FaultPhase::BeforeMutation => StorageOutcome::FailedBeforeMutation,
        FaultPhase::AfterMutation => StorageOutcome::FailedAfterMutation,
    };
    assert_eq!(faults[0].outcome, expected_outcome);
    let retired_entries = fixture.retired_entries.map(BackupEntry::storage_entry);
    assert!(
        storage
            .events()
            .iter()
            .all(|event| retired_entries.contains(&event.entry))
    );
    storage.clear_fail_points();

    fixture
        .vault
        .remove_old_backup(&fixture.retired_id)
        .await
        .unwrap();
    fixture
        .assert_entries_absent(&fixture.retired_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.current_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.control_entries)
        .await;
}

/// A backend acknowledgement is insufficient when the retired backup entry remains stored.
#[tokio::test]
async fn remove_old_backup_rejects_a_delete_that_did_not_happen() {
    let mut fixture = BackupRemovalFixture::new(StorageProxy::from(FailingRamStorage::new())).await;
    let ignored_entry = fixture.retired_entries[0];
    let storage = failing_ram_storage_mut(&mut fixture.vault);
    storage.set_noop_delete_at(ignored_entry.storage_entry());
    storage.clear_events();

    let error = fixture
        .vault
        .remove_old_backup(&fixture.retired_id)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("residual data remains"));
    fixture.assert_entries_present(&[ignored_entry]).await;
    fixture
        .assert_entries_present(&fixture.current_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.control_entries)
        .await;
    let storage = failing_ram_storage_mut(&mut fixture.vault);
    assert!(storage.events().contains(&StorageEvent::new(
        ignored_entry.storage_entry(),
        StorageOp::Delete,
        StorageOutcome::SucceededWithoutMutation,
    )));
    storage.clear_fail_points();

    fixture
        .vault
        .remove_old_backup(&fixture.retired_id)
        .await
        .unwrap();
    fixture
        .assert_entries_absent(&fixture.retired_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.current_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.control_entries)
        .await;
}

/// Custodian setup rollback also rejects a successful response that leaves backup data behind.
#[tokio::test]
async fn purge_backup_rejects_a_delete_that_did_not_happen() {
    let mut fixture = BackupRemovalFixture::new(StorageProxy::from(FailingRamStorage::new())).await;
    let ignored_entry = fixture.current_entries[1];
    let storage = failing_ram_storage_mut(&mut fixture.vault);
    storage.set_noop_delete_at(ignored_entry.storage_entry());
    storage.clear_events();

    let error = fixture
        .vault
        .purge_backup(&fixture.current_id)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("residual data remains"));
    fixture.assert_entries_present(&[ignored_entry]).await;
    fixture
        .assert_entries_present(&fixture.retired_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.control_entries)
        .await;
    let storage = failing_ram_storage_mut(&mut fixture.vault);
    assert!(storage.events().contains(&StorageEvent::new(
        ignored_entry.storage_entry(),
        StorageOp::Delete,
        StorageOutcome::SucceededWithoutMutation,
    )));
    storage.clear_fail_points();

    fixture
        .vault
        .purge_backup(&fixture.current_id)
        .await
        .unwrap();
    fixture
        .assert_entries_absent(&fixture.current_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.retired_entries)
        .await;
    fixture
        .assert_entries_present(&fixture.control_entries)
        .await;
}

// Runs against the in-process S3 mock, so it needs the features that gate the mock constructor.
#[cfg(all(feature = "non-wasm", feature = "testing"))]
#[tokio::test]
async fn remove_old_backup_s3() {
    let storage = crate::vault::storage::s3::create_s3_storage(
        StorageType::BACKUP,
        std::stringify!(remove_old_backup_s3),
    )
    .await;
    remove_old_backup_scenario(StorageProxy::from(storage)).await;
}

#[tokio::test]
async fn remove_old_backup_requires_custodian_vault() {
    let mut vault = Vault {
        storage: StorageProxy::from(RamStorage::new()),
        keychain: None,
    };
    let backup_id = derive_request_id("some_backup").unwrap();
    assert!(vault.remove_old_backup(&backup_id).await.is_err());
}

/// Regression test for the epoch-namespace gap in custodian context destruction.
/// Details can be found in https://github.com/zama-ai/kms-internal/issues/3110.
#[tokio::test]
async fn remove_old_backup_deletes_epoch_scoped_data() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backup_storage =
        FileStorage::new(Some(temp_dir.path()), StorageType::BACKUP, None).unwrap();

    let mut rng = AesRng::seed_from_u64(42);
    let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
    let (_dec_key, enc_key) = enc.keygen().unwrap();
    let keychain = SecretShareKeychain::<AesRng>::new::<FileStorage>(rng, None)
        .await
        .unwrap();
    let mut vault = Vault {
        storage: StorageProxy::from(backup_storage),
        keychain: Some(KeychainProxy::SecretSharing(keychain)),
    };
    let old_backup_id = derive_request_id("old_custodian_context").unwrap();
    let current_backup_id = derive_request_id("current_custodian_context").unwrap();
    let data_type = PrivDataType::FheKeyInfo;
    let epoch_id = EpochId::from_bytes([7; 32]);

    set_current_backup_id(&mut vault, old_backup_id, enc_key.clone());
    let epoch_id_item = derive_request_id("epoch_backup_item").unwrap();
    vault
        .store_bytes_at_epoch(
            b"epoch_secret",
            &epoch_id_item,
            &epoch_id,
            &data_type.to_string(),
        )
        .await
        .unwrap();
    let non_epoch_item = derive_request_id("non_epoch_backup_item").unwrap();
    vault
        .store_bytes(b"non_epoch_secret", &non_epoch_item, &data_type.to_string())
        .await
        .unwrap();

    let old_data_type = VaultDataType::CustodianBackupData(old_backup_id, data_type).to_string();
    assert!(
        vault
            .storage
            .data_exists(&non_epoch_item, &old_data_type)
            .await
            .unwrap()
    );
    assert!(
        vault
            .storage
            .data_exists_at_epoch(&epoch_id_item, &epoch_id, &old_data_type)
            .await
            .unwrap()
    );

    set_current_backup_id(&mut vault, current_backup_id, enc_key);
    vault.remove_old_backup(&old_backup_id).await.unwrap();

    assert!(
        vault
            .storage
            .all_data_ids(&old_data_type)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        vault
            .storage
            .all_data_ids_from_all_epochs(&old_data_type)
            .await
            .unwrap()
            .is_empty()
    );
}
