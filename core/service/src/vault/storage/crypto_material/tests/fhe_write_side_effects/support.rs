//! Fixture logic for multi-step FHE key write failures.

use super::super::*;
use crate::vault::storage::{
    ram::FailingRamStorage,
    test_support::{StorageEntry, StorageEvent, StorageOp, StorageOutcome, assert_same_events},
};
use serde::Serialize;
use tfhe::named::Named;
use tfhe_versionable::Versionize;

/// Fails the private storage write after mutation and verifies that the FHE key write is rolled back.
///
/// Panics on failure.
pub(super) async fn assert_fhe_write_rollback<PrivData>(
    key_id: RequestId,
    epoch_id: EpochId,
    private_data: PrivData,
    private_type: PrivDataType,
    public_keys: PublicKeySet,
    // The public artifact written before the pair: `ServerKey` for threshold keys or
    // `CompressedXofKeySet` for centralized keys.
    special_public_type: PubDataType,
) where
    PrivData: Serialize + Versionize + Named + Send + Sync,
    for<'a> <PrivData as Versionize>::Versioned<'a>: Send + Sync,
{
    let storage =
        CryptoMaterialStorage::from(FailingRamStorage::new(), FailingRamStorage::new(), None);
    let control_id = derive_request_id("fhe_write_failure_control").unwrap();
    let control = TestType { i: 99 };
    {
        let mut public = storage.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *public,
            &control_id,
            &control,
            &PubDataType::CACert.to_string(),
        )
        .await
        .unwrap();
        public.clear_events();
    }
    {
        let mut private = storage.private_storage.lock().await;
        store_versioned_at_request_id(
            &mut *private,
            &control_id,
            &control,
            &PrivDataType::ContextInfo.to_string(),
        )
        .await
        .unwrap();
        private.clear_events();
    }

    let public_before = storage.public_storage.lock().await.state();
    let private_before = storage.private_storage.lock().await.state();
    let special_entry = StorageEntry::new(key_id, None, special_public_type.to_string());
    let public_key_entry = StorageEntry::new(key_id, None, PubDataType::PublicKey.to_string());
    let private_entry = StorageEntry::new(key_id, Some(epoch_id), private_type.to_string());
    storage
        .private_storage
        .lock()
        .await
        .set_fail_store_after_mutation_at(private_entry.clone());
    let cache = Arc::new(RwLock::new(HashMap::new()));

    let result = storage
        .handle_fhe_keys(
            &key_id,
            &epoch_id,
            private_data,
            private_type,
            public_keys,
            cache.clone(),
            false,
            TEST_METRIC,
        )
        .await;

    assert_eq!(result, Err(StorageError::Writing));
    assert_eq!(storage.public_storage.lock().await.state(), public_before);
    assert_eq!(storage.private_storage.lock().await.state(), private_before);
    assert!(cache.read().await.is_empty());
    assert_same_events(
        storage.public_storage.lock().await.events(),
        &[
            StorageEvent::new(
                special_entry.clone(),
                StorageOp::Store,
                StorageOutcome::Created,
            ),
            StorageEvent::new(
                public_key_entry.clone(),
                StorageOp::Store,
                StorageOutcome::Created,
            ),
            StorageEvent::new(public_key_entry, StorageOp::Delete, StorageOutcome::Deleted),
            StorageEvent::new(special_entry, StorageOp::Delete, StorageOutcome::Deleted),
        ],
    );
    assert_same_events(
        storage.private_storage.lock().await.events(),
        &[
            StorageEvent::new(
                private_entry.clone(),
                StorageOp::Store,
                StorageOutcome::FailedAfterMutation,
            ),
            StorageEvent::new(private_entry, StorageOp::Delete, StorageOutcome::Deleted),
        ],
    );
}
