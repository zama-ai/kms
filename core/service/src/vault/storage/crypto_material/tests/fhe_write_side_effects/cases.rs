use super::super::*;
use super::support::run_fhe_write_rollback;
use crate::vault::storage::StorageType;

/// A complete key write rejects an existing pair half without changing storage or the cache.
#[rstest::rstest]
#[case::public_only(StorageType::PUB)]
#[case::private_only(StorageType::PRIV)]
#[tokio::test]
async fn fhe_write_rejects_an_existing_pair_half(#[case] existing_half: StorageType) {
    let key_id = derive_request_id("existing_fhe_pair_half").unwrap();
    let preproc_id = derive_request_id("existing_fhe_pair_half_preproc").unwrap();
    let epoch_id = *DEFAULT_EPOCH_ID;
    let (_, original_public, original_private) =
        generate_threshold_compressed_keys(&key_id, &preproc_id, 3183);
    // Another seed gives a different key pair.
    let (compressed_keyset, compact_public_key, attempted_private) =
        generate_threshold_compressed_keys(&key_id, &preproc_id, 3184);
    let storage =
        CryptoMaterialStorage::from(FailingRamStorage::new(), FailingRamStorage::new(), None);
    match existing_half {
        StorageType::PUB => {
            store_versioned_at_request_id(
                &mut *storage.public_storage.lock().await,
                &key_id,
                &original_public,
                &PubDataType::PublicKey.to_string(),
            )
            .await
            .unwrap();
        }
        StorageType::PRIV => {
            store_versioned_at_request_and_epoch_id(
                &mut *storage.private_storage.lock().await,
                &key_id,
                &epoch_id,
                &original_private,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await
            .unwrap();
        }
        _ => panic!("only public and private stores form an FHE pair"),
    }
    let public_before = {
        let mut public = storage.public_storage.lock().await;
        public.clear_events();
        public.state()
    };
    let private_before = {
        let mut private = storage.private_storage.lock().await;
        private.clear_events();
        private.state()
    };
    let control_id = derive_request_id("existing_fhe_pair_cache_control").unwrap();
    let cache = Arc::new(RwLock::new(HashMap::from([(
        (control_id, epoch_id),
        original_private,
    )])));

    let result = storage
        .handle_fhe_keys(
            &key_id,
            &epoch_id,
            attempted_private,
            PrivDataType::FheKeyInfo,
            PublicKeySet::Compressed {
                compact_public_key: Arc::new(compact_public_key),
                compressed_keyset: Arc::new(compressed_keyset),
            },
            Arc::clone(&cache),
            false,
            TEST_METRIC,
        )
        .await;

    assert_eq!(result, Err(StorageError::Duplicate));
    let public = storage.public_storage.lock().await;
    let private = storage.private_storage.lock().await;
    assert_eq!(public.state(), public_before);
    assert_eq!(private.state(), private_before);
    assert!(public.events().is_empty());
    assert!(private.events().is_empty());
    let cache = cache.read().await;
    assert_eq!(cache.len(), 1);
    assert!(cache.contains_key(&(control_id, epoch_id)));
}

/// A compressed write preserves an orphaned special key, including one from the uncompressed layout.
#[rstest::rstest]
#[case::same_layout(PubDataType::CompressedXofKeySet)]
#[case::other_layout(PubDataType::ServerKey)]
#[tokio::test]
async fn fhe_write_rejects_an_existing_special_key(#[case] existing_type: PubDataType) {
    let key_id = derive_request_id("existing_special_key").unwrap();
    let preproc_id = derive_request_id("existing_special_key_preproc").unwrap();
    let (compressed_keyset, compact_public_key, private_keys) =
        generate_threshold_compressed_keys(&key_id, &preproc_id, 3183);
    let storage =
        CryptoMaterialStorage::from(FailingRamStorage::new(), FailingRamStorage::new(), None);
    let public_before = {
        let mut public = storage.public_storage.lock().await;
        // Rejection depends on the path's presence, not the key's contents.
        store_versioned_at_request_id(
            &mut *public,
            &key_id,
            &TestType { i: 1 },
            &existing_type.to_string(),
        )
        .await
        .unwrap();
        public.clear_events();
        public.state()
    };
    let cache = Arc::new(RwLock::new(HashMap::new()));

    let result = storage
        .handle_fhe_keys(
            &key_id,
            &DEFAULT_EPOCH_ID,
            private_keys,
            PrivDataType::FheKeyInfo,
            PublicKeySet::Compressed {
                compact_public_key: Arc::new(compact_public_key),
                compressed_keyset: Arc::new(compressed_keyset),
            },
            Arc::clone(&cache),
            false,
            TEST_METRIC,
        )
        .await;

    assert_eq!(result, Err(StorageError::Duplicate));
    let public = storage.public_storage.lock().await;
    let private = storage.private_storage.lock().await;
    assert_eq!(public.state(), public_before);
    assert!(private.state().is_empty());
    assert!(public.events().is_empty());
    assert!(private.events().is_empty());
    assert!(cache.read().await.is_empty());
}

/// A failed compressed-key write removes its compressed keyset and partial pair.
#[tokio::test]
async fn compressed_fhe_write_cleans_new_entries_after_private_failure() {
    let key_id = derive_request_id("compressed_fhe_write_failure").unwrap();
    let epoch_id: EpochId = derive_request_id("compressed_fhe_write_failure_epoch")
        .unwrap()
        .into();
    let preproc_id = derive_request_id("compressed_fhe_write_failure_preproc").unwrap();
    let (compressed_keyset, compact_public_key, private_keys) =
        generate_threshold_compressed_keys(&key_id, &preproc_id, 3183);

    run_fhe_write_rollback(
        key_id,
        epoch_id,
        private_keys,
        PublicKeySet::Compressed {
            compact_public_key: Arc::new(compact_public_key),
            compressed_keyset: Arc::new(compressed_keyset),
        },
        PubDataType::CompressedXofKeySet,
    )
    .await;
}

/// A failed uncompressed-key write removes its server key and partial pair.
#[tokio::test]
async fn uncompressed_fhe_write_cleans_new_entries_after_private_failure() {
    let key_id = derive_request_id("uncompressed_fhe_write_failure").unwrap();
    let epoch_id: EpochId = derive_request_id("uncompressed_fhe_write_failure_epoch")
        .unwrap()
        .into();
    let (_, private_keys, public_keys) = setup_threshold_store(&key_id, RamStorage::new());

    run_fhe_write_rollback(
        key_id,
        epoch_id,
        private_keys,
        PublicKeySet::Uncompressed(Arc::new(public_keys)),
        PubDataType::ServerKey,
    )
    .await;
}
