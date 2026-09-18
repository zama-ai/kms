//! A new key or CRS must not be combined with material left by an earlier write.

use super::*;
use rstest::rstest;

/// Reject existing public artifacts or private keys without changing storage or the cache.
#[rstest]
#[case::public_key(Some(PubDataType::PublicKey))]
#[case::server_key(Some(PubDataType::ServerKey))]
#[case::compressed_keyset(Some(PubDataType::CompressedXofKeySet))]
#[case::private_key(None)]
#[tokio::test]
async fn fhe_write_rejects_existing_material(#[case] public_type: Option<PubDataType>) {
    let key_id = derive_request_id("fhe_write_guard").unwrap();
    let preproc_id = derive_request_id("fhe_write_guard_preproc").unwrap();
    let epoch_id = *DEFAULT_EPOCH_ID;
    let (_, _, compressed_keyset, compact_public_key, private_keys) =
        generate_compressed_keys(&key_id, &preproc_id, 42);
    let mut public = RamStorage::new();
    let mut private = RamStorage::new();
    // Only existence is checked; the seeded value need not be an actual key.
    if let Some(data_type) = public_type {
        store_versioned_at_request_id(
            &mut public,
            &key_id,
            &TestType { i: 1 },
            &data_type.to_string(),
        )
        .await
        .unwrap();
    } else {
        store_versioned_at_request_and_epoch_id(
            &mut private,
            &key_id,
            &epoch_id,
            &TestType { i: 1 },
            &PrivDataType::FhePrivateKey.to_string(),
        )
        .await
        .unwrap();
    }
    let public_before = public.clone();
    let private_before = private.clone();
    let storage = CryptoMaterialStorage::from(public, private, None);
    let cache = Arc::new(RwLock::new(HashMap::new()));

    let result = storage
        .handle_fhe_keys(
            &key_id,
            &epoch_id,
            private_keys,
            PrivDataType::FhePrivateKey,
            PublicKeySet::Compressed {
                compact_public_key: Arc::new(compact_public_key),
                compressed_keyset: Arc::new(compressed_keyset),
            },
            Arc::clone(&cache),
            false,
            TEST_METRIC,
        )
        .await;

    assert!(matches!(result, Err(StorageError::Duplicate)), "{result:?}");
    assert_eq!(*storage.public_storage.lock().await, public_before);
    assert_eq!(*storage.private_storage.lock().await, private_before);
    assert!(cache.read().await.is_empty());
}

/// Reject either existing CRS half and record the error instead of leaving the request pending.
#[rstest]
#[case::public_crs(true)]
#[case::private_metadata(false)]
#[tokio::test]
async fn crs_write_rejects_existing_material(#[case] public_exists: bool) {
    let mut rng = AesRng::seed_from_u64(100);
    let crs_id = RequestId::new_random(&mut rng);
    let epoch_id = *DEFAULT_EPOCH_ID;
    let (_, signing_key) = gen_sig_keys(&mut rng);
    let (crs, metadata) = async_generate_crs(
        &signing_key,
        TEST_PARAM,
        Some(1),
        dummy_domain(),
        vec![],
        &crs_id,
        rng,
    )
    .await
    .unwrap();
    let mut public = RamStorage::new();
    let mut private = RamStorage::new();
    if public_exists {
        store_versioned_at_request_id(
            &mut public,
            &crs_id,
            &TestType { i: 1 },
            &PubDataType::CRS.to_string(),
        )
        .await
        .unwrap();
    } else {
        store_versioned_at_request_and_epoch_id(
            &mut private,
            &crs_id,
            &epoch_id,
            &TestType { i: 1 },
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        .unwrap();
    }
    let public_before = public.clone();
    let private_before = private.clone();
    let storage = CryptoMaterialStorage::from(public, private, None);
    let meta_store = MetaStore::new_unlimited();
    let permit = meta_store.write().await.insert(&crs_id).unwrap();

    let result = storage
        .write_crs(
            &crs_id,
            &epoch_id,
            crs,
            metadata,
            Arc::clone(&meta_store),
            permit,
            TEST_METRIC,
        )
        .await;

    assert!(matches!(result, Err(StorageError::Duplicate)), "{result:?}");
    assert_eq!(*storage.public_storage.lock().await, public_before);
    assert_eq!(*storage.private_storage.lock().await, private_before);
    assert!(matches!(
        meta_store.read().await.retrieve(&crs_id),
        Some(EntryState::Done(Err(error))) if error == StorageError::Duplicate.to_string()
    ));
}
