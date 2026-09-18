//! Complete CRS writes must not combine existing material with a newly generated pair.

use super::*;
use crate::vault::storage::StorageType;

/// Either existing half rejects the write without changing storage, and marks the request failed.
#[rstest::rstest]
#[case::public_only(StorageType::PUB)]
#[case::private_only(StorageType::PRIV)]
#[tokio::test]
async fn crs_write_rejects_an_existing_pair_half(#[case] existing_half: StorageType) {
    let crs_id = derive_request_id("existing_crs_pair_half").unwrap();
    let epoch_id = *DEFAULT_EPOCH_ID;
    let mut rng = AesRng::seed_from_u64(100);
    let (_, signing_key) = gen_sig_keys(&mut rng);
    let (crs, crs_info) = async_generate_crs(
        &NodeSigningIdentity::ecdsa_only(signing_key),
        &[SigningSchemeType::Ecdsa256k1],
        TEST_PARAM,
        Some(1),
        dummy_domain(),
        vec![],
        &crs_id,
        rng,
    )
    .await
    .unwrap();
    let storage =
        CryptoMaterialStorage::from(FailingRamStorage::new(), FailingRamStorage::new(), None);
    // The existing bytes need not decode: rejection depends only on the entry's presence.
    match existing_half {
        StorageType::PUB => store_versioned_at_request_id(
            &mut *storage.public_storage.lock().await,
            &crs_id,
            &TestType { i: 1 },
            &PubDataType::CRS.to_string(),
        )
        .await
        .unwrap(),
        StorageType::PRIV => store_versioned_at_request_and_epoch_id(
            &mut *storage.private_storage.lock().await,
            &crs_id,
            &epoch_id,
            &TestType { i: 1 },
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        .unwrap(),
        _ => panic!("only public and private stores form a CRS pair"),
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
    let meta_store = MetaStore::new_unlimited();
    let permit = meta_store.write().await.insert(&crs_id).unwrap();

    let result = storage
        .write_crs(
            &crs_id,
            &epoch_id,
            crs,
            crs_info,
            Arc::clone(&meta_store),
            permit,
            OP_CRS_GEN_REQUEST,
        )
        .await;

    assert_eq!(result, Err(StorageError::Duplicate));
    let public = storage.public_storage.lock().await;
    let private = storage.private_storage.lock().await;
    assert_eq!(public.state(), public_before);
    assert_eq!(private.state(), private_before);
    assert!(public.events().is_empty());
    assert!(private.events().is_empty());
    match meta_store.read().await.retrieve(&crs_id).unwrap() {
        EntryState::Done(Err(error)) => assert_eq!(error, StorageError::Duplicate.to_string()),
        state => panic!("expected a failed CRS request, got {state:?}"),
    }
}
