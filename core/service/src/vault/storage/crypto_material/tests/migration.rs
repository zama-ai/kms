use super::*;
use crate::{
    engine::base::{
        DSEP_PUBDATA_KEY, compute_info_compressed_keygen, compute_info_standard_keygen,
    },
    vault::{
        Vault,
        storage::{
            read_versioned_at_request_and_epoch_id, store_versioned_at_request_and_epoch_id,
        },
    },
};

/// Helper to build ThresholdFheKeys for a compressed keyset with proper metadata.
/// Takes the `compact_pk` explicitly so tests can reproduce the production invariant that
/// the old CompactPublicKey bytes are preserved at the new key ID during migration.
fn threshold_fhe_keys_for_compressed_keyset(
    req_id: &RequestId,
    prep_id: &RequestId,
    private_keys: Arc<threshold_execution::tfhe_internals::private_keysets::PrivateKeySet<4>>,
    compact_pk: &tfhe::CompactPublicKey,
    sk: &PrivateSigKey,
    domain: &alloy_sol_types::Eip712Domain,
    compressed_keyset: &CompressedXofKeySet,
) -> ThresholdFheKeys {
    let info = compute_info_compressed_keygen(
        sk,
        &DSEP_PUBDATA_KEY,
        prep_id,
        req_id,
        compressed_keyset,
        compact_pk,
        domain,
        vec![],
    )
    .unwrap();

    ThresholdFheKeys::new(
        private_keys,
        PublicKeyMaterial::new(compressed_keyset.clone()),
        info,
    )
}

async fn store_migrated_compressed_material(
    crypto_storage: &ThresholdCryptoMaterialStorage<RamStorage, RamStorage>,
    new_key_id: &RequestId,
    new_epoch_id: &EpochId,
    compressed_keyset: &CompressedXofKeySet,
    compact_pk: &CompactPublicKey,
    new_fhe_keys: &ThresholdFheKeys,
) {
    {
        let mut pub_storage = crypto_storage.inner.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            new_key_id,
            compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            &mut *pub_storage,
            new_key_id,
            compact_pk,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
    }
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            new_key_id,
            new_epoch_id,
            new_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }
}

fn assert_current_compressed_metadata(meta_data: &KeyGenMetadata, key_id: &RequestId) {
    match meta_data {
        KeyGenMetadata::Current(inner) => {
            assert_eq!(inner.key_id, *key_id);
            assert!(
                inner
                    .key_digest_map
                    .contains_key(&PubDataType::CompressedXofKeySet),
                "metadata should contain CompressedXofKeySet digest"
            );
            assert!(
                inner.key_digest_map.contains_key(&PubDataType::PublicKey),
                "metadata should contain PublicKey digest"
            );
            assert!(
                !inner.key_digest_map.contains_key(&PubDataType::ServerKey),
                "new metadata should not contain ServerKey digest"
            );
        }
        _ => panic!("expected Current metadata"),
    }
}

async fn assert_migrated_public_material(
    crypto_storage: &ThresholdCryptoMaterialStorage<RamStorage, RamStorage>,
    old_key_id: &RequestId,
    new_key_id: &RequestId,
    expected_server_key_bytes: &[u8],
) {
    let pub_storage = crypto_storage.inner.public_storage.lock().await;
    assert!(
        pub_storage
            .data_exists(old_key_id, &PubDataType::CompressedXofKeySet.to_string())
            .await
            .unwrap(),
        "CompressedXofKeySet should exist at old_key_id"
    );
    assert!(
        pub_storage
            .data_exists(old_key_id, &PubDataType::ServerKey.to_string())
            .await
            .unwrap(),
        "ServerKey should be preserved at old_key_id after migration"
    );
    assert!(
        pub_storage
            .data_exists(old_key_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap(),
        "PublicKey should be preserved at old_key_id after migration"
    );
    assert!(
        pub_storage
            .data_exists(new_key_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap(),
        "PublicKey should also exist at new_key_id after migration"
    );
    let old_pk_bytes = pub_storage
        .load_bytes(old_key_id, &PubDataType::PublicKey.to_string())
        .await
        .unwrap();
    let new_pk_bytes = pub_storage
        .load_bytes(new_key_id, &PubDataType::PublicKey.to_string())
        .await
        .unwrap();
    assert_eq!(
        old_pk_bytes, new_pk_bytes,
        "compact PK bytes at old_key_id and new_key_id must be identical"
    );
    let old_server_key_bytes = pub_storage
        .load_bytes(old_key_id, &PubDataType::ServerKey.to_string())
        .await
        .unwrap();
    assert_eq!(
        old_server_key_bytes, expected_server_key_bytes,
        "ServerKey bytes at old_key_id must be preserved by migration"
    );
}

async fn load_public_material_bytes(
    crypto_storage: &ThresholdCryptoMaterialStorage<RamStorage, RamStorage>,
    key_id: &RequestId,
    data_type: PubDataType,
) -> Vec<u8> {
    let pub_storage = crypto_storage.inner.public_storage.lock().await;
    pub_storage
        .load_bytes(key_id, &data_type.to_string())
        .await
        .unwrap()
}

/// Seed an `old_key_id` with a pre-migration uncompressed keyset whose
/// `key_digest_map` covers PublicKey and ServerKey, plus the matching
/// pub-data files. Returns the pre-migration ThresholdFheKeys and the
/// CompactPublicKey stored at `old_key_id` so callers can feed the same
/// bytes into the migrated keyset (mirroring the production invariant
/// that the old compact PK is preserved at `new_key_id`).
async fn setup_pre_migration_uncompressed(
    crypto_storage: &ThresholdCryptoMaterialStorage<RamStorage, RamStorage>,
    old_key_id: &RequestId,
    epoch_id: &EpochId,
    sk: &PrivateSigKey,
    prep_id: &RequestId,
    domain: &alloy_sol_types::Eip712Domain,
) -> (ThresholdFheKeys, tfhe::CompactPublicKey) {
    let (_, fhe_keys_skeleton, fhe_key_set) = setup_threshold_store(old_key_id);
    let compact_pk = fhe_key_set.public_key.clone();

    // Compute real metadata that matches what we'll actually store in pub storage.
    let info = compute_info_standard_keygen(
        sk,
        &DSEP_PUBDATA_KEY,
        prep_id,
        old_key_id,
        &fhe_key_set,
        domain,
        vec![],
    )
    .unwrap();

    let old_fhe_keys = ThresholdFheKeys::new(
        fhe_keys_skeleton.private_keys.clone(),
        fhe_keys_skeleton.public_material.clone(),
        info,
    );

    // Private storage: ThresholdFheKeys at (old_key_id, epoch_id).
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            old_key_id,
            epoch_id,
            &old_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }
    // Public storage: PublicKey + ServerKey at old_key_id.
    {
        let mut pub_storage = crypto_storage.inner.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            old_key_id,
            &fhe_key_set.public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            &mut *pub_storage,
            old_key_id,
            &fhe_key_set.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();
    }

    (old_fhe_keys, compact_pk)
}

#[tokio::test]
async fn test_copy_compressed_key_to_original_success() {
    let old_key_id = derive_request_id("copy_compressed_old_key").unwrap();
    let new_key_id = derive_request_id("copy_compressed_new_key").unwrap();
    let prep_id = derive_request_id("copy_compressed_prep").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_compressed_epoch").unwrap().into();

    let (sk, domain, compressed_keyset, _generated_pk, _) =
        generate_compressed_keys(&new_key_id, &prep_id, 200);
    let crypto_storage = ram_threshold_storage(None);

    let (old_fhe_keys, compact_pk) = setup_pre_migration_uncompressed(
        &crypto_storage,
        &old_key_id,
        &epoch_id,
        &sk,
        &prep_id,
        &domain,
    )
    .await;
    let old_server_key_bytes =
        load_public_material_bytes(&crypto_storage, &old_key_id, PubDataType::ServerKey).await;

    let new_fhe_keys = threshold_fhe_keys_for_compressed_keyset(
        &new_key_id,
        &prep_id,
        old_fhe_keys.private_keys.clone(),
        &compact_pk,
        &sk,
        &domain,
        &compressed_keyset,
    );
    store_migrated_compressed_material(
        &crypto_storage,
        &new_key_id,
        &epoch_id,
        &compressed_keyset,
        &compact_pk,
        &new_fhe_keys,
    )
    .await;

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    let result = crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store.clone(),
        )
        .await;
    assert!(result.is_ok(), "copy should succeed: {result:?}");

    // ServerKey left over from the original uncompressed keyset is retained for
    // legacy/direct-storage consumers. PublicKey is in both the old and new
    // digest maps (the migrate keygen preserves the old compact PK at
    // new_key_id), so it must stay too; its bytes must match the ones at
    // new_key_id so external clients see the same compact PK at either ID.
    assert_migrated_public_material(
        &crypto_storage,
        &old_key_id,
        &new_key_id,
        &old_server_key_bytes,
    )
    .await;

    // ThresholdFheKeys at (old_key_id, epoch_id) has Compressed public_material
    // and metadata signed under old_key_id.
    {
        let guarded = crypto_storage
            .read_guarded_threshold_fhe_keys(&old_key_id, &epoch_id)
            .await
            .unwrap();
        assert!(
            guarded.is_compressed(),
            "ThresholdFheKeys should have Compressed public_material"
        );
        assert_current_compressed_metadata(&guarded.meta_data, &old_key_id);
    }

    // dkg_pubinfo_meta_store now holds the new metadata for old_key_id.
    {
        let guard = meta_store.read().await;
        let cell = guard
            .get_cell(&old_key_id)
            .expect("meta_store entry should exist");
        let value = cell.try_get().expect("meta_store entry should be set");
        let meta = value.expect("meta_store should hold Ok(metadata)");
        assert_current_compressed_metadata(&meta, &old_key_id);
    }
}

#[tokio::test]
async fn test_copy_compressed_key_overwrite() {
    let old_key_id = derive_request_id("copy_overwrite_old").unwrap();
    let new_key_id_1 = derive_request_id("copy_overwrite_new_1").unwrap();
    let new_key_id_2 = derive_request_id("copy_overwrite_new_2").unwrap();
    let prep_id = derive_request_id("copy_overwrite_prep").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_overwrite_epoch").unwrap().into();

    let (sk, domain, compressed_1, _generated_pk_1, _) =
        generate_compressed_keys(&new_key_id_1, &prep_id, 300);
    let crypto_storage = ram_threshold_storage(None);
    let (old_fhe_keys, compact_pk) = setup_pre_migration_uncompressed(
        &crypto_storage,
        &old_key_id,
        &epoch_id,
        &sk,
        &prep_id,
        &domain,
    )
    .await;
    let old_server_key_bytes =
        load_public_material_bytes(&crypto_storage, &old_key_id, PubDataType::ServerKey).await;

    let fhe_keys_1 = threshold_fhe_keys_for_compressed_keyset(
        &new_key_id_1,
        &prep_id,
        old_fhe_keys.private_keys.clone(),
        &compact_pk,
        &sk,
        &domain,
        &compressed_1,
    );
    store_migrated_compressed_material(
        &crypto_storage,
        &new_key_id_1,
        &epoch_id,
        &compressed_1,
        &compact_pk,
        &fhe_keys_1,
    )
    .await;

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id_1,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store.clone(),
        )
        .await
        .unwrap();
    assert_migrated_public_material(
        &crypto_storage,
        &old_key_id,
        &new_key_id_1,
        &old_server_key_bytes,
    )
    .await;

    let (_, _, compressed_2, _generated_pk_2, _) =
        generate_compressed_keys(&new_key_id_2, &prep_id, 300);
    let fhe_keys_2 = threshold_fhe_keys_for_compressed_keyset(
        &new_key_id_2,
        &prep_id,
        old_fhe_keys.private_keys.clone(),
        &compact_pk,
        &sk,
        &domain,
        &compressed_2,
    );
    store_migrated_compressed_material(
        &crypto_storage,
        &new_key_id_2,
        &epoch_id,
        &compressed_2,
        &compact_pk,
        &fhe_keys_2,
    )
    .await;

    let result = crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id_2,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store.clone(),
        )
        .await;
    assert!(result.is_ok(), "second copy should succeed: {result:?}");
    assert_migrated_public_material(
        &crypto_storage,
        &old_key_id,
        &new_key_id_2,
        &old_server_key_bytes,
    )
    .await;

    {
        let guarded = crypto_storage
            .read_guarded_threshold_fhe_keys(&old_key_id, &epoch_id)
            .await
            .unwrap();
        assert!(guarded.is_compressed());
        assert_current_compressed_metadata(&guarded.meta_data, &old_key_id);
    }
}

#[tokio::test]
async fn test_copy_compressed_key_missing_source() {
    let old_key_id = derive_request_id("copy_missing_old").unwrap();
    let new_key_id = derive_request_id("copy_missing_new").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_missing_epoch").unwrap().into();

    let (sk, domain, _, _, _) = generate_compressed_keys(&new_key_id, &new_key_id, 400);
    let crypto_storage = ram_threshold_storage(None);

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // No CompressedXofKeySet at new_key_id — should fail.
    let result = crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store,
        )
        .await;
    assert!(result.is_err(), "should fail when source key is missing");
}

#[tokio::test]
async fn test_copy_compressed_key_legacy_metadata_fails() {
    let old_key_id = derive_request_id("copy_legacy_old").unwrap();
    let new_key_id = derive_request_id("copy_legacy_new").unwrap();
    let prep_id = derive_request_id("copy_legacy_prep").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_legacy_epoch").unwrap().into();

    let (sk, domain, compressed_keyset, _generated_pk, _) =
        generate_compressed_keys(&new_key_id, &prep_id, 500);
    let crypto_storage = ram_threshold_storage(None);

    // We need a pre-existing old_fhe_keys at (old_key_id, epoch_id) so Phase A
    // can read it before hitting the LegacyV0 rejection on the migrated metadata.
    let (old_fhe_keys, compact_pk) = setup_pre_migration_uncompressed(
        &crypto_storage,
        &old_key_id,
        &epoch_id,
        &sk,
        &prep_id,
        &domain,
    )
    .await;

    let legacy_fhe_keys = ThresholdFheKeys::new(
        old_fhe_keys.private_keys.clone(),
        PublicKeyMaterial::new(compressed_keyset.clone()),
        KeyGenMetadata::LegacyV0(HashMap::new()),
    );

    store_migrated_compressed_material(
        &crypto_storage,
        &new_key_id,
        &epoch_id,
        &compressed_keyset,
        &compact_pk,
        &legacy_fhe_keys,
    )
    .await;

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    let result = crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store,
        )
        .await;
    assert!(result.is_err(), "should fail with LegacyV0 metadata");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("LegacyV0"),
        "error should mention LegacyV0, got: {err}"
    );
}

/// If Phase A validation fails (missing CompressedXofKeySet digest in the
/// migrated metadata), Phase B must not mutate pub/priv storage at old_key_id.
#[tokio::test]
async fn test_copy_compressed_key_validation_failure_is_atomic() {
    let old_key_id = derive_request_id("copy_atomic_old").unwrap();
    let new_key_id = derive_request_id("copy_atomic_new").unwrap();
    let prep_id = derive_request_id("copy_atomic_prep").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_atomic_epoch").unwrap().into();

    let (sk, domain, compressed_keyset, _generated_pk, _) =
        generate_compressed_keys(&new_key_id, &prep_id, 700);
    let crypto_storage = ram_threshold_storage(None);

    let (old_fhe_keys, compact_pk) = setup_pre_migration_uncompressed(
        &crypto_storage,
        &old_key_id,
        &epoch_id,
        &sk,
        &prep_id,
        &domain,
    )
    .await;
    let original_old_meta = old_fhe_keys.meta_data.clone();

    // Generate a valid compressed keyset at new_key_id, but store ThresholdFheKeys
    // with Current metadata whose key_digest_map is empty (no CompressedXofKeySet).
    // Current variant with empty digest map — triggers "missing CompressedXofKeySet digest".
    let bad_fhe_keys = ThresholdFheKeys::new(
        old_fhe_keys.private_keys.clone(),
        PublicKeyMaterial::new(compressed_keyset.clone()),
        KeyGenMetadata::new(new_key_id, prep_id, HashMap::new(), vec![]),
    );
    store_migrated_compressed_material(
        &crypto_storage,
        &new_key_id,
        &epoch_id,
        &compressed_keyset,
        &compact_pk,
        &bad_fhe_keys,
    )
    .await;

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let result = crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store.clone(),
        )
        .await;
    assert!(
        result.is_err(),
        "copy should fail when migrated metadata is missing the CompressedXofKeySet digest"
    );

    // Pub storage at old_key_id must still hold the original ServerKey/PublicKey
    // and must NOT have received the new CompressedXofKeySet.
    {
        let pub_storage = crypto_storage.inner.public_storage.lock().await;
        assert!(
            pub_storage
                .data_exists(&old_key_id, &PubDataType::ServerKey.to_string())
                .await
                .unwrap(),
            "pre-migration ServerKey must survive a validation failure"
        );
        assert!(
            pub_storage
                .data_exists(&old_key_id, &PubDataType::PublicKey.to_string())
                .await
                .unwrap(),
            "pre-migration PublicKey must survive a validation failure"
        );
        assert!(
            !pub_storage
                .data_exists(&old_key_id, &PubDataType::CompressedXofKeySet.to_string())
                .await
                .unwrap(),
            "CompressedXofKeySet must not be written to old_key_id on validation failure"
        );
    }

    // Priv storage at (old_key_id, epoch_id) must still hold the original
    // ThresholdFheKeys (uncompressed) — unchanged.
    {
        let guarded = crypto_storage
            .read_guarded_threshold_fhe_keys(&old_key_id, &epoch_id)
            .await
            .unwrap();
        assert!(
            !guarded.is_compressed(),
            "original uncompressed ThresholdFheKeys must survive a validation failure"
        );
        // Compare by metadata signature (cheap proxy for "unchanged").
        assert_eq!(
            guarded.meta_data.external_signature(),
            original_old_meta.external_signature(),
        );
    }

    // meta_store must be untouched on validation failure (no entry for old_key_id).
    {
        let guard = meta_store.read().await;
        assert!(
            guard.get_cell(&old_key_id).is_none(),
            "meta_store must not be mutated on validation failure"
        );
    }
}

/// Confirm that the backup vault, when configured, is updated alongside the
/// primary pub/priv storage so a restore brings back the migrated material.
#[tokio::test]
async fn test_copy_compressed_key_updates_backup_vault() {
    let old_key_id = derive_request_id("copy_backup_old").unwrap();
    let new_key_id = derive_request_id("copy_backup_new").unwrap();
    let prep_id = derive_request_id("copy_backup_prep").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_backup_epoch").unwrap().into();

    let (sk, domain, compressed_keyset, _generated_pk, _) =
        generate_compressed_keys(&new_key_id, &prep_id, 800);

    // Construct a Vault backed by RamStorage (no keychain — unencrypted backup).
    let backup_vault = Vault {
        storage: crate::vault::storage::StorageProxy::Ram(RamStorage::new()),
        keychain: None,
    };

    let crypto_storage = ram_threshold_storage(Some(backup_vault));

    let (old_fhe_keys, compact_pk) = setup_pre_migration_uncompressed(
        &crypto_storage,
        &old_key_id,
        &epoch_id,
        &sk,
        &prep_id,
        &domain,
    )
    .await;

    let new_fhe_keys = threshold_fhe_keys_for_compressed_keyset(
        &new_key_id,
        &prep_id,
        old_fhe_keys.private_keys.clone(),
        &compact_pk,
        &sk,
        &domain,
        &compressed_keyset,
    );
    store_migrated_compressed_material(
        &crypto_storage,
        &new_key_id,
        &epoch_id,
        &compressed_keyset,
        &compact_pk,
        &new_fhe_keys,
    )
    .await;

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store,
        )
        .await
        .expect("copy should succeed with backup vault configured");

    // Backup vault must now hold the migrated ThresholdFheKeys at
    // (old_key_id, epoch_id).
    let backup_vault = crypto_storage
        .inner
        .backup_vault
        .as_ref()
        .expect("backup vault should be configured");
    let vault_guard = backup_vault.lock().await;
    let backed_up: ThresholdFheKeys = read_versioned_at_request_and_epoch_id(
        &*vault_guard,
        &old_key_id,
        &epoch_id,
        &PrivDataType::FheKeyInfo.to_string(),
    )
    .await
    .expect("migrated ThresholdFheKeys should exist in backup vault");
    assert!(
        backed_up.is_compressed(),
        "backup vault must hold the migrated (compressed) keys, not the pre-migration uncompressed ones"
    );
    assert_current_compressed_metadata(&backed_up.meta_data, &old_key_id);
}
