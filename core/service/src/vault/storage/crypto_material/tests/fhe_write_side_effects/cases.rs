use super::super::*;
use super::support::assert_fhe_write_rollback;

/// A failed centralized compressed-key pair removes its compressed keyset and partial pair.
#[tokio::test]
async fn compressed_fhe_write_cleans_new_entries_after_private_failure() {
    let key_id = derive_request_id("compressed_fhe_write_failure").unwrap();
    let epoch_id: EpochId = derive_request_id("compressed_fhe_write_failure_epoch")
        .unwrap()
        .into();
    let preproc_id = derive_request_id("compressed_fhe_write_failure_preproc").unwrap();
    let (_, _, compressed_keyset, compact_public_key, private_keys) =
        generate_compressed_keys(&key_id, &preproc_id, 3183);

    assert_fhe_write_rollback(
        key_id,
        epoch_id,
        private_keys,
        PrivDataType::FhePrivateKey,
        PublicKeySet::Compressed {
            compact_public_key: Arc::new(compact_public_key),
            compressed_keyset: Arc::new(compressed_keyset),
        },
        PubDataType::CompressedXofKeySet,
    )
    .await;
}

/// A failed threshold uncompressed-key pair removes its server key and partial pair.
#[tokio::test]
async fn uncompressed_fhe_write_cleans_new_entries_after_private_failure() {
    let key_id = derive_request_id("uncompressed_fhe_write_failure").unwrap();
    let epoch_id: EpochId = derive_request_id("uncompressed_fhe_write_failure_epoch")
        .unwrap()
        .into();
    let (_, private_keys, public_keys) = setup_threshold_store(&key_id, RamStorage::new());

    assert_fhe_write_rollback(
        key_id,
        epoch_id,
        private_keys,
        PrivDataType::FheKeyInfo,
        PublicKeySet::Uncompressed(Arc::new(public_keys)),
        PubDataType::ServerKey,
    )
    .await;
}
