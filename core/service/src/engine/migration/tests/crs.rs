//! Tests the v0.15 migration of legacy private CRS metadata.

use super::super::migrate_to_0_15_x;
use crate::{
    consts::DEFAULT_EPOCH_ID,
    engine::base::{CrsGenMetadata, derive_request_id},
    vault::storage::{
        StorageExt, StorageType, file::FileStorage, ram::RamStorage,
        read_all_data_from_all_epochs_versioned, store_versioned_at_request_id,
    },
};
use kms_grpc::{
    RequestId,
    identifiers::EpochId,
    rpc_types::{KMSType, PrivDataType},
};
use std::collections::HashMap;

async fn assert_startup_migrates_legacy_crs_metadata<S>(mut private_storage: S)
where
    S: StorageExt + Sync + Send,
{
    let mut public_storage = RamStorage::new();
    let crs_id = derive_request_id("legacy_crs_metadata").unwrap();
    let data_type = PrivDataType::CrsInfo.to_string();
    let metadata = CrsGenMetadata::new(
        crs_id,
        vec![7; 32],
        128,
        &crate::dummy_domain(),
        vec![9; 8],
        vec![],
        b"legacy CRS metadata".to_vec(),
    );
    store_versioned_at_request_id(&mut private_storage, &crs_id, &metadata, &data_type)
        .await
        .unwrap();

    // The CRS migration is independent of the KMS mode. Centralized mode avoids unrelated PRSS setup.
    migrate_to_0_15_x(
        &mut public_storage,
        &mut private_storage,
        KMSType::Centralized,
        None,
    )
    .await
    .unwrap();

    assert!(
        !private_storage
            .data_exists(&crs_id, &data_type)
            .await
            .unwrap()
    );
    let stored: HashMap<(RequestId, EpochId), CrsGenMetadata> =
        read_all_data_from_all_epochs_versioned(&private_storage, &data_type)
            .await
            .unwrap();
    assert_eq!(stored, [((crs_id, *DEFAULT_EPOCH_ID), metadata)].into());

    // A second run sees no legacy entry and leaves the migrated value untouched.
    migrate_to_0_15_x(
        &mut public_storage,
        &mut private_storage,
        KMSType::Centralized,
        None,
    )
    .await
    .unwrap();
    let stored_after_second_run: HashMap<(RequestId, EpochId), CrsGenMetadata> =
        read_all_data_from_all_epochs_versioned(&private_storage, &data_type)
            .await
            .unwrap();
    assert_eq!(stored_after_second_run, stored);
}

/// A v0.15 startup moves readable CRS metadata on disk and removes its legacy file.
#[tokio::test]
async fn startup_migrates_legacy_crs_metadata_on_disk() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
    assert_startup_migrates_legacy_crs_metadata(storage).await;
}

/// The S3-backed startup migration removes the legacy object after it copies the metadata.
#[cfg(all(feature = "non-wasm", feature = "testing"))]
#[tokio::test]
async fn startup_migrates_legacy_crs_metadata_in_s3() {
    let storage = crate::vault::storage::s3::create_s3_storage(
        StorageType::PRIV,
        std::stringify!(startup_migrates_legacy_crs_metadata_in_s3),
    )
    .await;
    assert_startup_migrates_legacy_crs_metadata(storage).await;
}
