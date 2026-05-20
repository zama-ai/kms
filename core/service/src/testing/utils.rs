pub use crate::client::local_crypto::{
    EncryptionConfig, TestingPlaintext, compute_cipher, compute_cipher_from_stored_key,
    load_material_from_pub_storage, load_pk_from_pub_storage,
};
use crate::conf::{self, Keychain};
use crate::vault::Vault;
use crate::vault::keychain::make_keychain_proxy;
#[cfg(test)]
use crate::vault::storage::StorageReader;
#[cfg(test)]
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{StorageType, make_storage};
#[cfg(test)]
use kms_grpc::rpc_types::PubDataType;
use std::path::Path;

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

#[cfg(any(test, feature = "testing"))]
pub mod setup {
    use crate::consts::DEFAULT_EPOCH_ID;
    use crate::consts::{
        PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL,
    };
    use crate::engine::base::derive_request_id;
    use crate::testing::material::{MaterialType, threshold_crs_id_name, threshold_key_id_name};
    use crate::util::key_setup::{
        ThresholdSigningKeyConfig, ensure_central_crs_exists, ensure_central_keys_exist,
        ensure_client_keys_exist,
    };
    use crate::{
        consts::{
            DEFAULT_CENTRAL_CRS_ID, DEFAULT_CENTRAL_KEY_ID, DEFAULT_PARAM, KEY_PATH_PREFIX,
            OTHER_CENTRAL_DEFAULT_ID, OTHER_CENTRAL_TEST_ID, SIGNING_KEY_ID, TEST_CENTRAL_CRS_ID,
            TEST_CENTRAL_KEY_ID, TEST_PARAM, TMP_PATH_PREFIX,
        },
        util::key_setup::ensure_central_server_signing_keys_exist,
    };
    use crate::{
        util::key_setup::{
            ensure_threshold_crs_exists, ensure_threshold_keys_exist,
            ensure_threshold_server_signing_keys_exist,
        },
        vault::storage::{StorageType, file::FileStorage},
    };
    use anyhow::{Context, Result, bail};
    use kms_grpc::RequestId;
    use kms_grpc::identifiers::EpochId;
    use std::collections::BTreeSet;
    use std::path::Path;
    use threshold_execution::tfhe_internals::parameters::DKGParams;

    pub async fn ensure_dir_exist(path: Option<&Path>) {
        match path {
            Some(p) => {
                tokio::fs::create_dir_all(p.join(TMP_PATH_PREFIX))
                    .await
                    .unwrap();
                tokio::fs::create_dir_all(p.join(KEY_PATH_PREFIX))
                    .await
                    .unwrap();
            }
            None => {
                tokio::fs::create_dir_all(TMP_PATH_PREFIX).await.unwrap();
                tokio::fs::create_dir_all(KEY_PATH_PREFIX).await.unwrap();
            }
        }
    }

    pub async fn generate_material_to_path(
        material_type: MaterialType,
        path: Option<&Path>,
        party_counts: &[usize],
    ) -> Result<()> {
        let epoch_id = *DEFAULT_EPOCH_ID;
        ensure_dir_exist(path).await;
        ensure_client_keys_exist(path, &SIGNING_KEY_ID, true).await;
        match material_type {
            MaterialType::Testing => {
                central_material(
                    &TEST_PARAM,
                    &TEST_CENTRAL_KEY_ID,
                    &OTHER_CENTRAL_TEST_ID,
                    &TEST_CENTRAL_CRS_ID,
                    &epoch_id,
                    path,
                )
                .await;
            }
            MaterialType::Default => {
                central_material(
                    &DEFAULT_PARAM,
                    &DEFAULT_CENTRAL_KEY_ID,
                    &OTHER_CENTRAL_DEFAULT_ID,
                    &DEFAULT_CENTRAL_CRS_ID,
                    &epoch_id,
                    path,
                )
                .await;
            }
        }

        let max_supported_parties = PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL.len();
        if party_counts.contains(&0) {
            bail!(
                "Unsupported party count 0. Centralized material is generated implicitly, so threshold party counts must start at 2."
            );
        }

        let unique_party_counts = party_counts.iter().copied().collect::<BTreeSet<_>>();

        for party_count in unique_party_counts {
            if !(2..=max_supported_parties).contains(&party_count) {
                bail!(
                    "Unsupported party count {party_count}. Threshold party counts must be between 2 and {max_supported_parties}; centralized material is generated implicitly."
                );
            }

            let key_id = derive_request_id(&threshold_key_id_name(material_type, party_count))
                .with_context(|| {
                    format!("Failed to derive threshold key ID for {party_count} parties")
                })?;
            let crs_id = derive_request_id(&threshold_crs_id_name(material_type, party_count))
                .with_context(|| {
                    format!("Failed to derive threshold CRS ID for {party_count} parties")
                })?;
            let params = match material_type {
                MaterialType::Testing => &TEST_PARAM,
                MaterialType::Default => &DEFAULT_PARAM,
            };

            threshold_material(
                params,
                &key_id,
                &crs_id,
                &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..party_count],
                &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..party_count],
                &epoch_id,
                path,
            )
            .await;
        }

        Ok(())
    }

    async fn central_material(
        params: &DKGParams,
        fhe_key_id: &RequestId,
        other_fhe_key_id: &RequestId,
        crs_id: &RequestId,
        epoch_id: &EpochId,
        path: Option<&Path>,
    ) {
        let mut central_pub_storage = FileStorage::new(path, StorageType::PUB, None).unwrap();
        let mut central_priv_storage = FileStorage::new(path, StorageType::PRIV, None).unwrap();

        ensure_central_server_signing_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            &SIGNING_KEY_ID,
            true,
        )
        .await;
        ensure_central_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            params.to_owned(),
            fhe_key_id,
            other_fhe_key_id,
            epoch_id,
            true,
        )
        .await;
        ensure_central_crs_exists(
            &mut central_pub_storage,
            &mut central_priv_storage,
            params.to_owned(),
            crs_id,
            epoch_id,
            true,
        )
        .await;
    }

    async fn threshold_material(
        params: &DKGParams,
        fhe_key_id: &RequestId,
        crs_id: &RequestId,
        public_storage_prefixes: &[Option<String>],
        private_storage_prefixes: &[Option<String>],
        epoch_id: &EpochId,
        path: Option<&Path>,
    ) {
        assert_eq!(
            public_storage_prefixes.len(),
            private_storage_prefixes.len()
        );
        let amount_parties = public_storage_prefixes.len();
        let mut threshold_pub_storages = Vec::with_capacity(amount_parties);
        for storage_prefix in public_storage_prefixes.iter() {
            threshold_pub_storages
                .push(FileStorage::new(path, StorageType::PUB, storage_prefix.as_deref()).unwrap());
        }
        let mut threshold_priv_storages = Vec::with_capacity(amount_parties);
        for storage_prefix in private_storage_prefixes.iter() {
            threshold_priv_storages.push(
                FileStorage::new(path, StorageType::PRIV, storage_prefix.as_deref()).unwrap(),
            );
        }

        let _ = ensure_threshold_server_signing_keys_exist(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            &SIGNING_KEY_ID,
            true,
            ThresholdSigningKeyConfig::AllParties(
                (1..=amount_parties).map(|i| format!("party-{i}")).collect(),
            ),
            false,
        )
        .await;
        ensure_threshold_keys_exist(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            params.to_owned(),
            fhe_key_id,
            epoch_id,
            true,
        )
        .await;
        ensure_threshold_crs_exists(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            params.to_owned(),
            crs_id,
            epoch_id,
            true,
        )
        .await;
    }
}

// NOTE: this test stays out of the setup module
// because we don't want it to have the "testing" feature
#[tokio::test]
async fn test_purge() {
    use crate::consts::SIGNING_KEY_ID;
    use kms_grpc::rpc_types::PrivDataType;

    let temp_dir = tempfile::tempdir().unwrap();
    let test_prefix = Some(temp_dir.path());
    let mut central_pub_storage = FileStorage::new(test_prefix, StorageType::PUB, None).unwrap();
    let mut central_priv_storage = FileStorage::new(test_prefix, StorageType::PRIV, None).unwrap();

    // Check no keys exist
    assert!(
        central_pub_storage
            .all_data_ids(&PubDataType::VerfKey.to_string())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        central_priv_storage
            .all_data_ids(&PrivDataType::SigningKey.to_string())
            .await
            .unwrap()
            .is_empty()
    );
    // Create keys to be deleted
    assert!(
        crate::util::key_setup::ensure_central_server_signing_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            &SIGNING_KEY_ID,
            true,
        )
        .await
    );
    // Validate the keys were made
    let pub_ids = central_pub_storage
        .all_data_ids(&PubDataType::VerfKey.to_string())
        .await
        .unwrap();
    assert_eq!(pub_ids.len(), 1);
    let priv_ids = central_priv_storage
        .all_data_ids(&PrivDataType::SigningKey.to_string())
        .await
        .unwrap();
    assert_eq!(priv_ids.len(), 1);
    crate::util::key_setup::test_tools::purge(
        test_prefix,
        test_prefix,
        &pub_ids.into_iter().next().unwrap(),
        &[None],
        &[None],
    )
    .await;
    // Check the keys were deleted
    assert!(
        central_pub_storage
            .all_data_ids(&PubDataType::VerfKey.to_string())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        central_priv_storage
            .all_data_ids(&PrivDataType::SigningKey.to_string())
            .await
            .unwrap()
            .is_empty()
    );
}

// ============================================================================
// HEALTH CHECK UTILITIES
// ============================================================================

/// Get a health check client for a server on the given port
pub async fn get_health_client(
    port: u16,
) -> anyhow::Result<tonic_health::pb::health_client::HealthClient<tonic::transport::Channel>> {
    use crate::consts::{DEFAULT_PROTOCOL, DEFAULT_URL};
    use tonic::transport::Channel;

    let server_address = &format!("{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{port}");
    let channel_builder = Channel::from_shared(server_address.to_string())?;
    let channel = channel_builder.connect().await?;
    Ok(tonic_health::pb::health_client::HealthClient::new(channel))
}

/// Get the health status of a service
pub async fn get_status(
    health_client: &mut tonic_health::pb::health_client::HealthClient<tonic::transport::Channel>,
    service_name: &str,
) -> Result<i32, tonic::Status> {
    use tonic_health::pb::HealthCheckRequest;

    let request = tonic::Request::new(HealthCheckRequest {
        service: service_name.to_string(),
    });
    let response = health_client.check(request).await?;
    Ok(response.into_inner().status)
}
