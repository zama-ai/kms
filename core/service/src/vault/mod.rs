use anyhow::anyhow;
use keychain::{EnvelopeLoad, EnvelopeStore, Keychain, KeychainProxy};
use kms_grpc::{RequestId, identifiers::EpochId, rpc_types::PrivDataType};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::HashSet, fmt, path::MAIN_SEPARATOR};
use storage::{Storage, StorageProxy, StorageReader, StoreWriteOutcome};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use tfhe::{Unversionize, Versionize, named::Named};

#[cfg(feature = "non-wasm")]
use crate::vault::storage::StorageExt;
use crate::vault::storage::StorageReaderExt;

pub mod aws;
pub mod keychain;
pub mod storage;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, EnumIter)]
pub enum VaultDataType {
    // Backup of a piece of private data under a given backup id (RequestId) for custodian-based backup
    CustodianBackupData(RequestId, PrivDataType),
    // Backup a piece of private data for the import/export based backup
    EncryptedPrivData(PrivDataType),
    // Unencrypted data. May be either private or public data.
    UnencryptedData(String),
}

impl fmt::Display for VaultDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VaultDataType::CustodianBackupData(backup_id, data_type) => {
                write!(f, "{backup_id}{MAIN_SEPARATOR}{data_type}")
            }
            // Note that encrypted private data and unencrypted data will have the same string representation to allow tests to work without encryption
            // and to ensure backwards compatibility.
            VaultDataType::EncryptedPrivData(priv_data_type) => {
                write!(f, "{priv_data_type}")
            }
            VaultDataType::UnencryptedData(data_type) => write!(f, "{data_type}"),
        }
    }
}

pub struct Vault {
    pub storage: StorageProxy,
    pub keychain: Option<KeychainProxy>,
}

impl Vault {
    /// Determine the vault data based on the `outer_data_type` by considering the vault configuration.
    fn get_vault_data_type(&self, outer_data_type: &str) -> anyhow::Result<VaultDataType> {
        match self.keychain.as_ref() {
            Some(keychain_proxy) => match keychain_proxy {
                KeychainProxy::AwsKmsSymm(_awskmskeychain) => Ok(VaultDataType::EncryptedPrivData(
                    outer_data_type.try_into()?,
                )),
                KeychainProxy::AwsKmsAsymm(_awskmskeychain) => Ok(
                    VaultDataType::EncryptedPrivData(outer_data_type.try_into()?),
                ),
                KeychainProxy::SecretSharing(secret_share_keychain) => {
                    Ok(VaultDataType::CustodianBackupData(
                        secret_share_keychain.get_current_backup_id()?,
                        outer_data_type.try_into()?,
                    ))
                }
            },
            None => Ok(VaultDataType::UnencryptedData(outer_data_type.to_string())),
        }
    }

    /// Method for removing an old custodian backup identified by `backup_id`.
    ///
    /// Removes *all* backed-up information stored under `backup_id`, covering both the
    /// non-epoch namespace (`<backup_id>/<type>/<id>`) and the epoch namespace
    /// (`<backup_id>/<type>/<epoch>/<id>`) used for epoch-scoped material such as
    /// [`PrivDataType::FheKeyInfo`], [`PrivDataType::FhePrivateKey`] and
    /// [`PrivDataType::CrsInfo`].
    ///
    /// The method fails closed: after deleting, it re-enumerates every namespace and
    /// returns an error if any object still remains. Callers therefore only proceed to
    /// delete recovery material / drop lifecycle state once erasure is confirmed complete,
    /// so a partial deletion is retried rather than reported as a successful destruction.
    ///
    /// An error is also returned if `backup_id` is the _current_ backup id, or if this is
    /// not a custodian (secret-sharing) backup vault.
    async fn remove_old_backup(&mut self, backup_id: &RequestId) -> anyhow::Result<()> {
        // Only secret-sharing (custodian) backup vaults support per-backup-id removal, and
        // we must never wipe the backup that is currently in use.
        match self.keychain.as_ref() {
            Some(KeychainProxy::SecretSharing(secret_share_keychain)) => {
                if secret_share_keychain.get_current_backup_id()? == *backup_id {
                    return Err(anyhow!(
                        "remove_old_backup cannot be called on the current backup id"
                    ));
                }
            }
            _ => {
                return Err(anyhow!(
                    "remove_old_backup can only be called on custodian backup vaults"
                ));
            }
        }

        // The helper addresses the storage directly with the fully-qualified
        // `CustodianBackupData(backup_id, ..)` data type rather than going through the
        // Vault's `StorageReaderExt`/`StorageExt` methods: those resolve the data type
        // against the *current* backup id and would therefore target the wrong namespace
        // when erasing a retired context.
        self.delete_custodian_backup_data(backup_id).await?;

        // A backend can report a successful delete without removing the object. Re-enumerate the
        // namespace before the caller removes recovery material and lifecycle state.
        let mut residual = Vec::new();
        for cur_type in PrivDataType::iter() {
            let vault_data_type =
                VaultDataType::CustodianBackupData(*backup_id, cur_type).to_string();

            let remaining_non_epoch = self.storage.all_data_ids(&vault_data_type).await?;
            if !remaining_non_epoch.is_empty() {
                residual.push(format!(
                    "{} non-epoch object(s) for data type {cur_type}",
                    remaining_non_epoch.len()
                ));
            }

            for epoch_id in self
                .storage
                .all_epoch_ids_for_data(&vault_data_type)
                .await?
            {
                let remaining_epoch = self
                    .storage
                    .all_data_ids_at_epoch(&epoch_id, &vault_data_type)
                    .await?;
                if !remaining_epoch.is_empty() {
                    residual.push(format!(
                        "{} object(s) for data type {cur_type} at epoch {epoch_id}",
                        remaining_epoch.len()
                    ));
                }
            }
        }
        if !residual.is_empty() {
            return Err(anyhow!(
                "remove_old_backup did not fully erase backup id {backup_id}; residual data remains: {}",
                residual.join(", ")
            ));
        }

        Ok(())
    }

    /// Delete all custodian backup data stored under `backup_id`, i.e. every
    /// `<backup_id>/<data_type>/<data_id>` entry in the inner storage as well as every
    /// epoched `<backup_id>/<data_type>/<epoch_id>/<data_id>` entry.
    /// An error will be returned if existing data could not be deleted.
    /// A single info log lists the data types that held nothing under this backup id.
    async fn delete_custodian_backup_data(&mut self, backup_id: &RequestId) -> anyhow::Result<()> {
        let mut empty_types = Vec::new();
        for cur_type in PrivDataType::iter() {
            let vault_data_type = VaultDataType::CustodianBackupData(*backup_id, cur_type);
            let ids = self
                .storage
                .all_data_ids(&vault_data_type.to_string())
                .await?;
            // Epoched types (e.g. FheKeyInfo) are backed up under
            // <backup_id>/<data_type>/<epoch_id>/<data_id> and are not visible to
            // `all_data_ids`, so they must be enumerated per epoch.
            let epoch_ids = self
                .storage
                .all_epoch_ids_for_data(&vault_data_type.to_string())
                .await?;
            if ids.is_empty() && epoch_ids.is_empty() {
                empty_types.push(cur_type.to_string());
            }
            for cur_id in ids {
                self.storage
                    .delete_data(&cur_id, &vault_data_type.to_string())
                    .await?;
            }
            for cur_epoch_id in epoch_ids {
                let epoched_ids = self
                    .storage
                    .all_data_ids_at_epoch(&cur_epoch_id, &vault_data_type.to_string())
                    .await?;
                for cur_id in epoched_ids {
                    self.storage
                        .delete_data_at_epoch(&cur_id, &cur_epoch_id, &vault_data_type.to_string())
                        .await?;
                }
            }
        }
        if !empty_types.is_empty() {
            tracing::info!(
                "No data found for backup id {backup_id} and data types {}",
                empty_types.join(", ")
            );
        }
        Ok(())
    }

    /// Purge everything the vault holds under `backup_id`.
    ///
    /// On a custodian (secret-sharing keychain) vault this removes the per-context entries
    /// `<backup_id>/<data_type>/<data_id>` and their epoched counterparts; unlike
    /// [`Self::remove_old_backup`] it may also be called on the _current_ backup id,
    /// e.g. to clean up after a failed backup setup.
    /// On other vaults it falls back to deleting the data stored directly under `backup_id`.
    pub(crate) async fn purge_backup(&mut self, backup_id: &RequestId) -> anyhow::Result<()> {
        match self.keychain.as_ref() {
            Some(KeychainProxy::SecretSharing(_)) => {
                self.delete_custodian_backup_data(backup_id).await
            }
            _ => storage::delete_all_at_request_id(self, backup_id).await,
        }
    }
}

#[cfg(feature = "non-wasm")]
impl StorageReader for Vault {
    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        let vault_data_type = self.get_vault_data_type(data_type)?.to_string();
        match self.keychain.as_ref() {
            Some(keychain_proxy) => {
                let mut envelope = match keychain_proxy {
                    KeychainProxy::AwsKmsSymm(_awskmskeychain) => EnvelopeLoad::AppKeyBlob(
                        self.storage
                            .read_data(data_id, &vault_data_type)
                            .await
                            .map_err(|e| anyhow!("Key blob load failed: {e}"))?,
                    ),
                    KeychainProxy::AwsKmsAsymm(_awskmskeychain) => EnvelopeLoad::AppKeyBlob(
                        self.storage
                            .read_data(data_id, &vault_data_type)
                            .await
                            .map_err(|e| anyhow!("Key blob load failed: {e}"))?,
                    ),
                    KeychainProxy::SecretSharing(_secret_share_keychain) => {
                        EnvelopeLoad::OperatorRecoveryInput(
                            self.storage
                                .read_data(data_id, &vault_data_type)
                                .await
                                .map_err(|e| anyhow!("Backup recovery input load failed: {e}"))?,
                        )
                    }
                };
                keychain_proxy
                    .decrypt(&mut envelope)
                    .await
                    .map_err(|e| anyhow!("Decryption failed during load: {e}"))
            }
            None => self
                .storage
                .read_data(data_id, &vault_data_type)
                .await
                .map_err(|e| anyhow!("Unencrypted load failed: {e}")),
        }
    }

    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        self.storage
            .data_exists(data_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Existence check failed: {e}"))
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref()
            && secret_share_keychain.get_current_backup_id().is_err()
        {
            tracing::info!(
                "No custodian context has been set yet! Returning empty set of data ids."
            );
            return Ok(HashSet::new());
        }
        self.storage
            .all_data_ids(&backup_type)
            .await
            .map_err(|e| anyhow!("Getting all ids failed: {e}"))
    }

    fn info(&self) -> String {
        self.storage.info()
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        self.storage
            .load_bytes(data_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Byte load failed: {e}"))
    }
}

#[cfg(feature = "non-wasm")]
impl StorageReaderExt for Vault {
    async fn all_data_ids_at_epoch(
        &self,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref()
            && secret_share_keychain.get_current_backup_id().is_err()
        {
            tracing::info!(
                "No custodian context has been set yet! Returning empty set of data ids."
            );
            return Ok(HashSet::new());
        }
        self.storage
            .all_data_ids_at_epoch(epoch_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Getting all ids failed: {e}"))
    }

    async fn all_epoch_ids_for_data(&self, data_type: &str) -> anyhow::Result<HashSet<EpochId>> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref()
            && secret_share_keychain.get_current_backup_id().is_err()
        {
            tracing::info!(
                "No custodian context has been set yet! Returning empty set of data ids."
            );
            return Ok(HashSet::new());
        }
        self.storage
            .all_epoch_ids_for_data(&backup_type)
            .await
            .map_err(|e| anyhow!("Getting all ids failed: {e}"))
    }

    async fn data_exists_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<bool> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        self.storage
            .data_exists_at_epoch(data_id, epoch_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Existence check failed: {e}"))
    }

    async fn read_data_at_epoch<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        let vault_data_type = self.get_vault_data_type(data_type)?.to_string();
        match self.keychain.as_ref() {
            Some(keychain_proxy) => {
                let mut envelope = match keychain_proxy {
                    KeychainProxy::AwsKmsSymm(_awskmskeychain) => EnvelopeLoad::AppKeyBlob(
                        self.storage
                            .read_data_at_epoch(data_id, epoch_id, &vault_data_type)
                            .await
                            .map_err(|e| anyhow!("Key blob load failed: {e}"))?,
                    ),
                    KeychainProxy::AwsKmsAsymm(_awskmskeychain) => EnvelopeLoad::AppKeyBlob(
                        self.storage
                            .read_data_at_epoch(data_id, epoch_id, &vault_data_type)
                            .await
                            .map_err(|e| anyhow!("Key blob load failed: {e}"))?,
                    ),
                    KeychainProxy::SecretSharing(_secret_share_keychain) => {
                        EnvelopeLoad::OperatorRecoveryInput(
                            self.storage
                                .read_data_at_epoch(data_id, epoch_id, &vault_data_type)
                                .await
                                .map_err(|e| anyhow!("Backup recovery input load failed: {e}"))?,
                        )
                    }
                };
                keychain_proxy
                    .decrypt(&mut envelope)
                    .await
                    .map_err(|e| anyhow!("Decryption failed during load: {e}"))
            }
            None => self
                .storage
                .read_data_at_epoch(data_id, epoch_id, &vault_data_type)
                .await
                .map_err(|e| anyhow!("Unencrypted load failed: {e}")),
        }
    }

    async fn all_data_ids_from_all_epochs(
        &self,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref()
            && secret_share_keychain.get_current_backup_id().is_err()
        {
            tracing::info!(
                "No custodian context has been set yet! Returning empty set of data ids."
            );
            return Ok(HashSet::new());
        }
        self.storage
            .all_data_ids_from_all_epochs(&backup_type)
            .await
    }

    async fn load_bytes_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        self.storage
            .load_bytes_at_epoch(data_id, epoch_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Byte load at epoch failed: {e}"))
    }
}

#[cfg(feature = "non-wasm")]
impl Storage for Vault {
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let vault_data_type = self.get_vault_data_type(data_type)?.to_string();
        match self.keychain.as_mut() {
            Some(kcp) => {
                let envelope = kcp
                    .encrypt(data, data_type)
                    .await
                    .map_err(|e| anyhow!("Encryption failed during store: {e}"))?;
                match envelope {
                    EnvelopeStore::AppKeyBlob(blob) => self
                        .storage
                        .store_data(&blob, data_id, data_type)
                        .await
                        .map_err(|e| anyhow!("Key blob store failed: {e}")),
                    EnvelopeStore::OperatorBackupOutput(ct) => self
                        .storage
                        .store_data(&ct, data_id, &vault_data_type)
                        .await
                        .map_err(|e| anyhow!("Backup output store failed: {e}")),
                }
            }
            None => self
                .storage
                .store_data(data, data_id, &vault_data_type)
                .await
                .map_err(|e| anyhow!("Unencrypted store failed: {e}")),
        }
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        self.storage
            .delete_data(data_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Delete failed: {e}"))
    }

    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        self.storage
            .store_bytes(bytes, data_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Byte store failed: {e}"))
    }
}

#[cfg(feature = "non-wasm")]
impl StorageExt for Vault {
    async fn store_data_at_epoch<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let vault_data_type = self.get_vault_data_type(data_type)?.to_string();
        match self.keychain.as_mut() {
            Some(kcp) => {
                let envelope = kcp
                    .encrypt(data, data_type)
                    .await
                    .map_err(|e| anyhow!("Encryption failed during store: {e}"))?;
                match envelope {
                    EnvelopeStore::AppKeyBlob(blob) => self
                        .storage
                        .store_data_at_epoch(&blob, data_id, epoch_id, data_type)
                        .await
                        .map_err(|e| anyhow!("Key blob store failed: {e}")),
                    EnvelopeStore::OperatorBackupOutput(ct) => self
                        .storage
                        .store_data_at_epoch(&ct, data_id, epoch_id, &vault_data_type)
                        .await
                        .map_err(|e| anyhow!("Backup output store failed: {e}")),
                }
            }
            None => self
                .storage
                .store_data_at_epoch(data, data_id, epoch_id, &vault_data_type)
                .await
                .map_err(|e| anyhow!("Unencrypted store failed: {e}")),
        }
    }

    async fn store_bytes_at_epoch(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        self.storage
            .store_bytes_at_epoch(bytes, data_id, epoch_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Byte store at epoch failed: {e}"))
    }

    async fn delete_data_at_epoch(
        &mut self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        let backup_type = self.get_vault_data_type(data_type)?.to_string();
        self.storage
            .delete_data_at_epoch(data_id, epoch_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Delete failed: {e}"))
    }
}

pub(crate) fn storage_prefix_safety(
    storage_type: storage::StorageType,
    prefix: &str,
) -> anyhow::Result<()> {
    let pub_str = storage::StorageType::PUB.to_string();
    let priv_str = storage::StorageType::PRIV.to_string();
    let backup_str = storage::StorageType::BACKUP.to_string();
    let client_str = storage::StorageType::CLIENT.to_string();

    let print_warning = match storage_type {
        storage::StorageType::PUB => {
            prefix.starts_with(&priv_str)
                || prefix.starts_with(&client_str)
                || prefix.starts_with(&backup_str)
        }
        storage::StorageType::PRIV => {
            prefix.starts_with(&pub_str)
                || prefix.starts_with(&client_str)
                || prefix.starts_with(&backup_str)
        }
        storage::StorageType::CLIENT => {
            prefix.starts_with(&pub_str)
                || prefix.starts_with(&priv_str)
                || prefix.starts_with(&backup_str)
        }
        storage::StorageType::BACKUP => {
            prefix.starts_with(&pub_str)
                || prefix.starts_with(&priv_str)
                || prefix.starts_with(&client_str)
        }
    };
    if print_warning {
        let msg = format!(
            "The storage prefix {} starts with a different storage type {}. This may lead to confusion.",
            prefix, storage_type
        );
        tracing::warn!(msg);
        anyhow::bail!(msg);
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    mod backup_cleanup;

    use super::{Vault, VaultDataType};
    use crate::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType};
    use crate::engine::base::derive_request_id;
    use crate::vault::keychain::KeychainProxy;
    use crate::vault::keychain::secretsharing::SecretShareKeychain;
    use crate::vault::storage::file::FileStorage;
    use crate::vault::storage::{Storage, StorageProxy, StorageType};
    use aes_prng::AesRng;
    use kms_grpc::{RequestId, rpc_types::PrivDataType};
    use rand::SeedableRng;

    /// Build a secret-sharing keychain whose current backup id is `current_backup_id`.
    pub(crate) async fn make_secret_share_keychain(current_backup_id: RequestId) -> KeychainProxy {
        let mut rng = AesRng::seed_from_u64(42);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = enc.keygen().unwrap();
        let mut keychain = SecretShareKeychain::<AesRng>::new::<FileStorage>(rng, None)
            .await
            .unwrap();
        keychain.set_backup_enc_key(current_backup_id, enc_key);
        KeychainProxy::SecretSharing(keychain)
    }

    #[test]
    fn regression_test_vault_data_type_serialization() {
        let backup_id = RequestId::from_bytes([0u8; 32]);
        let vdt1 = VaultDataType::CustodianBackupData(backup_id, PrivDataType::FheKeyInfo);
        let vdt1_str = vdt1.to_string();
        assert_eq!(
            vdt1_str,
            format!(
                "{backup_id}{}{}",
                std::path::MAIN_SEPARATOR,
                PrivDataType::FheKeyInfo
            )
        );
        // Check encrypted and unencrypted data have the same string representation
        let vdt2 = VaultDataType::EncryptedPrivData(PrivDataType::FheKeyInfo);
        assert_eq!(vdt2.to_string(), PrivDataType::FheKeyInfo.to_string());
        let vdt3 = VaultDataType::UnencryptedData(PrivDataType::FheKeyInfo.to_string());
        assert_eq!(vdt3.to_string(), PrivDataType::FheKeyInfo.to_string());
        assert_eq!(vdt2.to_string(), vdt3.to_string());
    }

    /// Verify that custodian backup data is stored in a folder hierarchy
    /// rooted at the custodian context ID:
    ///   <backup_root>/<custodian_context_id>/<data_type>/<request_id>
    #[tokio::test]
    async fn test_custodian_backup_folder_hierarchy() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backup_storage =
            FileStorage::new(Some(temp_dir.path()), StorageType::BACKUP, None).unwrap();
        let backup_root = backup_storage.root_dir().to_path_buf();

        // Create a secret sharing keychain with a known custodian context ID
        let custodian_context_id = derive_request_id("test_custodian_context").unwrap();
        let mut vault = Vault {
            storage: StorageProxy::from(backup_storage),
            keychain: Some(make_secret_share_keychain(custodian_context_id).await),
        };

        // Store some data through the vault
        let data_type = PrivDataType::SigningKey;
        let data_id = derive_request_id("test_data_item").unwrap();
        // Use store_bytes since it doesn't require encryption (just wraps the path)
        vault
            .store_bytes(b"test_data", &data_id, &data_type.to_string())
            .await
            .unwrap();

        // Verify the folder hierarchy starts with the custodian context ID
        let expected_dir = backup_root
            .join(custodian_context_id.to_string())
            .join(data_type.to_string());
        assert!(
            expected_dir.exists(),
            "Backup data directory should be under <backup_root>/<custodian_context_id>/<data_type>, \
             expected: {expected_dir:?}"
        );
        let expected_file = expected_dir.join(data_id.to_string());
        assert!(
            expected_file.exists(),
            "Backup data file should be at <backup_root>/<custodian_context_id>/<data_type>/<request_id>, \
             expected: {expected_file:?}"
        );
    }
}
