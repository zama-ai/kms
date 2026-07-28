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

        // confirm nothing survived before the caller is allowed to delete the
        // recovery material and drop lifecycle state.
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
    /// An info log is produced for each data type that is not found in the backup.
    async fn delete_custodian_backup_data(&mut self, backup_id: &RequestId) -> anyhow::Result<()> {
        for cur_type in PrivDataType::iter() {
            let vault_data_type = VaultDataType::CustodianBackupData(*backup_id, cur_type);
            let ids = self
                .storage
                .all_data_ids(&vault_data_type.to_string())
                .await?;
            // Epoched types (e.g. FheKeyInfo) are backed up under
            // <backup_id>/<data_type>/<epoch_id>/<data_id> and are not visible to
            // `all_data_ids`, so they must be enumerated per epoch. Enumerating
            // epochs also fixes a latent bug: the earlier `remove_old_backup`
            // deleted only `all_data_ids` entries and left epoched backup
            // material orphaned.
            let epoch_ids = self
                .storage
                .all_epoch_ids_for_data(&vault_data_type.to_string())
                .await?;
            if ids.is_empty() && epoch_ids.is_empty() {
                tracing::info!("No data found for backup id {backup_id} and data type {cur_type}");
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
    use super::{Vault, VaultDataType};
    use crate::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType};
    use crate::engine::base::derive_request_id;
    use crate::vault::keychain::KeychainProxy;
    use crate::vault::keychain::secretsharing::SecretShareKeychain;
    use crate::vault::storage::file::FileStorage;
    use crate::vault::storage::ram::RamStorage;
    use crate::vault::storage::{
        Storage, StorageExt, StorageProxy, StorageReader, StorageReaderExt, StorageType,
    };
    use aes_prng::AesRng;
    use kms_grpc::{EpochId, RequestId, rpc_types::PrivDataType};
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

    /// `purge_backup` on a custodian vault must delete exactly the entries stored
    /// under the given backup id — including the _current_ one, which
    /// `remove_old_backup` refuses to touch (this is the cleanup path for a failed
    /// backup setup) — and leave other backups intact.
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
        // Entry under the current backup id, written through the vault
        vault
            .store_bytes(b"current", &data_id, &data_type.to_string())
            .await
            .unwrap();
        // Epoched entry under the current backup id
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
        // Entry under an old backup id, written directly at its per-context path
        let old_path = VaultDataType::CustodianBackupData(old_id, data_type).to_string();
        vault
            .storage
            .store_bytes(b"old", &data_id, &old_path)
            .await
            .unwrap();

        // Purging the old backup must not touch the current one
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

        // remove_old_backup refuses the current backup id, but purge_backup handles it
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

        // Purging an id with no data is not an error
        vault.purge_backup(&current_id).await.unwrap();
    }

    /// On a vault without a custodian keychain, `purge_backup` falls back to
    /// deleting the data stored directly under the given id, leaving other ids intact.
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

    /// Shared scenario: `remove_old_backup` must delete both non-epoched and epoched
    /// entries under the old backup id, leave the current backup untouched and refuse
    /// to delete the current backup id.
    async fn remove_old_backup_scenario(storage: StorageProxy) {
        let mut rng = AesRng::seed_from_u64(43);
        let epoch_id = EpochId::new_random(&mut rng);
        let old_backup_id = derive_request_id("old_custodian_context").unwrap();
        let mut vault = Vault {
            storage,
            keychain: Some(make_secret_share_keychain(old_backup_id).await),
        };

        // Store a non-epoched and an epoched entry under the old backup id.
        // Use store_bytes since it doesn't require encryption (just wraps the path)
        let data_id = derive_request_id("test_backup_data").unwrap();
        let non_epoched_type = PrivDataType::SigningKey.to_string();
        let epoched_type = PrivDataType::FheKeyInfo.to_string();
        vault
            .store_bytes(b"old_non_epoched", &data_id, &non_epoched_type)
            .await
            .unwrap();
        vault
            .store_bytes_at_epoch(b"old_epoched", &data_id, &epoch_id, &epoched_type)
            .await
            .unwrap();

        // Switch the keychain to a new custodian context and store the same entries under it
        let current_backup_id = derive_request_id("current_custodian_context").unwrap();
        if let Some(KeychainProxy::SecretSharing(keychain)) = vault.keychain.as_mut() {
            let enc_key = keychain.get_backup_enc_key().unwrap();
            keychain.set_backup_enc_key(current_backup_id, enc_key);
        }
        vault
            .store_bytes(b"cur_non_epoched", &data_id, &non_epoched_type)
            .await
            .unwrap();
        vault
            .store_bytes_at_epoch(b"cur_epoched", &data_id, &epoch_id, &epoched_type)
            .await
            .unwrap();

        // Removing the current backup id must fail
        assert!(vault.remove_old_backup(&current_backup_id).await.is_err());

        vault.remove_old_backup(&old_backup_id).await.unwrap();

        // Everything under the old backup id must be gone
        for cur_type in [PrivDataType::SigningKey, PrivDataType::FheKeyInfo] {
            let old_prefix =
                VaultDataType::CustodianBackupData(old_backup_id, cur_type).to_string();
            assert!(
                vault
                    .storage
                    .all_data_ids(&old_prefix)
                    .await
                    .unwrap()
                    .is_empty(),
                "non-epoched data for {cur_type} should be deleted"
            );
            assert!(
                vault
                    .storage
                    .all_data_ids_from_all_epochs(&old_prefix)
                    .await
                    .unwrap()
                    .is_empty(),
                "epoched data for {cur_type} should be deleted"
            );
        }

        // The current backup must be untouched
        let cur_non_epoched =
            VaultDataType::CustodianBackupData(current_backup_id, PrivDataType::SigningKey)
                .to_string();
        let cur_epoched =
            VaultDataType::CustodianBackupData(current_backup_id, PrivDataType::FheKeyInfo)
                .to_string();
        assert!(
            vault
                .storage
                .data_exists(&data_id, &cur_non_epoched)
                .await
                .unwrap()
        );
        assert!(
            vault
                .storage
                .data_exists_at_epoch(&data_id, &epoch_id, &cur_epoched)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_remove_old_backup_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(Some(temp_dir.path()), StorageType::BACKUP, None).unwrap();
        remove_old_backup_scenario(StorageProxy::from(storage)).await;
    }

    #[tokio::test]
    async fn test_remove_old_backup_ram() {
        remove_old_backup_scenario(StorageProxy::from(RamStorage::new())).await;
    }

    // Runs against the in-process S3 mock (see `storage::s3::mock_s3`), so it needs the
    // features that gate `create_s3_storage` rather than the removed `s3_tests` feature.
    #[cfg(all(feature = "non-wasm", feature = "testing"))]
    #[tokio::test]
    async fn test_remove_old_backup_s3() {
        let storage = crate::vault::storage::s3::create_s3_storage(
            StorageType::BACKUP,
            std::stringify!(test_remove_old_backup_s3),
        )
        .await;
        remove_old_backup_scenario(StorageProxy::from(storage)).await;
    }

    #[tokio::test]
    async fn test_remove_old_backup_requires_custodian_vault() {
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
    async fn test_remove_old_backup_deletes_epoch_scoped_data() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backup_storage =
            FileStorage::new(Some(temp_dir.path()), StorageType::BACKUP, None).unwrap();

        // Build a secret-sharing backup vault.
        let mut rng = AesRng::seed_from_u64(42);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = enc.keygen().unwrap();
        let keychain = SecretShareKeychain::<AesRng>::new::<FileStorage>(rng, None)
            .await
            .unwrap();
        let mut vault = Vault {
            storage: crate::vault::storage::StorageProxy::from(backup_storage),
            keychain: Some(KeychainProxy::SecretSharing(keychain)),
        };

        // The custodian context we will retire, and the one that becomes current after rotation.
        let old_backup_id = derive_request_id("old_custodian_context").unwrap();
        let current_backup_id = derive_request_id("current_custodian_context").unwrap();

        // `FheKeyInfo` is one of the epoch-scoped private data types.
        let data_type = PrivDataType::FheKeyInfo;
        let epoch_id = EpochId::from_bytes([7u8; 32]);

        // While `old_backup_id` is the current context, back up two objects: one epoch-scoped
        // (as the real backup-sync path does via `store_data_at_epoch`) and one non-epoch object
        // (a positive control proving `remove_old_backup` actually runs and deletes what it sees).
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

        // Sanity: both objects are present under the old context before retirement.
        let old_data_type =
            VaultDataType::CustodianBackupData(old_backup_id, data_type).to_string();
        assert!(
            vault
                .storage
                .data_exists(&non_epoch_item, &old_data_type)
                .await
                .unwrap(),
            "non-epoch backup should exist before destruction"
        );
        assert!(
            vault
                .storage
                .data_exists_at_epoch(&epoch_id_item, &epoch_id, &old_data_type)
                .await
                .unwrap(),
            "epoch-scoped backup should exist before destruction"
        );

        // Rotate: a new custodian context becomes current so the old one is allowed to be retired.
        set_current_backup_id(&mut vault, current_backup_id, enc_key);

        // Retire the old context. This is exactly what `delete_custodian_context_at_id` calls
        // before deleting the recovery material and reporting a successful destruction.
        vault.remove_old_backup(&old_backup_id).await.unwrap();

        // Positive control: the non-epoch object was deleted, so `remove_old_backup` did run.
        assert!(
            vault
                .storage
                .all_data_ids(&old_data_type)
                .await
                .unwrap()
                .is_empty(),
            "non-epoch backup should have been deleted by remove_old_backup"
        );

        // The retirement guarantee: no backup object for the retired context may remain.
        // The epoch namespace is enumerated separately from the non-epoch one, so this is
        // what catches a regression back to deleting only what `all_data_ids` reports.
        let leftover = vault
            .storage
            .all_data_ids_from_all_epochs(&old_data_type)
            .await
            .unwrap();
        assert!(
            leftover.is_empty(),
            "destroying a custodian context must erase epoch-scoped backups, \
             but these survived: {leftover:?}"
        );
    }

    /// Point the vault's secret-sharing keychain at `backup_id` as the current custodian context.
    fn set_current_backup_id(
        vault: &mut Vault,
        backup_id: RequestId,
        enc_key: crate::cryptography::encryption::UnifiedPublicEncKey,
    ) {
        match vault.keychain.as_mut() {
            Some(KeychainProxy::SecretSharing(kc)) => kc.set_backup_enc_key(backup_id, enc_key),
            _ => panic!("expected a secret sharing keychain"),
        }
    }
}
