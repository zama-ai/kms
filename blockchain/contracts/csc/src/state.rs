use crate::allowlists::AllowlistsCsc;
use contracts_common::{allowlists::AllowlistsStateManager, versioned_states::VersionedItem};
use events::kms::KmsConfig;

use cosmwasm_std::{StdError, StdResult, Storage};

pub struct ConfigStorage {
    kms_configuration: VersionedItem<KmsConfig>,
    storage_base_urls: VersionedItem<Vec<String>>,
    allowlists: VersionedItem<AllowlistsCsc>,
}

impl Default for ConfigStorage {
    fn default() -> Self {
        Self {
            kms_configuration: VersionedItem::new("kms_configuration"),
            storage_base_urls: VersionedItem::new("storage_base_urls"),
            allowlists: VersionedItem::new("allowlists"),
        }
    }
}

impl AllowlistsStateManager for ConfigStorage {
    type Allowlists = AllowlistsCsc;

    fn allowlists(&self) -> &VersionedItem<AllowlistsCsc> {
        &self.allowlists
    }
}

impl ConfigStorage {
    /// Get the KMS configuration
    pub fn get_kms_configuration(&self, storage: &dyn Storage) -> StdResult<KmsConfig> {
        self.kms_configuration.load(storage)
    }

    /// Set the KMS configuration
    pub fn set_kms_configuration(
        &self,
        storage: &mut dyn Storage,
        value: KmsConfig,
    ) -> StdResult<()> {
        self.kms_configuration.save(storage, &value)
    }

    /// Get the storage base URLs
    pub fn get_storage_base_urls(&self, storage: &dyn Storage) -> StdResult<Vec<String>> {
        self.storage_base_urls.load(storage)
    }

    /// Set the storage base URLs
    pub fn set_storage_base_urls(
        &self,
        storage: &mut dyn Storage,
        value: Vec<String>,
    ) -> StdResult<()> {
        self.storage_base_urls.save(storage, &value)
    }

    // Update the KMS's configuration
    pub fn update_kms_configuration(
        &self,
        storage: &mut dyn Storage,
        kms_configuration: KmsConfig,
    ) -> StdResult<()> {
        self.kms_configuration.update(
            storage,
            |current_kms_configuration| -> StdResult<KmsConfig> {
                // Following https://github.com/zama-ai/planning-blockchain/issues/182#issuecomment-2429482934
                // we disallow changing the amount of parties participating
                if current_kms_configuration.parties.len() != kms_configuration.parties.len() {
                    return Err(StdError::generic_err(
                        "Updating the core parties failed: \
                        It is currently not allowed to \
                        change the number of parties participating",
                    ));
                }
                Ok(kms_configuration)
            },
        )?;
        Ok(())
    }

    // Update the storage base URLs
    pub fn update_storage_base_urls(
        &self,
        storage: &mut dyn Storage,
        value: Vec<String>,
    ) -> StdResult<()> {
        self.storage_base_urls.save(storage, &value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::MockStorage;
    use events::kms::{FheParameter, KmsCoreParty};

    #[test]
    fn test_kms_configuration_threshold() {
        let dyn_store = &mut MockStorage::new();
        let storage = ConfigStorage::default();
        let kms_configuration = KmsConfig {
            parties: vec![KmsCoreParty::default(); 4],
            response_count_for_majority_vote: 3,
            response_count_for_reconstruction: 3,
            degree_for_reconstruction: 1,
            param_choice: FheParameter::Test,
        };
        storage
            .set_kms_configuration(dyn_store, kms_configuration.clone())
            .unwrap();
        assert_eq!(
            storage.get_kms_configuration(dyn_store).unwrap(),
            kms_configuration
        );

        // next try to update from threshold to centralized, which should fail
        let central_conf = KmsConfig {
            parties: vec![KmsCoreParty::default(); 1],
            response_count_for_majority_vote: 1,
            response_count_for_reconstruction: 1,
            degree_for_reconstruction: 0,
            param_choice: FheParameter::Test,
        };
        assert!(storage
            .update_kms_configuration(dyn_store, central_conf)
            .unwrap_err()
            .to_string()
            .contains("Updating the core parties failed:"));
    }

    #[test]
    fn test_kms_configuration_centralized() {
        let dyn_store = &mut MockStorage::new();
        let storage = ConfigStorage::default();
        let kms_configuration = KmsConfig {
            parties: vec![KmsCoreParty::default(); 1],
            response_count_for_majority_vote: 1,
            response_count_for_reconstruction: 1,
            degree_for_reconstruction: 0,
            param_choice: FheParameter::Test,
        };
        storage
            .set_kms_configuration(dyn_store, kms_configuration.clone())
            .unwrap();
        assert_eq!(
            storage.get_kms_configuration(dyn_store).unwrap(),
            kms_configuration
        );

        // next try to update from centralized to threshold, which should fail
        let threshold_conf = KmsConfig {
            parties: vec![KmsCoreParty::default(); 4],
            response_count_for_majority_vote: 3,
            response_count_for_reconstruction: 3,
            degree_for_reconstruction: 1,
            param_choice: FheParameter::Test,
        };
        assert!(storage
            .update_kms_configuration(dyn_store, threshold_conf)
            .unwrap_err()
            .to_string()
            .contains("Updating the core parties failed:"));
    }
}
