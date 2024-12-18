use crate::allowlists::AllowlistsCsc;
use contracts_common::{allowlists::AllowlistsStateManager, versioned_states::VersionedItem};
use events::kms::{FheParameter, KmsCoreParty};

use cosmwasm_std::{StdError, StdResult, Storage};

/// Struct containing the parameters that will need to conform with the number of parties
struct ParametersToConform {
    degree_for_reconstruction: Option<usize>,
    response_count_for_majority_vote: Option<usize>,
    response_count_for_reconstruction: Option<usize>,
}

impl ParametersToConform {
    fn new() -> Self {
        Self {
            degree_for_reconstruction: None,
            response_count_for_majority_vote: None,
            response_count_for_reconstruction: None,
        }
    }

    fn with_degree_for_reconstruction(mut self, value: usize) -> Self {
        self.degree_for_reconstruction = Some(value);
        self
    }

    fn with_response_count_for_majority_vote(mut self, value: usize) -> Self {
        self.response_count_for_majority_vote = Some(value);
        self
    }

    fn with_response_count_for_reconstruction(mut self, value: usize) -> Self {
        self.response_count_for_reconstruction = Some(value);
        self
    }
}

/// Storage for the CSC
/// - `parties` - the list of core parties and their associated information (id, public key, address, TLS public key)
/// - `response_count_for_majority_vote` - the number of responses needed for majority voting
///   (used for sending responses to the client with all operations except reencryption)
/// - `response_count_for_reconstruction` - the number of responses needed for reconstruction
///   (used for sending responses to the client with reencryption operations)
/// - `degree_for_reconstruction` - the degree of the polynomial for reconstruction
///   (used for checking majority and conformance)
/// - `param_choice` - the FHE parameter choice (either default or test)
/// - `storage_base_urls` - the list of storage base URLs
/// - `allowlists` - an optional struct containing several lists of addresses that define
///   who can trigger some operations (mostly about updating the configuration or allowlists).
///   Providing None will default to use the sender's address for all operation types.
pub struct ConfigStorage {
    parties: VersionedItem<Vec<KmsCoreParty>>,
    response_count_for_majority_vote: VersionedItem<usize>,
    response_count_for_reconstruction: VersionedItem<usize>,
    degree_for_reconstruction: VersionedItem<usize>,
    param_choice: VersionedItem<FheParameter>,
    storage_base_urls: VersionedItem<Vec<String>>,
    allowlists: VersionedItem<AllowlistsCsc>,
}

impl Default for ConfigStorage {
    fn default() -> Self {
        Self {
            parties: VersionedItem::new("parties"),
            response_count_for_majority_vote: VersionedItem::new(
                "response_count_for_majority_vote",
            ),
            response_count_for_reconstruction: VersionedItem::new(
                "response_count_for_reconstruction",
            ),
            degree_for_reconstruction: VersionedItem::new("degree_for_reconstruction"),
            param_choice: VersionedItem::new("param_choice"),
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
    /// We use the number of parties as a proxy to know whether we are in centralized case or threshold
    pub fn is_centralized(&self, storage: &dyn Storage) -> bool {
        self.parties.load(storage).unwrap().len() == 1
    }

    /// Check whether the given configuration parameters are conformant, and return an error if not
    ///
    /// This is a static method and thus does not load anything from the contract state
    pub(crate) fn check_config_is_conformant(
        parties: Vec<KmsCoreParty>,
        response_count_for_majority_vote: usize,
        response_count_for_reconstruction: usize,
        degree_for_reconstruction: usize,
    ) -> Result<(), StdError> {
        let num_parties = parties.len();

        // Centralized case (i.e. there is only one party)
        if num_parties == 1 {
            if response_count_for_majority_vote != 1
                || response_count_for_reconstruction != 1
                || degree_for_reconstruction != 0
            {
                return Err(StdError::generic_err(format!(
                    "KMS configuration is not conformant for centralized case. Got \
                    parties (len): {}, \
                    responses for majority vote: {} (expected 1), \
                    responses for reconstruction: {} (expected 1), \
                    degree for reconstruction: {} (expected 0)",
                    parties.len(),
                    response_count_for_majority_vote,
                    response_count_for_reconstruction,
                    degree_for_reconstruction
                )));
            }
            return Ok(());
        }

        // Threshold case

        // Check that (num_parties - 1) is divisible by 3
        if (num_parties - 1) % 3 != 0 {
            return Err(StdError::generic_err(format!(
                "Number of parties is incorrect. (num_parties - 1) must be divisible by 3. Got: {}",
                num_parties
            )));
        }

        let majority = num_parties.div_ceil(2);
        let reconstruction_min = degree_for_reconstruction + 2;

        // We assume we are always looking for highest possible threshold
        // Note that here we already check that (num_parties - 1) is divisible by 3
        let expected_degree = (num_parties - 1) / 3;

        // Check all conditions for threshold case
        // Majority vote requires at least a majority
        if response_count_for_majority_vote < majority
            // Majority vote cannot be more than the number of parties
            || response_count_for_majority_vote > num_parties
            // Reconstruction requires at least degree + 2 responses
            || response_count_for_reconstruction < reconstruction_min
            // Reconstruction cannot be more than the number of parties
            || response_count_for_reconstruction > num_parties
            // Degree for reconstruction must be the expected degree
            || degree_for_reconstruction != expected_degree
        {
            return Err(StdError::generic_err(format!(
                "KMS configuration is not conformant for threshold case. Got \
                parties (len): {}, \
                responses for majority vote: {} (expected between {} and {}, both included), \
                responses for reconstruction: {} (expected between {} and {}, both included), \
                degree for reconstruction: {} (expected {})",
                parties.len(),
                response_count_for_majority_vote,
                majority,
                num_parties,
                response_count_for_reconstruction,
                reconstruction_min,
                num_parties,
                degree_for_reconstruction,
                expected_degree
            )));
        }

        Ok(())
    }

    /// Check that the given configuration parameter(s) will be conformant with the others found in the contract state
    ///
    /// If some parameters are not provided, they will be loaded from the contract state. This allows
    /// for example to check that updating a parameter (or several parameters) will not break the
    /// configuration conformance before saving it to the state.
    fn check_parameters_will_conform(
        &self,
        storage: &dyn Storage,
        parameters_to_conform: ParametersToConform,
    ) -> Result<(), StdError> {
        let parties = self
            .parties
            .load(storage)
            .map_err(|e| StdError::generic_err(format!("Failed to load parties: {}", e)))?;

        let degree_for_reconstruction = parameters_to_conform
            .degree_for_reconstruction
            .unwrap_or_else(|| self.degree_for_reconstruction.load(storage).unwrap());
        let response_count_for_majority_vote = parameters_to_conform
            .response_count_for_majority_vote
            .unwrap_or_else(|| self.response_count_for_majority_vote.load(storage).unwrap());
        let response_count_for_reconstruction = parameters_to_conform
            .response_count_for_reconstruction
            .unwrap_or_else(|| {
                self.response_count_for_reconstruction
                    .load(storage)
                    .unwrap()
            });

        Self::check_config_is_conformant(
            parties,
            response_count_for_majority_vote,
            response_count_for_reconstruction,
            degree_for_reconstruction,
        )
    }

    /// Get the parties
    pub fn get_parties(&self, storage: &dyn Storage) -> StdResult<Vec<KmsCoreParty>> {
        self.parties.load(storage)
    }

    /// Set the parties
    pub(crate) fn set_parties(
        &self,
        storage: &mut dyn Storage,
        value: Vec<KmsCoreParty>,
    ) -> StdResult<()> {
        self.parties.save(storage, &value)
    }

    // Update the parties list
    pub fn update_parties(
        &self,
        storage: &mut dyn Storage,
        value: Vec<KmsCoreParty>,
    ) -> StdResult<Vec<KmsCoreParty>> {
        self.parties
            .update(storage, |current_parties| -> StdResult<Vec<KmsCoreParty>> {
                if current_parties.len() != value.len() {
                    return Err(StdError::generic_err(
                        "Updating the core parties failed: \
                        It is currently not allowed to \
                        change the number of parties participating",
                    ));
                }
                Ok(value)
            })
    }

    /// Get the response count for majority vote
    pub fn get_response_count_for_majority_vote(&self, storage: &dyn Storage) -> StdResult<usize> {
        self.response_count_for_majority_vote.load(storage)
    }

    /// Set the response count for majority vote
    pub(crate) fn set_response_count_for_majority_vote(
        &self,
        storage: &mut dyn Storage,
        value: usize,
    ) -> StdResult<()> {
        self.response_count_for_majority_vote.save(storage, &value)
    }

    // Update the response count for majority vote
    pub fn update_response_count_for_majority_vote(
        &self,
        storage: &mut dyn Storage,
        value: usize,
    ) -> StdResult<usize> {
        // Check that the given response count for majority vote will be conformant with the current configuration
        self.check_parameters_will_conform(
            storage,
            ParametersToConform::new().with_response_count_for_majority_vote(value),
        )?;

        self.response_count_for_majority_vote
            .update(storage, |_| -> StdResult<usize> { Ok(value) })
    }

    /// Get the response count for reconstruction
    pub fn get_response_count_for_reconstruction(&self, storage: &dyn Storage) -> StdResult<usize> {
        self.response_count_for_reconstruction.load(storage)
    }

    /// Set the response count for reconstruction
    pub(crate) fn set_response_count_for_reconstruction(
        &self,
        storage: &mut dyn Storage,
        value: usize,
    ) -> StdResult<()> {
        self.response_count_for_reconstruction.save(storage, &value)
    }

    // Update the response count for reconstruction
    pub fn update_response_count_for_reconstruction(
        &self,
        storage: &mut dyn Storage,
        value: usize,
    ) -> StdResult<usize> {
        // Check that the given response count for reconstruction will be conformant with the current configuration
        self.check_parameters_will_conform(
            storage,
            ParametersToConform::new().with_response_count_for_reconstruction(value),
        )?;

        self.response_count_for_reconstruction
            .update(storage, |_| -> StdResult<usize> { Ok(value) })
    }

    /// Get the degree for reconstruction
    pub fn get_degree_for_reconstruction(&self, storage: &dyn Storage) -> StdResult<usize> {
        self.degree_for_reconstruction.load(storage)
    }

    /// Set the degree for reconstruction
    pub(crate) fn set_degree_for_reconstruction(
        &self,
        storage: &mut dyn Storage,
        value: usize,
    ) -> StdResult<()> {
        self.degree_for_reconstruction.save(storage, &value)
    }

    // Update the degree for reconstruction
    pub fn update_degree_for_reconstruction(
        &self,
        storage: &mut dyn Storage,
        value: usize,
    ) -> StdResult<usize> {
        // Check that the given degree for reconstruction will be conformant with the current configuration
        self.check_parameters_will_conform(
            storage,
            ParametersToConform::new().with_degree_for_reconstruction(value),
        )?;

        self.degree_for_reconstruction
            .update(storage, |_| -> StdResult<usize> { Ok(value) })
    }

    /// Get the parameter choice
    pub fn get_param_choice(&self, storage: &dyn Storage) -> StdResult<FheParameter> {
        self.param_choice.load(storage)
    }

    /// Set the parameter choice
    pub(crate) fn set_param_choice(
        &self,
        storage: &mut dyn Storage,
        value: FheParameter,
    ) -> StdResult<()> {
        self.param_choice.save(storage, &value)
    }

    // Update the parameter choice
    pub fn update_param_choice(
        &self,
        storage: &mut dyn Storage,
        value: FheParameter,
    ) -> StdResult<FheParameter> {
        self.param_choice
            .update(storage, |_| -> StdResult<FheParameter> { Ok(value) })
    }

    /// Get the storage base URLs
    pub fn get_storage_base_urls(&self, storage: &dyn Storage) -> StdResult<Vec<String>> {
        self.storage_base_urls.load(storage)
    }

    /// Set the storage base URLs
    pub(crate) fn set_storage_base_urls(
        &self,
        storage: &mut dyn Storage,
        value: Vec<String>,
    ) -> StdResult<()> {
        self.storage_base_urls.save(storage, &value)
    }

    // Update the storage base URLs
    pub fn update_storage_base_urls(
        &self,
        storage: &mut dyn Storage,
        value: Vec<String>,
    ) -> StdResult<Vec<String>> {
        self.storage_base_urls
            .update(storage, |_| -> StdResult<Vec<String>> { Ok(value) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::MockStorage;
    use events::kms::{FheParameter, KmsCoreParty};

    /// Helper function to set all the configuration parameters all at once
    fn set_all_config_parameters(
        storage: &mut ConfigStorage,
        dyn_store: &mut dyn Storage,
        parties: Vec<KmsCoreParty>,
        response_count_for_majority_vote: usize,
        response_count_for_reconstruction: usize,
        degree_for_reconstruction: usize,
    ) -> StdResult<()> {
        storage.set_parties(dyn_store, parties)?;
        storage
            .set_response_count_for_majority_vote(dyn_store, response_count_for_majority_vote)?;
        storage
            .set_response_count_for_reconstruction(dyn_store, response_count_for_reconstruction)?;
        storage.set_degree_for_reconstruction(dyn_store, degree_for_reconstruction)?;
        Ok(())
    }

    #[test]
    fn test_check_config_is_conformant() {
        let response_count_for_majority_vote = 3;
        let response_count_for_reconstruction = 4;
        let degree_for_reconstruction = 1;

        // Test conformance fails with (n_parties - 1) not divisible by 3
        let wrong_parties = vec![KmsCoreParty::default(); 5];

        assert!(ConfigStorage::check_config_is_conformant(
            wrong_parties.clone(),
            response_count_for_majority_vote,
            response_count_for_reconstruction,
            degree_for_reconstruction + 1,
        )
        .unwrap_err()
        .to_string()
        .contains("Number of parties is incorrect"));

        let parties = vec![KmsCoreParty::default(); 4];

        // Test conformance fails with non-conformant parameters (for 4 parties)
        assert!(ConfigStorage::check_config_is_conformant(
            parties.clone(),
            response_count_for_majority_vote,
            response_count_for_reconstruction,
            degree_for_reconstruction + 1,
        )
        .unwrap_err()
        .to_string()
        .contains("KMS configuration is not conformant"));

        // Test conformance succeeds with conformant parameters (for 4 parties)
        ConfigStorage::check_config_is_conformant(
            parties.clone(),
            response_count_for_majority_vote,
            response_count_for_reconstruction,
            degree_for_reconstruction,
        )
        .unwrap();
    }

    #[test]
    fn test_conformance_centralized() {
        let dyn_store = &mut MockStorage::new();
        let mut storage = ConfigStorage::default();

        let num_parties = 1;
        let parties = vec![KmsCoreParty::default(); num_parties];
        let response_count_for_majority_vote = 1;
        let response_count_for_reconstruction = 1;
        let degree_for_reconstruction = 0;

        // Set all the configuration parameters
        set_all_config_parameters(
            &mut storage,
            dyn_store,
            parties.clone(),
            response_count_for_majority_vote,
            response_count_for_reconstruction,
            degree_for_reconstruction,
        )
        .unwrap();

        // Test non-conformant cases

        // Degree of reconstruction =/= 0
        let new_degree = 1;
        assert!(storage
            .update_degree_for_reconstruction(dyn_store, new_degree)
            .unwrap_err()
            .to_string()
            .contains("KMS configuration is not conformant"));

        // Response count for reconstruction =/= 1
        let new_response_count_for_reconstruction = 2;
        assert!(storage
            .update_response_count_for_reconstruction(
                dyn_store,
                new_response_count_for_reconstruction
            )
            .unwrap_err()
            .to_string()
            .contains("KMS configuration is not conformant"));

        // Response count for majority vote =/= 1
        let new_response_count_for_majority_vote = 3;
        assert!(storage
            .update_response_count_for_majority_vote(
                dyn_store,
                new_response_count_for_majority_vote
            )
            .unwrap_err()
            .to_string()
            .contains("KMS configuration is not conformant"));
    }

    #[test]
    fn test_conformance_threshold() {
        let dyn_store = &mut MockStorage::new();
        let mut storage = ConfigStorage::default();

        let num_parties = 4;
        let parties = vec![KmsCoreParty::default(); num_parties];
        let response_count_for_majority_vote = 3;
        let response_count_for_reconstruction = 4;
        let degree_for_reconstruction = 1;

        // Set all the configuration parameters
        set_all_config_parameters(
            &mut storage,
            dyn_store,
            parties.clone(),
            response_count_for_majority_vote,
            response_count_for_reconstruction,
            degree_for_reconstruction,
        )
        .unwrap();

        // For 4 parties:
        // - degree = 1 (3*1 + 1 = 4)
        // - majority = 2 (ceil(4/2))
        // - degree + 2 = 3 <= reconstruction response count <= 4 = num_parties
        // - majority = 2 <= majority vote response count <= 4 = num_parties
        let expected_majority = 2;
        let expected_degree = 1;

        // Test non-conformant cases for 4 parties

        // Degree of reconstruction =/= 1
        let new_degree = expected_degree + 1;
        assert!(storage
            .update_degree_for_reconstruction(dyn_store, new_degree)
            .unwrap_err()
            .to_string()
            .contains("KMS configuration is not conformant"));

        // Response count for reconstruction too low
        let new_response_count_for_reconstruction = expected_degree + 1;
        assert!(storage
            .update_response_count_for_reconstruction(
                dyn_store,
                new_response_count_for_reconstruction
            )
            .unwrap_err()
            .to_string()
            .contains("KMS configuration is not conformant"));

        // Response count for reconstruction too high
        let new_response_count_for_reconstruction = num_parties + 1;
        assert!(storage
            .update_response_count_for_reconstruction(
                dyn_store,
                new_response_count_for_reconstruction
            )
            .unwrap_err()
            .to_string()
            .contains("KMS configuration is not conformant"));

        // Response count for majority vote too low
        let new_response_count_for_majority_vote = expected_majority - 1;
        assert!(storage
            .update_response_count_for_majority_vote(
                dyn_store,
                new_response_count_for_majority_vote
            )
            .unwrap_err()
            .to_string()
            .contains("KMS configuration is not conformant"));

        // Response count for majority vote too high
        let new_response_count_for_majority_vote = num_parties + 1;
        assert!(storage
            .update_response_count_for_majority_vote(
                dyn_store,
                new_response_count_for_majority_vote
            )
            .unwrap_err()
            .to_string()
            .contains("KMS configuration is not conformant"));
    }

    #[test]
    fn test_is_centralized() {
        let dyn_store = &mut MockStorage::new();
        let storage = ConfigStorage::default();

        // Test centralized case with single party
        let single_party = vec![KmsCoreParty::default()];
        storage.set_parties(dyn_store, single_party).unwrap();
        assert!(storage.is_centralized(dyn_store));

        // Test threshold case with multiple parties
        let multiple_parties = vec![KmsCoreParty::default(); 4];
        storage.set_parties(dyn_store, multiple_parties).unwrap();
        assert!(!storage.is_centralized(dyn_store));
    }

    #[test]
    fn test_parties() {
        let dyn_store = &mut MockStorage::new();
        let storage = ConfigStorage::default();

        let parties = vec![KmsCoreParty::default(); 2];

        // Test set
        storage.set_parties(dyn_store, parties.clone()).unwrap();

        // Test get
        assert_eq!(storage.get_parties(dyn_store).unwrap(), parties);

        // Test update with same number of parties succeeds
        let new_parties = vec![KmsCoreParty::default(); 2];
        let updated_parties = storage
            .update_parties(dyn_store, new_parties.clone())
            .unwrap();
        assert_eq!(updated_parties, new_parties);

        // Test that updating with a different number of parties properly fails
        let different_size_parties = vec![KmsCoreParty::default(); 3];
        assert!(storage
            .update_parties(dyn_store, different_size_parties)
            .unwrap_err()
            .to_string()
            .contains("Updating the core parties failed:"));
    }

    #[test]
    fn test_response_count_for_majority_vote() {
        let dyn_store = &mut MockStorage::new();
        let mut storage = ConfigStorage::default();

        let parties = vec![KmsCoreParty::default(); 4];
        let response_count_for_majority_vote = 3;
        let response_count_for_reconstruction = 4;
        let degree_for_reconstruction = 1;

        // Set all the configuration parameters
        set_all_config_parameters(
            &mut storage,
            dyn_store,
            parties.clone(),
            response_count_for_majority_vote,
            response_count_for_reconstruction,
            degree_for_reconstruction,
        )
        .unwrap();

        // Test get
        assert_eq!(
            storage
                .get_response_count_for_majority_vote(dyn_store)
                .unwrap(),
            response_count_for_majority_vote
        );

        // Test that updating with a conformant value succeeds
        let correct_count = 4;
        let updated_count = storage
            .update_response_count_for_majority_vote(dyn_store, correct_count)
            .unwrap();
        assert_eq!(updated_count, correct_count);
    }

    #[test]
    fn test_response_count_for_reconstruction() {
        let dyn_store = &mut MockStorage::new();
        let mut storage = ConfigStorage::default();

        let parties = vec![KmsCoreParty::default(); 4];
        let response_count_for_majority_vote = 3;
        let response_count_for_reconstruction = 4;
        let degree_for_reconstruction = 1;

        // Set all the configuration parameters
        set_all_config_parameters(
            &mut storage,
            dyn_store,
            parties.clone(),
            response_count_for_majority_vote,
            response_count_for_reconstruction,
            degree_for_reconstruction,
        )
        .unwrap();

        // Test get
        assert_eq!(
            storage
                .get_response_count_for_reconstruction(dyn_store)
                .unwrap(),
            response_count_for_reconstruction
        );

        // Test that updating with a non-conformant value properly fails
        let wrong_count = 6;
        assert!(storage
            .update_response_count_for_reconstruction(dyn_store, wrong_count)
            .unwrap_err()
            .to_string()
            .contains("KMS configuration is not conformant"));

        // Test that updating with a conformant value succeeds
        let correct_count = 4;
        let updated_count = storage
            .update_response_count_for_reconstruction(dyn_store, correct_count)
            .unwrap();
        assert_eq!(updated_count, correct_count);
    }

    #[test]
    fn test_degree_for_reconstruction() {
        let dyn_store = &mut MockStorage::new();
        let mut storage = ConfigStorage::default();

        let parties = vec![KmsCoreParty::default(); 4];
        let response_count_for_majority_vote = 3;
        let response_count_for_reconstruction = 4;
        let degree_for_reconstruction = 1;

        // Set all the configuration parameters
        set_all_config_parameters(
            &mut storage,
            dyn_store,
            parties.clone(),
            response_count_for_majority_vote,
            response_count_for_reconstruction,
            degree_for_reconstruction,
        )
        .unwrap();

        // Test get
        assert_eq!(
            storage.get_degree_for_reconstruction(dyn_store).unwrap(),
            degree_for_reconstruction
        );

        // Test that updating with a non-conformant value properly fails
        let wrong_degree = 2;
        assert!(storage
            .update_degree_for_reconstruction(dyn_store, wrong_degree)
            .unwrap_err()
            .to_string()
            .contains("KMS configuration is not conformant"));

        // Test that updating with a conformant value succeeds
        let correct_degree = 1;
        let updated_degree = storage
            .update_degree_for_reconstruction(dyn_store, correct_degree)
            .unwrap();
        assert_eq!(updated_degree, correct_degree);
    }

    #[test]
    fn test_param_choice() {
        let dyn_store = &mut MockStorage::new();
        let storage = ConfigStorage::default();

        let param = FheParameter::Test;

        // Test set
        storage.set_param_choice(dyn_store, param).unwrap();

        // Test get
        assert_eq!(storage.get_param_choice(dyn_store).unwrap(), param);

        // Test update
        let new_param = FheParameter::Default;
        let updated_param = storage.update_param_choice(dyn_store, new_param).unwrap();
        assert_eq!(updated_param, new_param);
    }

    #[test]
    fn test_storage_base_urls() {
        let dyn_store = &mut MockStorage::new();
        let storage = ConfigStorage::default();

        let urls = vec!["url1".to_string(), "url2".to_string()];

        // Test set
        storage
            .set_storage_base_urls(dyn_store, urls.clone())
            .unwrap();

        // Test get
        assert_eq!(storage.get_storage_base_urls(dyn_store).unwrap(), urls);

        // Test update
        let new_urls = vec!["url3".to_string(), "url4".to_string()];
        let updated_urls = storage
            .update_storage_base_urls(dyn_store, new_urls.clone())
            .unwrap();
        assert_eq!(updated_urls, new_urls);
    }
}
