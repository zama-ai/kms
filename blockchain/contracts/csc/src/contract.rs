#![allow(clippy::too_many_arguments)]

use crate::state::ConfigStorage;
use events::kms::{ConfigurationUpdatedEvent, FheParameter, KmsCoreParty};

use contracts_common::{
    allowlists::{AllowlistsContractManager, AllowlistsManager, AllowlistsStateManager},
    migrations::Migration,
};

use cosmwasm_std::{Response, StdResult, Storage};
use cw2::set_contract_version;

use sylvia::{
    contract, entry_points,
    types::{ExecCtx, InstantiateCtx, MigrateCtx, QueryCtx},
};

// Info for migration
const CONTRACT_NAME: &str = "kms-config";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

// Type aliases for the allowlists and operation types to use in the CSC
// We recover them from the storage for better maintainability
type Allowlists = <ConfigStorage as AllowlistsStateManager>::Allowlists;
type AllowlistType = <Allowlists as AllowlistsManager>::AllowlistType;

#[derive(Default)]
pub struct ConfigurationContract {
    pub(crate) storage: ConfigStorage,
}

/// Implement the `AllowlistsContractManager` trait
///
/// This allows to check that the sender is allowed to trigger a given operation
impl AllowlistsContractManager for ConfigurationContract {
    type Allowlists = Allowlists;

    fn storage(&self) -> &dyn AllowlistsStateManager<Allowlists = Allowlists> {
        &self.storage
    }
}

/// Implement the `Migration` trait
///
/// This allows to migrate the contract's state from an old version to a new version, without
/// changing its address. This will automatically use versioning to ensure compatibility between
/// versions
impl Migration for ConfigurationContract {}

#[entry_points]
#[contract]
impl ConfigurationContract {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configuration Smart Contract instantiation
    ///
    /// It can be used to represent both the centralized and threshold case.
    ///
    /// # Arguments
    /// * `parties` - the list of core parties and their associated information (id, public key, address, TLS public key)
    /// * `response_count_for_majority_vote` - the number of responses needed for majority voting
    /// (used for sending responses to the client with all operations except reencryption)
    /// * `response_count_for_reconstruction` - the number of responses needed for reconstruction
    /// (used for sending responses to the client with reencryption operations)
    /// * `degree_for_reconstruction` - the degree of the polynomial for reconstruction
    /// (used for checking majority and conformance)
    /// * `param_choice` - the FHE parameter choice (either default or test)
    /// * `storage_base_urls` - the list of storage base URLs
    /// * `allowlists` - an optional struct containing several lists of addresses that define
    /// who can trigger some operations (mostly about updating the configuration or allowlists).
    /// Providing None will default to use the sender's address for all operation types.
    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        parties: Vec<KmsCoreParty>,
        response_count_for_majority_vote: usize,
        response_count_for_reconstruction: usize,
        degree_for_reconstruction: usize,
        param_choice: FheParameter,
        storage_base_urls: Vec<String>,
        allowlists: Option<Allowlists>,
    ) -> StdResult<Response> {
        // Check that the configuration parameters are conformant
        ConfigStorage::check_config_is_conformant(
            parties.clone(),
            response_count_for_majority_vote,
            response_count_for_reconstruction,
            degree_for_reconstruction,
        )?;

        // Set all the configuration parameters
        self.storage.set_parties(ctx.deps.storage, parties)?;
        self.storage.set_response_count_for_majority_vote(
            ctx.deps.storage,
            response_count_for_majority_vote,
        )?;
        self.storage.set_response_count_for_reconstruction(
            ctx.deps.storage,
            response_count_for_reconstruction,
        )?;
        self.storage
            .set_degree_for_reconstruction(ctx.deps.storage, degree_for_reconstruction)?;

        // Set the FHE parameter choice
        self.storage
            .set_param_choice(ctx.deps.storage, param_choice)?;

        // Set the storage base URLs
        self.storage
            .set_storage_base_urls(ctx.deps.storage, storage_base_urls)?;

        // Configure allowlists for some operations
        let allowlists = match allowlists {
            Some(addresses) => {
                addresses.check_all_addresses_are_valid(ctx.deps.api)?;
                addresses
            }
            None => {
                // Default to only allowing the contract instantiator
                Allowlists::default_all_to(ctx.info.sender.as_str())
            }
        };

        self.storage.set_allowlists(ctx.deps.storage, allowlists)?;

        // Set contract version
        set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        Ok(Response::default())
    }

    /// Get the list of core parties participating in the KMS
    #[sv::msg(query)]
    pub fn get_parties(&self, ctx: QueryCtx) -> StdResult<Vec<KmsCoreParty>> {
        self.storage.get_parties(ctx.deps.storage)
    }

    /// Update the configuration value for the given operation
    ///
    /// This includes checking that the sender is allowed to trigger the operation, and emitting
    /// the corresponding events.
    /// If a config parameter will make the overall configuration non-conformant, an error will be
    /// thrown and the configuration will not be updated.
    fn update_config<T: std::fmt::Debug + Clone>(
        &self,
        ctx: &mut ExecCtx,
        operation: &str,
        value: T,
        get_old: impl FnOnce(&mut dyn Storage) -> StdResult<T>,
        update: impl FnOnce(&mut dyn Storage, T) -> StdResult<T>,
    ) -> StdResult<Response> {
        let sender_allowed_event =
            self.check_sender_is_allowed(ctx, AllowlistType::Configure, operation)?;

        let old_value = get_old(ctx.deps.storage)?;
        let new_value = update(ctx.deps.storage, value)?;

        let configuration_updated_event = ConfigurationUpdatedEvent::new(
            operation.to_string(),
            format!("{:?}", old_value),
            format!("{:?}", new_value),
        );

        let response = Response::new()
            .add_event(sender_allowed_event)
            .add_event(configuration_updated_event);
        Ok(response)
    }

    /// Update the list of core parties
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn update_parties(
        &self,
        mut ctx: ExecCtx,
        value: Vec<KmsCoreParty>,
    ) -> StdResult<Response> {
        self.update_config(
            &mut ctx,
            "update_parties",
            value,
            |storage| self.storage.get_parties(storage),
            |storage, value| self.storage.update_parties(storage, value),
        )
    }

    /// Get the number of responses needed for majority voting
    #[sv::msg(query)]
    pub fn get_response_count_for_majority_vote(&self, ctx: QueryCtx) -> StdResult<usize> {
        self.storage
            .get_response_count_for_majority_vote(ctx.deps.storage)
    }

    /// Update the number of responses needed for majority voting
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn update_response_count_for_majority_vote(
        &self,
        mut ctx: ExecCtx,
        value: usize,
    ) -> StdResult<Response> {
        self.update_config(
            &mut ctx,
            "update_response_count_for_majority_vote",
            value,
            |storage| self.storage.get_response_count_for_majority_vote(storage),
            |storage, value| {
                self.storage
                    .update_response_count_for_majority_vote(storage, value)
            },
        )
    }

    /// Get the number of responses needed for reconstruction
    #[sv::msg(query)]
    pub fn get_response_count_for_reconstruction(&self, ctx: QueryCtx) -> StdResult<usize> {
        self.storage
            .get_response_count_for_reconstruction(ctx.deps.storage)
    }

    /// Update the number of responses needed for reconstruction
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn update_response_count_for_reconstruction(
        &self,
        mut ctx: ExecCtx,
        value: usize,
    ) -> StdResult<Response> {
        self.update_config(
            &mut ctx,
            "update_response_count_for_reconstruction",
            value,
            |storage| self.storage.get_response_count_for_reconstruction(storage),
            |storage, value| {
                self.storage
                    .update_response_count_for_reconstruction(storage, value)
            },
        )
    }

    /// Get the degree of the polynomial for reconstruction
    #[sv::msg(query)]
    pub fn get_degree_for_reconstruction(&self, ctx: QueryCtx) -> StdResult<usize> {
        self.storage.get_degree_for_reconstruction(ctx.deps.storage)
    }

    /// Update the degree of the polynomial for reconstruction
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn update_degree_for_reconstruction(
        &self,
        mut ctx: ExecCtx,
        value: usize,
    ) -> StdResult<Response> {
        self.update_config(
            &mut ctx,
            "update_degree_for_reconstruction",
            value,
            |storage| self.storage.get_degree_for_reconstruction(storage),
            |storage, value| {
                self.storage
                    .update_degree_for_reconstruction(storage, value)
            },
        )
    }

    /// Get the FHE parameter choice
    #[sv::msg(query)]
    pub fn get_param_choice(&self, ctx: QueryCtx) -> StdResult<FheParameter> {
        self.storage.get_param_choice(ctx.deps.storage)
    }

    /// Update the FHE parameter choice
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn update_param_choice(
        &self,
        mut ctx: ExecCtx,
        value: FheParameter,
    ) -> StdResult<Response> {
        self.update_config(
            &mut ctx,
            "update_param_choice",
            value,
            |storage| self.storage.get_param_choice(storage),
            |storage, value| self.storage.update_param_choice(storage, value),
        )
    }

    /// Get the list of storage base URLs
    #[sv::msg(query)]
    pub fn get_storage_base_urls(&self, ctx: QueryCtx) -> StdResult<Vec<String>> {
        self.storage.get_storage_base_urls(ctx.deps.storage)
    }

    /// Update the list of storage base URLs
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn update_storage_base_urls(
        &self,
        mut ctx: ExecCtx,
        value: Vec<String>,
    ) -> StdResult<Response> {
        self.update_config(
            &mut ctx,
            "update_storage_base_urls",
            value,
            |storage| self.storage.get_storage_base_urls(storage),
            |storage, value| self.storage.update_storage_base_urls(storage, value),
        )
    }

    /// Allow an address to trigger the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn add_allowlist(
        &self,
        ctx: ExecCtx,
        address: String,
        operation_type: AllowlistType,
    ) -> StdResult<Response> {
        self.impl_add_allowlist(ctx, address, operation_type)
    }

    /// Forbid an address from triggering the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn remove_allowlist(
        &self,
        ctx: ExecCtx,
        address: String,
        operation_type: AllowlistType,
    ) -> StdResult<Response> {
        self.impl_remove_allowlist(ctx, address, operation_type)
    }

    /// Replace all of the allowlists for the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn replace_allowlists(
        &self,
        ctx: ExecCtx,
        addresses: Vec<String>,
        operation_type: AllowlistType,
    ) -> StdResult<Response> {
        self.impl_replace_allowlists(ctx, addresses, operation_type)
    }

    /// Function to migrate from old version to new version
    ///
    /// As there is only one version of the contract for now, this function has no real use. Future
    /// versions of the contract will be required to provide this function, with additional migration
    /// logic if needed. This might include changing the function's signature.
    #[sv::msg(migrate)]
    fn migrate(&self, ctx: MigrateCtx) -> StdResult<Response> {
        self.apply_migration(ctx.deps.storage)
    }
}

#[cfg(test)]
mod tests {
    use super::sv::mt::ConfigurationContractProxy;
    use crate::{allowlists::AllowlistsCsc, contract::sv::mt::CodeId};
    use contracts_common::allowlists::AllowlistsManager;
    use cosmwasm_std::Addr;
    use cw_multi_test::{App as MtApp, IntoAddr as _};
    use events::kms::{FheParameter, KmsCoreParty};
    use sylvia::multitest::App;
    const DUMMY_STORAGE_BASE_URL: &str = "https://dummy-storage-base-url.example.com";

    fn setup_test_env() -> (App<MtApp>, Addr) {
        let app = App::default();
        let owner = "owner".into_addr();

        (app, owner)
    }

    /// Test the contract instantiation
    #[test]
    fn test_instantiate() {
        let (app, owner) = setup_test_env();

        let code_id = CodeId::store_code(&app);

        // Instantiation should fail because `degree_for_reconstruction` is too high
        assert!(code_id
            .instantiate(
                vec![KmsCoreParty::default(); 4],
                3,
                3,
                2,
                FheParameter::Test,
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .is_err());

        // Instantiation should fail because `response_count_for_majority_vote` is greater than the
        // number of parties
        assert!(code_id
            .instantiate(
                vec![KmsCoreParty::default(); 4],
                5,
                3,
                1,
                FheParameter::Test,
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .is_err());

        // Instantiation should fail because `response_count_for_reconstruction` is greater than the
        // number of parties
        assert!(code_id
            .instantiate(
                vec![KmsCoreParty::default(); 4],
                3,
                5,
                1,
                FheParameter::Test,
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .is_err());

        // Instantiation should succeed
        code_id
            .instantiate(
                vec![KmsCoreParty::default(); 4],
                3,
                3,
                1,
                FheParameter::Test,
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();
    }

    /// Test the storage base URLs
    #[test]
    fn test_storage_base_urls() {
        let (app, owner) = setup_test_env();

        let code_id = CodeId::store_code(&app);

        let old_base_urls = vec![
            "https://old_storage1.example.com".to_string(),
            "https://old_storage2.example.com".to_string(),
        ];

        let contract = code_id
            .instantiate(
                vec![KmsCoreParty::default(); 4],
                3,
                3,
                1,
                FheParameter::Test,
                old_base_urls.clone(),
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let new_base_urls = vec![
            "https://new_storage1.example.com".to_string(),
            "https://new_storage2.example.com".to_string(),
        ];

        // Test update method
        let response = contract
            .update_storage_base_urls(new_base_urls.clone())
            .call(&owner)
            .unwrap();

        // Check we have 3 events:
        // - 1 for the execution
        // - 1 for the sender allowed
        // - 1 for the configuration updated
        assert_eq!(response.events.len(), 3);

        // Test getter method
        let result = contract.get_storage_base_urls().unwrap();
        assert_eq!(result, new_base_urls);
    }

    /// Test updating parties
    #[test]
    fn test_parties() {
        let (app, owner) = setup_test_env();

        let code_id = CodeId::store_code(&app);

        let old_parties = vec![KmsCoreParty::default(); 4];

        let contract = code_id
            .instantiate(
                old_parties.clone(),
                3,
                3,
                1,
                FheParameter::Test,
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let new_parties = vec![KmsCoreParty::default(); 4];

        // Test update method
        let response = contract
            .update_parties(new_parties.clone())
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 3);

        // Test getter method
        let result = contract.get_parties().unwrap();
        assert_eq!(result, new_parties);

        // Test that modifying the number of parties is not allowed
        assert!(contract
            .update_parties(vec![KmsCoreParty::default(); 5])
            .call(&owner)
            .unwrap_err()
            .to_string()
            .contains("Updating the core parties failed:"));
    }

    /// Test updating response count for majority vote
    #[test]
    fn test_response_count_for_majority_vote() {
        let (app, owner) = setup_test_env();

        let code_id = CodeId::store_code(&app);

        let contract = code_id
            .instantiate(
                vec![KmsCoreParty::default(); 4],
                3,
                3,
                1,
                FheParameter::Test,
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let new_count = 3;

        // Test update method
        let response = contract
            .update_response_count_for_majority_vote(new_count)
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 3);

        // Test getter method
        let result = contract.get_response_count_for_majority_vote().unwrap();
        assert_eq!(result, new_count);
    }

    /// Test updating response count for reconstruction
    #[test]
    fn test_response_count_for_reconstruction() {
        let (app, owner) = setup_test_env();

        let code_id = CodeId::store_code(&app);

        let contract = code_id
            .instantiate(
                vec![KmsCoreParty::default(); 4],
                3,
                3,
                1,
                FheParameter::Test,
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let new_count = 3;

        // Test update method
        let response = contract
            .update_response_count_for_reconstruction(new_count)
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 3);

        // Test getter method
        let result = contract.get_response_count_for_reconstruction().unwrap();
        assert_eq!(result, new_count);
    }

    /// Test updating degree for reconstruction
    #[test]
    fn test_degree_for_reconstruction() {
        let (app, owner) = setup_test_env();

        let code_id = CodeId::store_code(&app);

        let contract = code_id
            .instantiate(
                vec![KmsCoreParty::default(); 4],
                3,
                3,
                1,
                FheParameter::Test,
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let new_degree = 1;

        // Test update method
        let response = contract
            .update_degree_for_reconstruction(new_degree)
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 3);

        // Test getter method
        let result = contract.get_degree_for_reconstruction().unwrap();
        assert_eq!(result, new_degree);
    }

    /// Test updating FHE parameters
    #[test]
    fn test_param_choice() {
        let (app, owner) = setup_test_env();

        let code_id = CodeId::store_code(&app);

        let contract = code_id
            .instantiate(
                vec![KmsCoreParty::default(); 4],
                3,
                3,
                1,
                FheParameter::Test,
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let new_param = FheParameter::Test;

        // Test update method
        let response = contract
            .update_param_choice(new_param)
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 3);

        // Test getter method
        let result = contract.get_param_choice().unwrap();
        assert_eq!(result, new_param);
    }
}
