use crate::state::ConfigStorage;
use events::kms::{ConfigurationUpdatedEvent, KmsConfig};

use contracts_common::{
    allowlists::{AllowlistsContractManager, AllowlistsManager, AllowlistsStateManager},
    migrations::Migration,
};

use cosmwasm_std::{Response, StdResult};
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
    ///
    /// # Arguments
    /// * `kms_configuration` - the KMS's configuration
    /// * `storage_base_urls` - the list of storage base URLs
    /// * `allowlists` - an optional struct containing several lists of addresses that define
    /// who can trigger some operations (mostly about updating the configuration or allowlists).
    /// Providing None will default to use the sender's address for all operation types.
    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        kms_configuration: KmsConfig,
        storage_base_urls: Vec<String>,
        allowlists: Option<Allowlists>,
    ) -> StdResult<Response> {
        // Check conformance of centralized or threshold config
        if !kms_configuration.is_conformant() {
            return Err(cosmwasm_std::StdError::generic_err(
                "KMS configuration is not conformant.",
            ));
        }

        // Set all the configuration values
        self.storage
            .set_kms_configuration(ctx.deps.storage, kms_configuration)?;

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
    pub fn get_kms_configuration(&self, ctx: QueryCtx) -> StdResult<KmsConfig> {
        self.storage.get_kms_configuration(ctx.deps.storage)
    }

    /// Get the list of storage base URLs
    #[sv::msg(query)]
    pub fn get_storage_base_urls(&self, ctx: QueryCtx) -> StdResult<Vec<String>> {
        self.storage.get_storage_base_urls(ctx.deps.storage)
    }

    /// Update the KMS's configuration
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    /// Additionally, it is currently not allowed to change the number of parties participating.
    #[sv::msg(exec)]
    pub fn update_kms_configuration(&self, ctx: ExecCtx, value: KmsConfig) -> StdResult<Response> {
        let operation = "update_kms_configuration";

        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Configure, operation)?;

        self.storage
            .update_kms_configuration(ctx.deps.storage, value.clone())?;

        let configuration_updated_event = ConfigurationUpdatedEvent::new(
            operation.to_string(),
            self.storage.get_kms_configuration(ctx.deps.storage)?,
            value,
        );

        let response = Response::new()
            .add_event(sender_allowed_event)
            .add_event(configuration_updated_event);
        Ok(response)
    }

    /// Update the list of storage base URLs
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn update_storage_base_urls(
        &self,
        ctx: ExecCtx,
        value: Vec<String>,
    ) -> StdResult<Response> {
        let operation = "update_storage_base_urls";

        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Configure, operation)?;

        self.storage
            .update_storage_base_urls(ctx.deps.storage, value.clone())?;

        let configuration_updated_event = ConfigurationUpdatedEvent::new(
            operation.to_string(),
            self.storage
                .get_storage_base_urls(ctx.deps.storage)?
                .join(","),
            value.join(","),
        );

        let response = Response::new()
            .add_event(sender_allowed_event)
            .add_event(configuration_updated_event);
        Ok(response)
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
    use events::kms::{FheParameter, KmsConfig, KmsCoreParty};
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
                KmsConfig {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 2,
                    param_choice: FheParameter::Test,
                },
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .is_err());

        // Instantiation should fail because `response_count_for_majority_vote` is greater than the no. of parties
        assert!(code_id
            .instantiate(
                KmsConfig {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 5,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .is_err());

        // Instantiation should fail because `response_count_for_reconstruction` is greater than the no. of parties
        assert!(code_id
            .instantiate(
                KmsConfig {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 5,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .is_err());

        // Instantiation should succeed
        let contract = code_id
            .instantiate(
                KmsConfig {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        // Get the KMS configuration
        let value = contract.get_kms_configuration();
        assert!(value.is_ok());
    }

    /// Test to update the KMS configuration
    #[test]
    fn test_update_kms_configuration() {
        let (app, owner) = setup_test_env();

        let code_id = CodeId::store_code(&app);

        let contract = code_id
            .instantiate(
                KmsConfig {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                vec![DUMMY_STORAGE_BASE_URL.to_string()],
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let new_kms_configuration = KmsConfig {
            parties: vec![KmsCoreParty::default(); 4],
            response_count_for_majority_vote: 3,
            response_count_for_reconstruction: 3,
            degree_for_reconstruction: 1,
            param_choice: FheParameter::Test,
        };

        let response = contract
            .update_kms_configuration(new_kms_configuration.clone())
            .call(&owner)
            .unwrap();

        // Check we have 3 events:
        // - 1 for the execution
        // - 1 for the sender allowed
        // - 1 for the configuration updated
        assert_eq!(response.events.len(), 3);

        let result = contract.get_kms_configuration().unwrap();
        assert_eq!(result, new_kms_configuration);
    }

    /// Test to update the storage base URLs
    #[test]
    fn test_update_storage_base_urls() {
        let (app, owner) = setup_test_env();

        let code_id = CodeId::store_code(&app);

        let old_base_urls = vec![
            "https://old_storage1.example.com".to_string(),
            "https://old_storage2.example.com".to_string(),
        ];

        let contract = code_id
            .instantiate(
                KmsConfig {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                old_base_urls.clone(),
                Some(AllowlistsCsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let new_base_urls = vec![
            "https://new_storage1.example.com".to_string(),
            "https://new_storage2.example.com".to_string(),
        ];

        let response = contract
            .update_storage_base_urls(new_base_urls.clone())
            .call(&owner)
            .unwrap();

        // Check we have 3 events:
        // - 1 for the execution
        // - 1 for the sender allowed
        // - 1 for the configuration updated
        assert_eq!(response.events.len(), 3);

        let result = contract.get_storage_base_urls().unwrap();
        assert_eq!(result, new_base_urls);
    }
}
