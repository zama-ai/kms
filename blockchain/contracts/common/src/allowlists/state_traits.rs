use crate::{
    allowlists::{AdminsOperations, AllowlistsManager},
    versioned_states::VersionedItem,
};
use cosmwasm_std::{Api, StdError, StdResult, Storage};
use serde::de::DeserializeOwned;
use tfhe_versionable::Unversionize;

/// Manage allowlists in a contract's state.
pub trait AllowlistsStateManager {
    type Allowlists: DeserializeOwned + Unversionize + Clone + AllowlistsManager;

    fn allowlists(&self) -> &VersionedItem<Self::Allowlists>;

    /// Set allowlists.
    ///
    /// Some exec operations must not be accessible to anyone. To allow some finer-grain control
    /// on who can launch said operations the contract holds several lists of addresses of who can
    /// call these operations
    fn set_allowlists(
        &self,
        storage: &mut dyn Storage,
        allowlists: Self::Allowlists,
    ) -> StdResult<()> {
        self.allowlists().save(storage, &allowlists)
    }

    /// Check that the given address is allowed to trigger the given operation type
    fn check_address_is_allowed(
        &self,
        storage: &dyn Storage,
        address: &str,
        operation_type: <Self::Allowlists as AllowlistsManager>::AllowlistType,
    ) -> Result<(), cosmwasm_std::StdError> {
        let allowlists = self.allowlists().load(storage)?;
        allowlists
            .get_addresses(operation_type.clone())
            .check_is_allowed(address)
            .map_err(|e| StdError::generic_err(format!("Type `{}`: {}", operation_type, e)))
    }

    /// Allow an address to trigger the given operation type
    fn add_allowlist(
        &self,
        storage: &mut dyn Storage,
        address: &str,
        operation_type: <Self::Allowlists as AllowlistsManager>::AllowlistType,
        cosmwasm_api: &dyn Api,
    ) -> StdResult<()> {
        self.allowlists().update(storage, |mut allowlists| {
            allowlists
                .get_addresses_mut(operation_type.clone())
                .add_allowed(address.to_string(), cosmwasm_api)
                .map_err(|e| StdError::generic_err(format!("Type `{}`: {}", operation_type, e)))?;
            Ok(allowlists) as Result<Self::Allowlists, StdError>
        })?;
        Ok(())
    }

    /// Forbid an address from triggering the given operation type
    fn remove_allowlist(
        &self,
        storage: &mut dyn Storage,
        address: &str,
        operation_type: <Self::Allowlists as AllowlistsManager>::AllowlistType,
    ) -> StdResult<()> {
        self.allowlists().update(storage, |mut allowlists| {
            allowlists
                .get_addresses_mut(operation_type.clone())
                .remove_allowed(address)
                .map_err(|e| StdError::generic_err(format!("Type `{}`: {}", operation_type, e)))?;
            Ok(allowlists) as Result<Self::Allowlists, StdError>
        })?;
        Ok(())
    }

    /// Replace all of the allowlists for the given operation type
    fn replace_allowlists(
        &self,
        storage: &mut dyn Storage,
        addresses: Vec<String>,
        operation_type: <Self::Allowlists as AllowlistsManager>::AllowlistType,
        cosmwasm_api: &dyn Api,
    ) -> StdResult<()> {
        self.allowlists().update(storage, |mut allowlists| {
            allowlists
                .get_addresses_mut(operation_type.clone())
                .replace_allowed(addresses, cosmwasm_api)
                .map_err(|e| StdError::generic_err(format!("Type `{}`: {}", operation_type, e)))?;
            Ok(allowlists) as Result<Self::Allowlists, StdError>
        })?;
        Ok(())
    }
}
