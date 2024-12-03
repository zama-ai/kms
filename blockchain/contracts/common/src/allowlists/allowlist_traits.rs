use cosmwasm_std::{Api, StdError};
use strum::IntoEnumIterator;

use super::{Admins, AdminsOperations};

pub trait GetAdminType {
    fn get_admin_type() -> Self;
}

/// Manage different types of allowlists
pub trait AllowlistsManager {
    /// Enum that defines the different operation types handled by the AllowlistsManager struct
    type AllowlistType: IntoEnumIterator + Clone + std::fmt::Display + GetAdminType;

    /// Get the list of addresses for the given operation type
    fn get_addresses(&self, address_type: Self::AllowlistType) -> &Admins;

    /// Get a mutable reference to the list of addresses for the given operation type
    fn get_addresses_mut(&mut self, address_type: Self::AllowlistType) -> &mut Admins;

    /// Instantiate all allowlists and default them all to the given address
    fn default_all_to(addr: &str) -> Self;

    /// Check that addresses of all operation types are valid
    fn check_all_addresses_are_valid(&self, cosmwasm_api: &dyn Api) -> Result<(), StdError> {
        for address_type in Self::AllowlistType::iter() {
            let addresses = self.get_addresses(address_type.clone());

            addresses
                .check_is_valid(cosmwasm_api)
                .map_err(|e| StdError::generic_err(format!("Type `{}`: {}", address_type, e)))?;
        }
        Ok(())
    }
}
