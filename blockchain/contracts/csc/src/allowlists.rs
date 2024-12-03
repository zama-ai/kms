use cosmwasm_schema::cw_serde;
use strum_macros::{Display, EnumIter};
use tfhe_versionable::{Versionize, VersionsDispatch};

use contracts_common::allowlists::{Admins, AdminsOperations, AllowlistsManager, GetAdminType};

#[derive(VersionsDispatch)]
pub enum AllowlistTypeCscVersioned {
    V0(AllowlistTypeCsc),
}

/// The types of operations that are only allowed to be triggered by certain addresses in the config
/// contract.
///
/// This enum is closely bound to the `AllowlistsCsc` struct: all its variants are matching
/// the `AllowlistsCsc`'s fields.
#[cw_serde]
#[derive(Versionize, EnumIter, Display)]
#[versionize(AllowlistTypeCscVersioned)]
pub enum AllowlistTypeCsc {
    Admin,     // Allowed to update allowlists of any type
    Configure, // Allowed to update values in the CSC
}

impl GetAdminType for AllowlistTypeCsc {
    fn get_admin_type() -> Self {
        Self::Admin
    }
}

#[derive(VersionsDispatch)]
pub enum AllowlistsCscVersioned {
    V0(AllowlistsCsc),
}

/// This struct contains two lists of addresses meant to restrict who is allowed to trigger certain
/// operations in the CSC:
/// - `admins`: who is allowed to update allowlists of any type
/// - `configure`: who is allowed to update values in the CSC
/// All the given addresses should be valid.
#[cw_serde]
#[derive(Versionize)]
#[versionize(AllowlistsCscVersioned)]
pub struct AllowlistsCsc {
    pub admin: Admins,
    pub configure: Admins,
}

impl AllowlistsManager for AllowlistsCsc {
    type AllowlistType = AllowlistTypeCsc;

    /// Create a new list of allowlists with only the given address.
    fn default_all_to(addr: &str) -> Self {
        Self {
            admin: Admins::default_to(addr),
            configure: Admins::default_to(addr),
        }
    }

    /// Get the list of addresses for the given operation type.
    fn get_addresses(&self, address_type: AllowlistTypeCsc) -> &Admins {
        // This destructuring is necessary to make sure the `AllowlistsCsc` struct is properly
        // bound to the `AllowlistTypeCsc` enum.
        // This forces us to update this method if:
        // - `AllowlistsCsc` has a new field
        // - `AllowlistTypeCsc` has a new variant
        let Self { admin, configure } = self;

        match address_type {
            AllowlistTypeCsc::Admin => admin,
            AllowlistTypeCsc::Configure => configure,
        }
    }

    /// Get a mutable reference to the list of addresses for the given operation type.
    ///
    /// This is useful for updating the list of addresses.
    fn get_addresses_mut(&mut self, address_type: AllowlistTypeCsc) -> &mut Admins {
        let Self { admin, configure } = self;
        match address_type {
            AllowlistTypeCsc::Admin => admin,
            AllowlistTypeCsc::Configure => configure,
        }
    }
}
