use cosmwasm_schema::cw_serde;
use strum_macros::{Display, EnumIter};
use tfhe_versionable::{Versionize, VersionsDispatch};

use contracts_common::allowlists::{Admins, AdminsOperations, AllowlistsManager, GetAdminType};

#[derive(VersionsDispatch)]
pub enum AllowlistTypeAscVersioned {
    V0(AllowlistTypeAsc),
}

/// The types of operations that are only allowed to be triggered by certain addresses in the ASC.
///
/// This enum is closely bound to the `AllowlistsAsc` struct: all its variants are matching
/// the `AllowlistsAsc`'s fields.
#[cw_serde]
#[derive(Versionize, EnumIter, Display)]
#[versionize(AllowlistTypeAscVersioned)]
pub enum AllowlistTypeAsc {
    Admin,    // Allowed to update allowlists of any type
    Generate, // Allowed to trigger gen calls (ex: `keygen`, `crs_gen`)
    Response, // Allowed to trigger response calls (ex: `decrypt_response`, `keygen_response`)
}

impl GetAdminType for AllowlistTypeAsc {
    fn get_admin_type() -> Self {
        Self::Admin
    }
}

#[derive(VersionsDispatch)]
pub enum AllowlistsAscVersioned {
    V0(AllowlistsAsc),
}

/// This struct contains two lists of addresses meant to restrict who can trigger certain operations
/// in the ASC:
/// - `admins`: who is allowed to update allowlists of any type
/// - `generate`: who is allowed to trigger any gen calls (ex: `keygen`, `crs_gen`)
/// - `response`: who is allowed to trigger all response calls (ex: `decrypt_response`, `keygen_response`)
/// All the given addresses should be valid.
#[cw_serde]
#[derive(Versionize)]
#[versionize(AllowlistsAscVersioned)]
pub struct AllowlistsAsc {
    pub generate: Admins,
    pub response: Admins,
    pub admin: Admins,
}

impl AllowlistsManager for AllowlistsAsc {
    type AllowlistType = AllowlistTypeAsc;

    /// Create a new list of allowlists with only the given address.
    fn default_all_to(addr: &str) -> Self {
        Self {
            generate: Admins::default_to(addr),
            response: Admins::default_to(addr),
            admin: Admins::default_to(addr),
        }
    }

    /// Get the list of addresses for the given operation type.
    fn get_addresses(&self, address_type: AllowlistTypeAsc) -> &Admins {
        // This destructuring is necessary to make sure the `AllowlistsAsc` struct is properly
        // bound to the `AllowlistTypeAsc` enum.
        // This forces us to update this method if:
        // - `AllowlistsAsc` has a new field
        // - `AllowlistTypeAsc` has a new variant
        let Self {
            generate,
            response,
            admin,
        } = self;

        match address_type {
            AllowlistTypeAsc::Generate => generate,
            AllowlistTypeAsc::Response => response,
            AllowlistTypeAsc::Admin => admin,
        }
    }

    /// Get a mutable reference to the list of addresses for the given operation type.
    ///
    /// This is useful for updating the list of addresses.
    fn get_addresses_mut(&mut self, address_type: AllowlistTypeAsc) -> &mut Admins {
        let Self {
            generate,
            response,
            admin,
        } = self;
        match address_type {
            AllowlistTypeAsc::Generate => generate,
            AllowlistTypeAsc::Response => response,
            AllowlistTypeAsc::Admin => admin,
        }
    }
}
