use contracts_common::allowlists::{Admins, AdminsOperations, AllowlistsManager, GetAdminType};
use cosmwasm_schema::cw_serde;
use strum_macros::{Display, EnumIter};
use tfhe_versionable::{Versionize, VersionsDispatch};

#[derive(VersionsDispatch)]
pub enum AllowlistTypeBscVersioned {
    V0(AllowlistTypeBsc),
}

/// The types of operations that are only allowed to be triggered by certain addresses in the BSC.
///
/// This enum is closely bound to the `AllowlistsBsc` struct: all its variants are matching
/// the `AllowlistsBsc`'s fields.
#[cw_serde]
#[derive(Versionize, EnumIter, Display)]
#[versionize(AllowlistTypeBscVersioned)]
pub enum AllowlistTypeBsc {
    Admin,    // Allowed to update allowlists of any type
    Generate, // Allowed to trigger gen calls (ex: `keygen`, `crs_gen`)
    Response, // Allowed to trigger response calls (ex: `decrypt_response`, `keygen_response`)
}

impl GetAdminType for AllowlistTypeBsc {
    fn get_admin_type() -> Self {
        Self::Admin
    }
}

#[derive(VersionsDispatch)]
pub enum AllowlistsBscVersioned {
    V0(AllowlistsBsc),
}

/// This struct contains two lists of addresses meant to restrict who can trigger certain operations
/// in the BSC:
/// - `admins`: who is allowed to update allowlists of any type
/// - `generate`: who is allowed to trigger any gen calls (ex: `key_generation`, `crs_generation`)
/// - `response`: who is allowed to trigger all response calls (ex: `decryption_response`, `key_generation_response`)
/// All the given addresses should be valid.
#[cw_serde]
#[derive(Versionize)]
#[versionize(AllowlistsBscVersioned)]
pub struct AllowlistsBsc {
    pub generate: Admins,
    pub response: Admins,
    pub admin: Admins,
}

impl AllowlistsManager for AllowlistsBsc {
    type AllowlistType = AllowlistTypeBsc;

    /// Create a new list of allowlists with only the given address.
    fn default_all_to(addr: &str) -> Self {
        Self {
            generate: Admins::default_to(addr),
            response: Admins::default_to(addr),
            admin: Admins::default_to(addr),
        }
    }

    /// Get the list of addresses for the given operation type.
    fn get_addresses(&self, address_type: AllowlistTypeBsc) -> &Admins {
        // This destructuring is necessary to make sure the `AllowlistsBsc` struct is properly
        // bound to the `AllowlistTypeBsc` enum.
        // This forces us to update this method if:
        // - `AllowlistsBsc` has a new field
        // - `AllowlistTypeBsc` has a new variant
        let Self {
            generate,
            response,
            admin,
        } = self;

        match address_type {
            AllowlistTypeBsc::Generate => generate,
            AllowlistTypeBsc::Response => response,
            AllowlistTypeBsc::Admin => admin,
        }
    }

    /// Get a mutable reference to the list of addresses for the given operation type.
    ///
    /// This is useful for updating the list of addresses.
    fn get_addresses_mut(&mut self, address_type: AllowlistTypeBsc) -> &mut Admins {
        let Self {
            generate,
            response,
            admin,
        } = self;
        match address_type {
            AllowlistTypeBsc::Generate => generate,
            AllowlistTypeBsc::Response => response,
            AllowlistTypeBsc::Admin => admin,
        }
    }
}
