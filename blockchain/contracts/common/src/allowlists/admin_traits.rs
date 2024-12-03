use cosmwasm_std::Api;

/// Define a type alias for Vec<String>
///
/// We define an alias with a trait instead of struct mostly because when we instantiate the ASC,
/// we read JSON objects and not Rust objects. This means type conversions are not made. Hence,
/// having a struct would require us to provide an `admin` field for each operation type in the
/// JSON used for contract instantiation, which is not practical.
pub type Admins = Vec<String>;

/// Define a trait for Admins-related operations
pub trait AdminsOperations {
    fn default_to(addr: &str) -> Self;
    fn is_valid(&self, cosmwasm_api: &dyn Api) -> bool;
    fn check_is_valid(&self, cosmwasm_api: &dyn Api) -> Result<(), cosmwasm_std::StdError>;
    fn is_allowed(&self, address: &str) -> bool;
    fn check_is_allowed(&self, address: &str) -> Result<(), cosmwasm_std::StdError>;
    fn add_allowed(
        &mut self,
        address: String,
        cosmwasm_api: &dyn Api,
    ) -> Result<(), cosmwasm_std::StdError>;
    fn remove_allowed(&mut self, address: &str) -> Result<(), cosmwasm_std::StdError>;
    fn replace_allowed(
        &mut self,
        admins: Vec<String>,
        cosmwasm_api: &dyn Api,
    ) -> Result<(), cosmwasm_std::StdError>;
}

/// This traits provides methods to manage a list of addresses that are considered admins
/// (ie, they can be used to allow or restrict some permissions). The most important methods are:
/// - `is_valid`: check if the current list of admins is valid
/// - `is_allowed`: check if the given address is in the list of admins
/// - `add_allowed`: add an address to the list of admins
/// - `remove_allowed`: remove an address from the list of admins, if there is (strictly) more than one address
/// - `replace_allowed`: replace the list of admins with a new non-empty list
impl AdminsOperations for Admins {
    /// Create a new list of admins with only the given address.
    fn default_to(addr: &str) -> Self {
        vec![addr.to_string()]
    }

    /// Indicate if the current list of admins is valid.
    fn is_valid(&self, cosmwasm_api: &dyn Api) -> bool {
        self.iter()
            .all(|addr| cosmwasm_api.addr_validate(addr).is_ok())
    }

    /// Check that the current list of admins is valid.
    fn check_is_valid(&self, cosmwasm_api: &dyn Api) -> Result<(), cosmwasm_std::StdError> {
        if !self.is_valid(cosmwasm_api) {
            return Err(cosmwasm_std::StdError::generic_err(
                "Some addresses are invalid ",
            ));
        }
        Ok(())
    }

    /// Indicate if the given address is in the current list of admins.
    fn is_allowed(&self, address: &str) -> bool {
        self.contains(&address.to_string())
    }

    /// Check that the given address is in the current list of admins.
    fn check_is_allowed(&self, address: &str) -> Result<(), cosmwasm_std::StdError> {
        if !self.is_allowed(address) {
            return Err(cosmwasm_std::StdError::generic_err(format!(
                "Address `{}` is not allowed",
                address
            )));
        }
        Ok(())
    }

    /// Add an address to the current list of admins, if it is not already present. Also checks that
    /// the new list is valid.
    fn add_allowed(
        &mut self,
        address: String,
        cosmwasm_api: &dyn Api,
    ) -> Result<(), cosmwasm_std::StdError> {
        if !self.contains(&address) {
            self.push(address);
        }
        self.check_is_valid(cosmwasm_api)?;

        Ok(())
    }

    /// Remove an address from the current list of admins, if there is (strictly) more than one address.
    fn remove_allowed(&mut self, address: &str) -> Result<(), cosmwasm_std::StdError> {
        if self.len() <= 1 {
            return Err(cosmwasm_std::StdError::generic_err(
                "Cannot remove address: only one address is remaining",
            ));
        }
        self.retain(|x| x != address);
        Ok(())
    }

    /// Replace the current list of admins with a new non-empty list. Also checks that the new list
    /// is valid.
    fn replace_allowed(
        &mut self,
        admins: Vec<String>,
        cosmwasm_api: &dyn Api,
    ) -> Result<(), cosmwasm_std::StdError> {
        if admins.is_empty() {
            return Err(cosmwasm_std::StdError::generic_err(
                "Cannot replace with empty list of addresses",
            ));
        }

        *self = admins;

        self.check_is_valid(cosmwasm_api)?;

        Ok(())
    }
}
