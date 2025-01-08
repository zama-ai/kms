use crate::allowlists::AllowlistsAsc;
use contracts_common::{allowlists::AllowlistsStateManager, versioned_states::VersionedItem};
use cosmwasm_std::{StdResult, Storage};

// This storage struct is used to handle storage in the ASC. It contains:
// - the configuration parameters for the KMS (centralized or threshold mode)
// - the transactions stored in the ASC, along their operation request values (indexed by transaction ID)
// - the response values stored in the ASC (indexed by transaction ID and a counter)
// - a counter for the number of response values received for each transaction (indexed by transaction ID)
// - a debug proof flag
// - the address of the contract verifying the proof
// - the lists of addresses allowed to trigger each operation type

// This storage struct needs to use versionized types instead of direct CosmWasm types in order to
// make it able to save, load or update versioned data in a backward-compatible manner
// These versioned types are defined in the `versioned_storage` module and use the versionize features
// from tfhe-rs
pub struct KmsContractStorage {
    debug_proof: VersionedItem<bool>,
    verify_proof_contract_address: VersionedItem<String>,
    csc_address: VersionedItem<String>,
    bsc_address: VersionedItem<String>,
    allowlists: VersionedItem<AllowlistsAsc>,
}

impl Default for KmsContractStorage {
    fn default() -> Self {
        Self {
            debug_proof: VersionedItem::new("debug_proof"),
            verify_proof_contract_address: VersionedItem::new("verify_proof_contract_address"),
            csc_address: VersionedItem::new("csc_address"),
            bsc_address: VersionedItem::new("bsc_address"),
            allowlists: VersionedItem::new("allowlists"),
        }
    }
}

/// Implement the `AllowlistsStateManager` trait for the ASC's state
///
/// This allows to set, check or update the allowlists in the storage
impl AllowlistsStateManager for KmsContractStorage {
    type Allowlists = AllowlistsAsc;

    fn allowlists(&self) -> &VersionedItem<AllowlistsAsc> {
        &self.allowlists
    }
}

impl KmsContractStorage {
    pub fn set_verify_proof_contract_address(
        &self,
        storage: &mut dyn Storage,
        value: String,
    ) -> StdResult<()> {
        self.verify_proof_contract_address.save(storage, &value)
    }

    pub fn get_verify_proof_contract_address(&self, storage: &dyn Storage) -> StdResult<String> {
        self.verify_proof_contract_address.load(storage)
    }

    pub fn set_csc_address(&self, storage: &mut dyn Storage, value: String) -> StdResult<()> {
        self.csc_address.save(storage, &value)
    }

    pub fn get_csc_address(&self, storage: &dyn Storage) -> StdResult<String> {
        self.csc_address.load(storage)
    }

    pub fn get_bsc_address(&self, storage: &dyn Storage) -> StdResult<String> {
        self.bsc_address.load(storage)
    }

    pub fn set_bsc_address(&self, storage: &mut dyn Storage, value: String) -> StdResult<()> {
        self.bsc_address.save(storage, &value)
    }

    // Save the debug proof flag in the storage
    pub fn set_debug_proof(&self, storage: &mut dyn Storage, value: bool) -> StdResult<()> {
        self.debug_proof.save(storage, &value)
    }

    // Load the debug proof flag from the storage
    #[allow(dead_code)]
    pub fn get_debug_proof(&self, storage: &dyn Storage) -> StdResult<bool> {
        self.debug_proof.load(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::MockStorage;

    #[test]
    fn test_verify_proof_contract_address() {
        let storage = KmsContractStorage::default();
        let mut dyn_storage = MockStorage::new();
        let address = "contract".to_string();
        storage
            .set_verify_proof_contract_address(&mut dyn_storage, address.clone())
            .unwrap();
        let loaded_address = storage
            .get_verify_proof_contract_address(&dyn_storage)
            .unwrap();
        assert_eq!(loaded_address, address);
    }

    #[test]
    fn test_csc_address() {
        let storage = KmsContractStorage::default();
        let mut dyn_storage = MockStorage::new();
        let address = "contract".to_string();
        storage
            .set_csc_address(&mut dyn_storage, address.clone())
            .unwrap();
        let loaded_address = storage.get_csc_address(&dyn_storage).unwrap();
        assert_eq!(loaded_address, address);
    }

    #[test]
    fn test_bsc_address() {
        let storage = KmsContractStorage::default();
        let mut dyn_storage = MockStorage::new();
        let address = "contract".to_string();
        storage
            .set_bsc_address(&mut dyn_storage, address.clone())
            .unwrap();
        let loaded_address = storage.get_bsc_address(&dyn_storage).unwrap();
        assert_eq!(loaded_address, address);
    }

    #[test]
    fn test_debug_proof() {
        let storage = KmsContractStorage::default();
        let mut dyn_storage = MockStorage::new();
        let value = true;
        storage.set_debug_proof(&mut dyn_storage, value).unwrap();
        let loaded_value = storage.get_debug_proof(&dyn_storage).unwrap();
        assert_eq!(loaded_value, value);
    }
}
