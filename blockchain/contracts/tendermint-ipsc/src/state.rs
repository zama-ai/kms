use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::Item;
use events::HexVector;

pub struct ProofStorage {
    validators_pubkeys: Item<Vec<HexVector>>,
    last_root_hash: Item<HexVector>,
}

impl Default for ProofStorage {
    fn default() -> Self {
        Self {
            validators_pubkeys: Item::new("validators_pubkeys"),
            last_root_hash: Item::new("last_root_hash"),
        }
    }
}

impl ProofStorage {
    pub fn get_validators(&self, storage: &dyn Storage) -> StdResult<Vec<HexVector>> {
        self.validators_pubkeys.load(storage)
    }

    pub fn set_validators(
        &self,
        storage: &mut dyn Storage,
        validators: Vec<HexVector>,
    ) -> StdResult<()> {
        self.validators_pubkeys.save(storage, &validators)
    }

    pub fn get_last_root_hash(&self, storage: &dyn Storage) -> StdResult<Option<HexVector>> {
        self.last_root_hash.may_load(storage)
    }

    pub fn set_last_root_hash(&self, storage: &mut dyn Storage, hash: HexVector) -> StdResult<()> {
        self.last_root_hash.save(storage, &hash)
    }
}
