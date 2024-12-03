// Build an "old" version of a dummy struct and define a CosmWasm storage struct from it
use cosmwasm_schema::cw_serde;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Versionize, VersionsDispatch};

use crate::versioned_states::{VersionedItem, VersionedMap};

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum MyStructVersioned {
    V0(MyStruct),
}

#[cw_serde]
#[derive(Versionize)]
#[versionize(MyStructVersioned)]
pub struct MyStruct {
    pub attribute_0: String,
}

impl MyStruct {
    pub fn new(string_value: &str) -> Self {
        Self {
            attribute_0: string_value.to_string(),
        }
    }
}

pub struct VersionedStorage {
    pub my_versioned_map: VersionedMap<String, MyStruct>,
    pub my_versioned_item: VersionedItem<MyStruct>,
    pub my_versioned_map_prefix: VersionedMap<(String, String), MyStruct>,
}

impl Default for VersionedStorage {
    fn default() -> Self {
        Self {
            my_versioned_map: VersionedMap::new("my_versioned_map"),
            my_versioned_item: VersionedItem::new("my_versioned_item"),
            my_versioned_map_prefix: VersionedMap::new("my_versioned_map_prefix"),
        }
    }
}
