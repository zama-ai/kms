// Build a "new" version of the "old" dummy struct from above and define a new CosmWasm storage
// struct from it
use cosmwasm_schema::cw_serde;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, Versionize, VersionsDispatch};

use crate::versioned_states::{VersionedItem, VersionedMap};

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum MyStructVersioned<T: Default> {
    V0(MyStructV0),
    V1(MyStruct<T>),
}

#[cw_serde]
#[derive(Version)]
pub struct MyStructV0 {
    pub attribute_0: String,
}

impl<T: Default> Upgrade<MyStruct<T>> for MyStructV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<MyStruct<T>, Self::Error> {
        Ok(MyStruct {
            attribute_0: self.attribute_0,
            attribute_1: T::default(),
        })
    }
}

#[cw_serde]
#[derive(Versionize, Default)]
#[versionize(MyStructVersioned)]
pub struct MyStruct<T: Default> {
    pub attribute_0: String,
    pub attribute_1: T,
}

impl<T: Default> MyStruct<T> {
    pub fn new(new_str: &str) -> Self {
        Self {
            attribute_0: new_str.to_string(),
            attribute_1: T::default(),
        }
    }

    // Define a simple method that updates the struct
    pub fn add_prefix(&mut self, prefix: &str) {
        self.attribute_0 = prefix.to_string() + &self.attribute_0
    }
}

pub struct VersionedStorage {
    pub my_versioned_map: VersionedMap<String, MyStruct<u8>>,
    pub my_versioned_item: VersionedItem<MyStruct<u8>>,
    pub my_versioned_map_prefix: VersionedMap<(String, String), MyStruct<u8>>,
}

// Namespace must match the one from the old version
impl Default for VersionedStorage {
    fn default() -> Self {
        Self {
            my_versioned_map: VersionedMap::new("my_versioned_map"),
            my_versioned_item: VersionedItem::new("my_versioned_item"),
            my_versioned_map_prefix: VersionedMap::new("my_versioned_map_prefix"),
        }
    }
}
// Define a "broken" CosmWasm storage struct that uses a different namespace
pub struct BrokenVersionedStorage {
    pub my_versioned_map: VersionedMap<String, MyStruct<u8>>,
    pub my_versioned_item: VersionedItem<MyStruct<u8>>,
}

impl Default for BrokenVersionedStorage {
    fn default() -> Self {
        Self {
            my_versioned_map: VersionedMap::new("my_broken_versioned_map"),
            my_versioned_item: VersionedItem::new("my_broken_versioned_item"),
        }
    }
}
