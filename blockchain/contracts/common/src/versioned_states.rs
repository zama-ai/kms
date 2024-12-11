use cosmwasm_std::{StdError, StdResult, Storage};
use cw_storage_plus::{Item, Map, PrefixBound, PrimaryKey};
use serde::{de::DeserializeOwned, Serialize};
use tfhe_versionable::{Unversionize, VersionizeOwned};

pub struct VersionedItem<T: VersionizeOwned> {
    versioned_item: Item<<T as VersionizeOwned>::VersionedOwned>,
}

// Implement a versionized Item for a given type T
// Not all methods supported by CosmWasm's Item are currently implemented by VersionedItem, only the
// ones needed by the ASC are. However, it should be easy to add the missing methods if
// needed in the future
impl<T> VersionedItem<T>
where
    T: DeserializeOwned + VersionizeOwned + Unversionize + Clone,
{
    pub fn new(namespace: &'static str) -> Self {
        Self {
            versioned_item: Item::new(namespace),
        }
    }

    // Versionize and save the given data
    pub fn save(&self, store: &mut dyn Storage, data: &T) -> StdResult<()> {
        let versioned_data = data.clone().versionize_owned();
        self.versioned_item.save(store, &versioned_data)?;
        Ok(())
    }

    // Loads the data (if it exists) and unversionize it before returning it
    pub fn may_load(&self, store: &dyn Storage) -> StdResult<Option<T>> {
        let versioned_result = self.versioned_item.may_load(store)?;
        versioned_result
            .map(|v| T::unversionize(v))
            .transpose()
            .map_err(|e| {
                StdError::generic_err(format!(
                    "Unversionizing data failed after loading it: {}",
                    e
                ))
            })
    }

    // Loads the data and unversionize it before returning it
    pub fn load(&self, store: &dyn Storage) -> StdResult<T> {
        let versioned_result = self.versioned_item.load(store)?;
        T::unversionize(versioned_result).map_err(|e| {
            StdError::generic_err(format!(
                "Unversionizing data failed after loading it: {}",
                e
            ))
        })
    }

    // Loads the data, unversionize it, apply the given action to it, versionize the result and save it
    pub fn update<A, E>(&self, store: &mut dyn Storage, action: A) -> Result<T, E>
    where
        A: FnOnce(T) -> Result<T, E>,
        E: From<StdError>,
    {
        // Load in Item calls `load` instead of `may_load` like in Map
        let input = self.load(store)?;
        let output = action(input)?;
        self.save(store, &output)?;
        Ok(output)
    }
}

// Implement a versionized Map for a given type T
// Not all methods supported by CosmWasm's Map are currently implemented by VersionedMap, only the
// ones needed by the ASC are. However, it should be easy to add the missing methods if
// needed in the future
pub struct VersionedMap<K, T: VersionizeOwned> {
    versioned_map: Map<K, <T as VersionizeOwned>::VersionedOwned>,
}

impl<'a, K, T> VersionedMap<K, T>
where
    K: PrimaryKey<'a>,
    T: Serialize + DeserializeOwned + VersionizeOwned + Unversionize + Clone,
{
    pub fn new(namespace: &'static str) -> Self {
        Self {
            versioned_map: Map::new(namespace),
        }
    }

    // Versionize and save the given data and associate it to the given key
    pub fn save(&self, store: &mut dyn Storage, k: K, data: &T) -> StdResult<()> {
        let versioned_data = data.clone().versionize_owned();
        self.versioned_map.save(store, k, &versioned_data)?;
        Ok(())
    }

    // Loads the data associated to the given key (if it exists) and unversionize it before returning it
    pub fn may_load(&self, store: &dyn Storage, k: K) -> StdResult<Option<T>> {
        let versioned_result = self.versioned_map.may_load(store, k)?;
        versioned_result
            .map(|v| T::unversionize(v))
            .transpose()
            .map_err(|e| {
                StdError::generic_err(format!(
                    "Unversionizing data failed after loading it: {}",
                    e
                ))
            })
    }

    // Loads the data associated to the given key and unversionize it before returning it
    pub fn load(&self, storage: &dyn Storage, k: K) -> StdResult<T> {
        let versioned_result = self.versioned_map.load(storage, k);
        versioned_result.and_then(|t| {
            T::unversionize(t).map_err(|e| {
                StdError::generic_err(format!(
                    "Unversionizing data failed after loading it: {}",
                    e
                ))
            })
        })
    }

    // Loads the data associated to the given key (if it exists), unversionize it, apply the given
    // action to it (if it exists), versionize the result and save it along the same key
    // If the key is not associated to any key, action(None) is run instead, but the rest stays the same
    pub fn update<A, E>(&self, store: &mut dyn Storage, k: K, action: A) -> Result<T, E>
    where
        A: FnOnce(Option<T>) -> Result<T, E>,
        E: From<StdError>,
    {
        let input = self.may_load(store, k.clone())?;
        let output = action(input)?;
        self.save(store, k, &output)?;

        // Return the actual output struct and not the versioned enum
        Ok(output)
    }

    // Indicate whether the given key is associated to any data in storage, without parsing or
    // interpreting the contents
    pub fn has(&self, store: &dyn Storage, k: K) -> bool {
        self.versioned_map.has(store, k)
    }

    // Collect the different items found within the given CosmWasm storage, filter them by the given
    // prefix, then unversionize them before returning them. Note that we use `prefix_range_raw`
    // instead of `prefix_range` to avoid the overhead of unversionizing the keys, since we currently
    // have no methods needing these keys
    // Also, we prefer to implement `prefix_range_raw` instead of using `prefix` and then `range_raw`
    // because that would require use to implement a custom `VersionedPrefix` type. It is just simpler
    // to instead support `prefix_range_raw` here
    pub fn prefix_range_raw<'c>(
        &self,
        store: &'c dyn Storage,
        min: Option<PrefixBound<'a, K::Prefix>>,
        max: Option<PrefixBound<'a, K::Prefix>>,
        order: cosmwasm_std::Order,
    ) -> Box<dyn Iterator<Item = StdResult<cosmwasm_std::Record<T>>> + 'c>
    where
        T: 'c,
        'a: 'c,
        K: 'c,
    {
        let versioned_items = self.versioned_map.prefix_range_raw(store, min, max, order);

        let items = versioned_items.map(|result| {
            result.and_then(|(k, v)| {
                T::unversionize(v)
                    .map_err(|e| {
                        StdError::generic_err(format!(
                            "Unversionizing data failed after loading all mapped data: {}",
                            e
                        ))
                    })
                    .map(|unversioned_item| (k, unversioned_item))
            })
        });
        Box::new(items)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::versioned_test_utils::{v0, v1};
    use cosmwasm_std::{testing::MockStorage, Order, StdError};
    use cw_storage_plus::PrefixBound;

    #[test]
    fn test_versioned_has() {
        // Create an old VersionedStorage instance
        let old_versioned_storage = v0::VersionedStorage::default();

        let dyn_store = &mut MockStorage::new();

        // Build an old struct
        let old_test_key = "old_test_key".to_string();
        let old_test_value = "old_test_value";
        let my_old_struct = v0::MyStruct::new(old_test_value);

        // Insert the old struct into the old storage
        old_versioned_storage
            .my_versioned_map
            .save(dyn_store, old_test_key.clone(), &my_old_struct)
            .expect("Failed to save old struct");

        // Create a new VersionedStorage instance
        let new_versioned_storage = v1::VersionedStorage::default();

        // Build a new struct
        let new_test_key = "new_test_key".to_string();
        let new_test_value = "new_test_value";
        let my_new_struct = v1::MyStruct::new(new_test_value);

        // Insert the new struct into the new storage
        new_versioned_storage
            .my_versioned_map
            .save(dyn_store, new_test_key.clone(), &my_new_struct)
            .expect("Failed to save new struct");

        // Check that the old struct is present in the new storage
        assert!(new_versioned_storage
            .my_versioned_map
            .has(dyn_store, old_test_key.clone()));

        // Check that the new struct is present in the new storage
        assert!(new_versioned_storage
            .my_versioned_map
            .has(dyn_store, new_test_key.clone()));

        // Check that the new storage does not contain an unrelated key
        assert!(!new_versioned_storage
            .my_versioned_map
            .has(dyn_store, "unrelated_key".to_string()));
    }

    #[test]
    fn test_versioned_map_load() {
        // Create an old VersionedStorage instance
        let old_versioned_storage = v0::VersionedStorage::default();

        let dyn_store = &mut MockStorage::new();

        // Build an old struct
        let test_key = "test_key".to_string();
        let test_value = "test_value";
        let my_old_struct = v0::MyStruct::new(test_value);

        // Insert the old struct into the old storage
        old_versioned_storage
            .my_versioned_map
            .save(dyn_store, test_key.clone(), &my_old_struct)
            .expect("Failed to save old struct");

        // Create a new VersionedStorage instance
        let new_versioned_storage = v1::VersionedStorage::default();

        // Load the new struct using the new VersionedStorage, the same key and the same CosmWasm storage
        let my_new_struct = new_versioned_storage
            .my_versioned_map
            .load(dyn_store, test_key.clone())
            .unwrap_or_else(|e| panic!("Failed to load my_new_struct: {}", e));

        // Test that the struct has been loaded under its new version
        // Note: `attribute_1` is of type `<u8>` because VersionedStorage has been constructed like this
        assert_eq!(my_new_struct.attribute_0, test_value.to_string());
        assert_eq!(my_new_struct.attribute_0, my_old_struct.attribute_0);
        assert_eq!(my_new_struct.attribute_1, <u8>::default());

        // Create a new broken VersionedStorage instance (defines the same value map but with a
        // different namespace)
        let broken_versioned_storage = v1::BrokenVersionedStorage::default();

        // Load the new struct using the new VersionedStorage, the same key and the same CosmWasm storage
        // Since the value map's namespace is different, the struct associated to the key cannot be
        // found within this storage. This is because it serves as a unique identifier for the
        // CosmWasm storage space within the contract's state
        broken_versioned_storage
            .my_versioned_map
            .load(dyn_store, test_key)
            .expect_err("Loading the broken storage should fail due to different namespace");
    }

    #[test]
    fn test_versioned_item_load() {
        // Create an old VersionedStorage instance
        let old_versioned_storage = v0::VersionedStorage::default();

        let dyn_store = &mut MockStorage::new();

        // Build an old struct
        let test_value = "test_value";
        let my_old_struct = v0::MyStruct::new(test_value);

        // Insert the old struct into the old storage
        old_versioned_storage
            .my_versioned_item
            .save(dyn_store, &my_old_struct)
            .expect("Failed to save old struct");

        // Create a new VersionedStorage instance
        let new_versioned_storage = v1::VersionedStorage::default();

        // Load the new struct using the new VersionedStorage and the same CosmWasm storage
        let my_new_struct = new_versioned_storage
            .my_versioned_item
            .load(dyn_store)
            .unwrap_or_else(|e| panic!("Failed to load my_new_struct: {}", e));

        // Test that the struct has been loaded under its new version
        // Note: `attribute_1` is of type `<u8>` because VersionedStorage has been constructed like this
        assert_eq!(my_new_struct.attribute_0, test_value.to_string());
        assert_eq!(my_new_struct.attribute_0, my_old_struct.attribute_0);
        assert_eq!(my_new_struct.attribute_1, <u8>::default());

        // Create a new broken VersionedStorage instance (defines the same value map but with a
        // different namespace)
        let broken_versioned_storage = v1::BrokenVersionedStorage::default();

        // Load the new struct using the new VersionedStorage, the same key and the same CosmWasm storage
        // Since the value map's namespace is different, the struct cannot be found within this
        // storage. This is because it serves as a unique identifier for the CosmWasm storage
        // space within the contract's state
        broken_versioned_storage
            .my_versioned_item
            .load(dyn_store)
            .expect_err("Loading the broken storage should fail due to different namespace");
    }

    #[test]
    fn test_versioned_map_update() {
        // Create an old VersionedStorage instance
        let old_versioned_storage = v0::VersionedStorage::default();

        let dyn_store = &mut MockStorage::new();

        // Build an old struct
        let test_key = "test_key".to_string();
        let test_value = "test_value";
        let my_old_struct = v0::MyStruct::new(test_value);

        // Insert the old struct into the old storage
        old_versioned_storage
            .my_versioned_map
            .save(dyn_store, test_key.clone(), &my_old_struct)
            .expect("Failed to save old struct");

        // Create a new VersionedStorage instance
        let new_versioned_storage = v1::VersionedStorage::default();

        let new_prefix = "updated_";

        // Update the struct using the new VersionedStorage, the same key, the same CosmWasm storage
        // and a function that will append a given prefix to one of the new struct's attribute
        let my_new_struct = new_versioned_storage
            .my_versioned_map
            .update(dyn_store, test_key.clone(), |my_struct| {
                my_struct.map_or_else(
                    || Ok(v1::MyStruct::default()),
                    |mut my_struct| {
                        my_struct.add_prefix(new_prefix);
                        Ok(my_struct) as Result<v1::MyStruct<u8>, StdError>
                    },
                )
            })
            .unwrap_or_else(|e| panic!("Failed to update struct from new storage: {}", e));

        // Test that the struct has been loaded under its new version and updated with the new prefix
        // Note: `attribute_1` is of type `<u8>` because VersionedStorage has been constructed like this
        assert_eq!(
            my_new_struct.attribute_0,
            new_prefix.to_string() + test_value
        );
        assert_ne!(my_new_struct.attribute_0, my_old_struct.attribute_0);
        assert_eq!(my_new_struct.attribute_1, <u8>::default());

        // Note that there no real reason to test with the "broken storage" because of the nature of
        // the update function: when trying to load the new struct, since the namespace is new and
        // empty, no errors will be thrown and the struct will be simply added to the storage (under
        // the same key but different storage namespace)
    }

    #[test]
    fn test_versioned_item_update() {
        // Create an old VersionedStorage instance
        let old_versioned_storage = v0::VersionedStorage::default();

        let dyn_store = &mut MockStorage::new();

        // Build an old struct
        let test_value = "test_value";
        let my_old_struct = v0::MyStruct::new(test_value);

        // Insert the old struct into the old storage
        old_versioned_storage
            .my_versioned_item
            .save(dyn_store, &my_old_struct)
            .expect("Failed to save old struct");

        // Create a new VersionedStorage instance
        let new_versioned_storage = v1::VersionedStorage::default();

        let new_prefix = "updated_";

        // Update the struct using the new VersionedStorage, the same CosmWasm storage and a function
        // that will append a given prefix to one of the new struct's attribute
        let my_new_struct = new_versioned_storage
            .my_versioned_item
            .update(dyn_store, |mut my_struct| {
                my_struct.add_prefix(new_prefix);
                Ok(my_struct) as Result<v1::MyStruct<u8>, StdError>
            })
            .unwrap_or_else(|e| panic!("Failed to update struct from new storage: {}", e));

        // Test that the struct has been loaded under its new version and updated with the new prefix
        // Note: `attribute_1` is of type `<u8>` because VersionedStorage has been constructed like this
        assert_eq!(
            my_new_struct.attribute_0,
            new_prefix.to_string() + test_value
        );
        assert_ne!(my_new_struct.attribute_0, my_old_struct.attribute_0);
        assert_eq!(my_new_struct.attribute_1, <u8>::default());

        // Note that there no real reason to test with the "broken storage" because of the nature of
        // the update function: when trying to load the new struct, since the namespace is new and
        // empty, no errors will be thrown and the struct will be simply added to the storage (under
        // the same key but different storage namespace)
    }

    #[test]
    fn test_versioned_prefix_range_raw() {
        // Create an old VersionedStorage instance
        let old_versioned_storage = v0::VersionedStorage::default();

        let dyn_store = &mut MockStorage::new();

        // Build an old struct, with a prefix
        let old_test_key = ("prefix_1".to_string(), "old_test_key".to_string());
        let old_test_value = "old_test_value";
        let my_old_struct = v0::MyStruct::new(old_test_value);

        // Insert the old struct into the old storage
        old_versioned_storage
            .my_versioned_map_prefix
            .save(dyn_store, old_test_key.clone(), &my_old_struct)
            .expect("Failed to save old struct");

        // Create a new VersionedStorage instance
        let new_versioned_storage = v1::VersionedStorage::default();

        // Build a first new struct, with the same prefix as for the old struct
        let new_first_test_key = ("prefix_1".to_string(), "new_first_test_key".to_string());
        let new_first_test_value = "new_first_test_value";
        let my_new_first_struct = v1::MyStruct::new(new_first_test_value);

        // Insert the new struct into the new storage
        new_versioned_storage
            .my_versioned_map_prefix
            .save(dyn_store, new_first_test_key.clone(), &my_new_first_struct)
            .expect("Failed to save new struct");

        // Build a second new struct, with a different prefix
        let new_second_test_key = ("prefix_2".to_string(), "new_second_test_key".to_string());
        let new_second_test_value = "new_second_test_value";
        let my_new_second_struct = v1::MyStruct::new(new_second_test_value);

        // Insert the new struct into the new storage
        new_versioned_storage
            .my_versioned_map_prefix
            .save(
                dyn_store,
                new_second_test_key.clone(),
                &my_new_second_struct,
            )
            .expect("Failed to save new struct");

        let mut my_test_values = Vec::new();

        // Iterate over the storage and filter by the first prefix
        new_versioned_storage
            .my_versioned_map_prefix
            .prefix_range_raw(
                dyn_store,
                Some(PrefixBound::inclusive("prefix_1".to_string())),
                Some(PrefixBound::inclusive("prefix_1".to_string())),
                Order::Ascending,
            )
            .for_each(|my_struct| {
                if let Ok((_, my_struct)) = my_struct {
                    // Test that all struct has the new attribute_1
                    // Note: `attribute_1` is of type `<u8>` because VersionedStorage has been
                    // constructed like this
                    assert_eq!(my_struct.attribute_1, <u8>::default());

                    my_test_values.push(my_struct.attribute_0);
                }
            });

        // Test that the struct has been loaded under its new version without altering the values
        // of attribute_0
        // Note: the vec's order is important here, as CosmWasm's `prefix_range_raw` function orders by
        // lexicographical order on key names
        assert_eq!(my_test_values, vec![new_first_test_value, old_test_value]);

        // Note that there no real reason to test with the "broken storage" because of the nature of
        // the prefix_range_raw function: when iterating through the items, since the namespace is new and
        // empty, no errors will be thrown and an empty vector is returned
    }
}
