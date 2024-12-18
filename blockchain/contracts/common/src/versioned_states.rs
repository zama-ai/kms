use cosmwasm_std::{StdError, StdResult, Storage};
use cw_storage_plus::{Bound, Item, KeyDeserialize, Map, PrefixBound, PrimaryKey};
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

    /// Versionize and save the given data
    pub fn save(&self, store: &mut dyn Storage, data: &T) -> StdResult<()> {
        let versioned_data = data.clone().versionize_owned();
        self.versioned_item.save(store, &versioned_data)?;
        Ok(())
    }

    /// Load the data (if it exists) and unversionize it before returning it
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

    /// Load the data and unversionize it before returning it
    pub fn load(&self, store: &dyn Storage) -> StdResult<T> {
        let versioned_result = self.versioned_item.load(store)?;
        T::unversionize(versioned_result).map_err(|e| {
            StdError::generic_err(format!(
                "Unversionizing data failed after loading it: {}",
                e
            ))
        })
    }

    /// Load the data, unversionize it, apply the given action to it, versionize the result and save it
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

/// Unversionize the items of a versioned map iterator
///
/// This is a helper function to unversionize the items of a versioned map iterator, regardless of
/// the keys' type (serialized or deserialized)
fn unversionize_map_items<'c, K, T>(
    versioned_iterator: Box<
        dyn Iterator<Item = StdResult<(K, <T as VersionizeOwned>::VersionedOwned)>> + 'c,
    >,
) -> Box<dyn Iterator<Item = StdResult<(K, T)>> + 'c>
where
    T: Serialize + DeserializeOwned + VersionizeOwned + Unversionize + Clone + 'c,
    K: 'c,
{
    let items = versioned_iterator.map(|result| {
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

// Implement a versionized Map for a given type T
// Not all methods supported by CosmWasm's Map are currently implemented by VersionedMap, only the
// ones needed by the ASC are. However, it should be easy to add the missing methods if needed
// in the future
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

    /// Versionize and save the given data under the given key
    pub fn save(&self, store: &mut dyn Storage, k: K, data: &T) -> StdResult<()> {
        let versioned_data = data.clone().versionize_owned();
        self.versioned_map.save(store, k, &versioned_data)?;
        Ok(())
    }

    /// Indicate whether the given key is associated to any data in storage, without loading anything
    pub fn has(&self, store: &dyn Storage, k: K) -> bool {
        self.versioned_map.has(store, k)
    }

    /// Load the data associated to the given key and unversionize it before returning it
    ///
    /// If the key is not associated to any data, None is returned
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

    /// Load the data associated to the given key and unversionize it before returning it
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

    /// Load the data associated to the given key, unversionize it, apply the given action to it,
    /// versionize the result and save it along the same key.
    ///
    /// If the key is not associated to any key, action(None) is run instead, but the rest stays the same
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

    /// Collect the different keys found within the given CosmWasm storage, without loading the
    /// versioned items
    ///
    /// The advantage of using `keys_raw` instead of `keys` is that we avoid the overhead of
    /// deserializing the keys
    /// Note that since we are not loading any versioned items, we directly call cw-storage-plus's
    /// `keys_raw` method
    pub fn keys_raw<'c>(
        &self,
        store: &'c dyn Storage,
        min: Option<Bound<'a, K>>,
        max: Option<Bound<'a, K>>,
        order: cosmwasm_std::Order,
    ) -> Box<dyn Iterator<Item = Vec<u8>> + 'c>
    where
        T: 'c,
    {
        self.versioned_map.keys_raw(store, min, max, order)
    }

    /// Collect the different items found within the given CosmWasm storage, filter them by the given
    /// prefix, then unversionize them before returning them.
    ///
    /// The advantage of using `prefix_range_raw` instead of `prefix_range` is that we avoid the
    /// overhead of deserializing the keys
    /// Also, we prefer to implement `prefix_range_raw` instead of using `prefix` and then `range_raw`
    /// because that would require use to implement a custom `VersionedPrefix` type. It is just simpler
    /// to instead support `prefix_range_raw`
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
        let versioned_iterator = self.versioned_map.prefix_range_raw(store, min, max, order);
        unversionize_map_items(versioned_iterator)
    }
}

// For methods such as `range` that deserializes the keys, we need to add a new trait bound to the
// keys' type `K`
impl<'a, K, T> VersionedMap<K, T>
where
    K: PrimaryKey<'a> + KeyDeserialize,
    T: Serialize + DeserializeOwned + VersionizeOwned + Unversionize + Clone,
{
    /// Collect the different items found within the given CosmWasm storage then unversionize them
    /// before returning them.
    ///
    /// Note that `range` deserializes the keys, and is preferred over `range_raw` only when we need
    /// to access these keys
    pub fn range<'c>(
        &self,
        store: &'c dyn Storage,
        min: Option<Bound<'a, K>>,
        max: Option<Bound<'a, K>>,
        order: cosmwasm_std::Order,
    ) -> Box<dyn Iterator<Item = StdResult<(K::Output, T)>> + 'c>
    where
        T: 'c,
        K::Output: 'static,
    {
        let versioned_iterator = self.versioned_map.range(store, min, max, order);
        unversionize_map_items(versioned_iterator)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::versioned_test_utils::{v0, v1};
    use cosmwasm_std::{testing::MockStorage, Order, StdError};
    use cw_storage_plus::PrefixBound;

    // Test VersionedItem's methods
    #[test]
    fn test_versioned_item_load() {
        // Create an old VersionedStorage instance
        let old_versioned_storage = v0::VersionedStorage::default();

        let dyn_store = &mut MockStorage::new();

        // Build an old struct
        let test_value = "test_value";
        let my_old_struct = v0::MyStruct::new(test_value);

        // Test that the item is not present in the old storage
        let none_item = old_versioned_storage.my_versioned_item.may_load(dyn_store);
        assert!(none_item.is_ok());
        assert!(none_item.unwrap().is_none());

        // Insert the old struct into the old storage
        old_versioned_storage
            .my_versioned_item
            .save(dyn_store, &my_old_struct)
            .expect("Failed to save old struct");

        // Test that the item is now present in the old storage
        let some_item = old_versioned_storage.my_versioned_item.may_load(dyn_store);
        assert!(some_item.is_ok());
        assert!(some_item.unwrap().is_some());

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

        // Do the same test for `may_load`
        broken_versioned_storage
            .my_versioned_item
            .may_load(dyn_store)
            .expect_err("Loading the broken storage should fail due to different namespace");
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

    // Test VersionedMap's methods

    #[test]
    fn test_versioned_map_has() {
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

        // Test that the item is not present in the old storage
        let none_item = old_versioned_storage
            .my_versioned_map
            .may_load(dyn_store, test_key.clone());
        assert!(none_item.is_ok());
        assert!(none_item.unwrap().is_none());

        // Insert the old struct into the old storage
        old_versioned_storage
            .my_versioned_map
            .save(dyn_store, test_key.clone(), &my_old_struct)
            .expect("Failed to save old struct");

        // Test that the item is now present in the old storage
        let some_item = old_versioned_storage
            .my_versioned_map
            .may_load(dyn_store, test_key.clone());
        assert!(some_item.is_ok());
        assert!(some_item.unwrap().is_some());

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
            .load(dyn_store, test_key.clone())
            .expect_err("Loading the broken storage should fail due to different namespace");

        // Do the same test for `may_load`
        broken_versioned_storage
            .my_versioned_map
            .may_load(dyn_store, test_key)
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

    #[test]
    fn test_versioned_range() {
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

        // Build a first new struct
        let new_first_test_key = "new_first_test_key".to_string();
        let new_first_test_value = "new_first_test_value";
        let my_new_first_struct = v1::MyStruct::new(new_first_test_value);

        // Insert the new struct into the new storage
        new_versioned_storage
            .my_versioned_map
            .save(dyn_store, new_first_test_key.clone(), &my_new_first_struct)
            .expect("Failed to save new struct");

        let mut my_test_values = Vec::new();
        let mut my_test_keys = Vec::new();

        // Iterate over the storage
        new_versioned_storage
            .my_versioned_map
            .range(dyn_store, None, None, Order::Ascending)
            .for_each(|my_struct| {
                if let Ok((my_key, my_struct)) = my_struct {
                    // Test that all struct has the new attribute_1
                    // Note: `attribute_1` is of type `<u8>` because VersionedStorage has been
                    // constructed like this
                    assert_eq!(my_struct.attribute_1, <u8>::default());

                    my_test_values.push(my_struct.attribute_0);
                    my_test_keys.push(my_key);
                }
            });

        // Test that the struct has been loaded under its new version without altering the values
        // of attribute_0. Also test that the keys are the same and in the correct order
        // Note: the vec's order is important here, as CosmWasm's `range` function orders by
        // lexicographical order on key names
        assert_eq!(my_test_values, vec![new_first_test_value, old_test_value]);
        assert_eq!(my_test_keys, vec![new_first_test_key, old_test_key]);

        // Note that there no real reason to test with the "broken storage" because of the nature of
        // the range function: when iterating through the items, since the namespace is new and
        // empty, no errors will be thrown and an empty vector is returned
    }
}
