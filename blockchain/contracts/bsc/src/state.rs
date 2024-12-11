use crate::allowlists::AllowlistsBsc;
use contracts_common::{
    allowlists::AllowlistsStateManager,
    versioned_states::{VersionedItem, VersionedMap},
};
use cosmwasm_std::{Env, Order, StdError, StdResult, Storage};
use cw_storage_plus::PrefixBound;
use events::kms::{
    CrsGenResponseValues, KeyGenResponseValues, KmsOperation, OperationValue, Transaction,
    TransactionId,
};
use std::collections::HashSet;

type KeyId = String;
type CrsId = String;
type Address = String;
type TxnId = Vec<u8>;
type Counter = u32;

pub struct BackendStorage {
    acl: VersionedMap<KeyId, HashSet<Address>>,
    allowlists: VersionedItem<AllowlistsBsc>,
    csc_address: VersionedItem<Address>,
    transactions: VersionedMap<TxnId, Transaction>,
    transaction_senders: VersionedMap<TxnId, Address>,
    operation_response_counters: VersionedMap<TxnId, Counter>,
    operation_response_values: VersionedMap<(TxnId, Counter), OperationValue>,
    key_gen_response_values: VersionedMap<KeyId, Vec<KeyGenResponseValues>>,
    crs_gen_response_values: VersionedMap<CrsId, Vec<CrsGenResponseValues>>,
}

impl Default for BackendStorage {
    fn default() -> Self {
        Self {
            acl: VersionedMap::new("acl"),
            allowlists: VersionedItem::new("allowlists"),
            csc_address: VersionedItem::new("csc_address"),
            transactions: VersionedMap::new("transactions"),
            transaction_senders: VersionedMap::new("transaction_senders"),
            operation_response_counters: VersionedMap::new("operation_response_counters"),
            operation_response_values: VersionedMap::new("operation_response_values"),
            key_gen_response_values: VersionedMap::new("key_gen_response_values"),
            crs_gen_response_values: VersionedMap::new("crs_gen_response_values"),
        }
    }
}

/// Implement the `AllowlistsStateManager` trait for the BSC's state
///
/// This allows to set, check or update the allowlists in the storage
impl AllowlistsStateManager for BackendStorage {
    type Allowlists = AllowlistsBsc;

    fn allowlists(&self) -> &VersionedItem<AllowlistsBsc> {
        &self.allowlists
    }
}

impl BackendStorage {
    pub fn get_csc_address(&self, storage: &dyn Storage) -> StdResult<String> {
        self.csc_address.load(storage)
    }

    pub(crate) fn set_csc_address(
        &self,
        storage: &mut dyn Storage,
        value: String,
    ) -> StdResult<()> {
        self.csc_address.save(storage, &value)
    }

    pub fn get_transaction_sender(
        &self,
        storage: &dyn Storage,
        transaction_id: &TransactionId,
    ) -> StdResult<Address> {
        self.transaction_senders
            .load(storage, transaction_id.to_vec())
    }

    pub fn get_acl_address_set(
        &self,
        storage: &dyn Storage,
        key_id: &KeyId,
    ) -> StdResult<HashSet<Address>> {
        self.acl.load(storage, key_id.clone())
    }

    /// Get the list of all key gen response values for a given key ID
    ///
    /// These values are stored separately than usual transaction response values because it avoids
    /// having to loop through all transaction values to find them.
    pub fn get_key_gen_response_values(
        &self,
        storage: &dyn Storage,
        key_id: &str,
    ) -> StdResult<Vec<KeyGenResponseValues>> {
        self.key_gen_response_values
            .load(storage, key_id.to_string())
    }

    /// Get the list of all CRS gen response values for a given CRS ID
    ///
    /// These values are stored separately than usual transaction response values because it avoids
    /// having to loop through all transaction values to find them.
    pub fn get_crs_gen_response_values(
        &self,
        storage: &dyn Storage,
        crs_id: &str,
    ) -> StdResult<Vec<CrsGenResponseValues>> {
        self.crs_gen_response_values
            .load(storage, crs_id.to_string())
    }

    /// Load a transaction from the storage and include its associated response values
    pub fn get_transaction_with_response_values(
        &self,
        storage: &dyn Storage,
        txn_id: &TransactionId,
    ) -> StdResult<Transaction> {
        let mut transaction = self.transactions.load(storage, txn_id.to_vec())?;

        // Add response values to the transaction since they are not stored in the transaction map
        // but instead in the `response_values` map
        let response_values = self.get_response_values_from_transaction(storage, txn_id, None)?;
        transaction.add_operations(response_values);
        Ok(transaction)
    }

    /// Return the list of all operation values of a given type found in the storage and associated
    /// to the given transaction ID
    pub fn get_values_from_transaction_and_operation(
        &self,
        storage: &dyn Storage,
        transaction_id: &TransactionId,
        operation: &KmsOperation,
    ) -> StdResult<Vec<OperationValue>> {
        // Since request and response transactions are stored separately, we need to handle them
        // differently
        match operation {
            op if op.is_request() => {
                self.get_request_values_from_transaction(storage, transaction_id, Some(op))
            }
            op if op.is_response() => {
                self.get_response_values_from_transaction(storage, transaction_id, Some(op))
            }
            _ => Err(StdError::generic_err(format!(
                "Operation type {} not supported. Neither a request nor a response",
                operation
            ))),
        }
    }

    /// Return the list of all request operation values found in the storage and associated to the
    /// given transaction ID.
    /// Optionally, a specific operation type can be provided to filter the returned values
    pub fn get_request_values_from_transaction(
        &self,
        storage: &dyn Storage,
        transaction_id: &TransactionId,
        operation: Option<&KmsOperation>,
    ) -> StdResult<Vec<OperationValue>> {
        // Load all request operations associated to the given transaction ID from the storage
        let operations = self
            .transactions
            .load(storage, transaction_id.to_vec())?
            .operations()
            .to_vec();

        // Filter the operations based on the optional operation type provided
        Ok(if let Some(op) = operation {
            operations
                .into_iter()
                .filter(|val| &val.into_kms_operation() == op)
                .collect()
        } else {
            operations
        })
    }

    /// Return the list of all response operation values found in the storage and associated to the
    /// given transaction ID
    /// Optionally, a specific operation type can be provided to filter the returned values
    fn get_response_values_from_transaction(
        &self,
        storage: &dyn Storage,
        transaction_id: &TransactionId,
        operation: Option<&KmsOperation>,
    ) -> StdResult<Vec<OperationValue>> {
        let mut operation_response_values = Vec::new();

        // Load all response operations associated to the given transaction ID from the storage
        // Optionally, a specific operation type can be provided to filter the returned values
        // Note that we use `prefix_range_raw` instead of `prefix_range` to avoid some deserialization
        // overhead for keys since we don't use them
        // Also, we prefer to use `prefix_range_raw` instead of calling `prefix` and then `range_raw`
        // because that would require us to implement a custom `VersionedPrefix` type. It is just simpler
        // to instead support `prefix_range_raw` in `VersionedMap`
        self.operation_response_values
            .prefix_range_raw(
                storage,
                Some(PrefixBound::inclusive(transaction_id.to_vec())),
                Some(PrefixBound::inclusive(transaction_id.to_vec())),
                Order::Ascending,
            )
            .try_for_each(|item| -> StdResult<_> {
                let (_, value) = item?;
                if let Some(op) = operation {
                    if &value.into_kms_operation() == op {
                        operation_response_values.push(value);
                    }
                } else {
                    operation_response_values.push(value);
                }
                Ok(())
            })?;
        Ok(operation_response_values)
    }

    /// Check if a transaction exists in the storage using its ID, without loading the whole struct
    pub fn has_transaction(&self, storage: &dyn Storage, transaction_id: &TransactionId) -> bool {
        self.transactions.has(storage, transaction_id.to_vec())
    }

    pub fn add_address_to_acl(
        &self,
        storage: &mut dyn Storage,
        key_id: &KeyId,
        address: &Address,
    ) -> StdResult<()> {
        self.acl
            .update(storage, key_id.to_string(), |address_set| {
                let updated_address_set = address_set
                    .map(|mut address_set| {
                        address_set.insert(address.to_string());
                        Ok(address_set) as Result<HashSet<String>, StdError>
                    })
                    .unwrap_or_else(|| {
                        let mut address_set = HashSet::new();
                        address_set.insert(address.to_string());
                        Ok(address_set)
                    })?;
                Ok(updated_address_set) as Result<HashSet<String>, StdError>
            })?;
        Ok(())
    }

    /// Update a request transaction in the storage
    ///
    /// If this request is the first request for the given transaction ID, a new transaction struct
    /// will be saved in the storage. Otherwise, the request's value will be added to the existing
    /// transaction.
    /// Request values are stored within `Transaction` structs, which are themselves stored in the
    /// `transactions` map. They are separated from response values to avoid some size limits when
    /// updating transactions. More info in `save_response_value`.
    pub fn save_request_on_transaction(
        &self,
        storage: &mut dyn Storage,
        env: &Env,
        transaction_id: &TransactionId,
        operation_value: &OperationValue,
    ) -> StdResult<()> {
        // Check that the operation is a request
        if !operation_value.is_request() {
            return Err(StdError::generic_err(format!(
                "Cannot save request on transaction id <{}> with non-request operation <{}>",
                transaction_id.to_hex(),
                operation_value,
            )));
        }

        // Update the transaction in the storage, using the logic explained above
        self.transactions
            .update(storage, transaction_id.to_vec(), |tx| {
                let tx_updated = tx
                    .map(|mut tx| {
                        tx.add_operation(operation_value.clone());
                        Ok(tx) as Result<Transaction, StdError>
                    })
                    .unwrap_or_else(|| {
                        let tx = env.transaction.clone().ok_or_else(|| {
                            StdError::generic_err("Transaction not found in context")
                        })?;
                        Ok(Transaction::new(
                            env.block.height,
                            tx.index,
                            vec![operation_value.clone()],
                        ))
                    })?;
                Ok(tx_updated) as Result<Transaction, StdError>
            })?;
        Ok(())
    }

    /// Save a response value in the storage
    ///
    /// Response values are stored separately than request values. This is because response values
    /// can get very large and CosmWasm limits the maximum byte size of objects read/written in the
    /// storage to 128KB : https://github.com/CosmWasm/cosmwasm/blob/main/packages/vm/src/imports.rs#L40
    /// In particular, with multiple parties that are each returning a response, instead of having
    /// to load and save all responses values within the `Transaction` struct each time we need to
    /// add a new one, we use this separated storage mechanism:
    /// - response values are stored in the `response_values` map, indexed by transaction ID and a counter
    /// - a counter is stored in the `response_counters` map, indexed by transaction ID
    /// - whenever a new response needs to be saved, it used the current counter among its keys, and
    ///   the counter is then incremented by one
    pub fn save_response_on_transaction(
        &self,
        storage: &mut dyn Storage,
        transaction_id: &TransactionId,
        operation_value: &OperationValue,
    ) -> StdResult<()> {
        // Check that the operation is a response
        if !operation_value.is_response() {
            return Err(StdError::generic_err(format!(
                "Cannot save response on transaction id <{}> with non-response operation <{}>",
                transaction_id.to_hex(),
                operation_value,
            )));
        }

        // Update the current counter for this transaction ID, starting from 0 if no counter has
        // been set yet
        let new_counter = self.operation_response_counters.update(
            storage,
            transaction_id.to_vec(),
            |counter| -> StdResult<u32> {
                let current = counter.unwrap_or(0) + 1;
                Ok(current)
            },
        )?;

        // Save the response value in the storage using this new counter and the given transaction ID
        self.operation_response_values.save(
            storage,
            (transaction_id.to_vec(), new_counter),
            operation_value,
        )?;
        Ok(())
    }

    pub fn save_transaction_sender(
        &self,
        storage: &mut dyn Storage,
        transaction_id: &TransactionId,
        sender: &Address,
    ) -> StdResult<()> {
        self.transaction_senders
            .save(storage, transaction_id.to_vec(), sender)?;
        Ok(())
    }

    /// Save a key generation response values in the storage
    ///
    /// Note that this assumes we won't have too many key generations, else we might encounter the
    /// same read/write conflict as explained in the comments of `save_response_on_transaction`
    pub fn save_key_gen_response_values(
        &self,
        storage: &mut dyn Storage,
        key_response_values: KeyGenResponseValues,
    ) -> StdResult<()> {
        self.key_gen_response_values.update(
            storage,
            key_response_values.request_id().to_string(),
            |key_response| {
                let mut response = key_response.unwrap_or_default();
                response.push(key_response_values);
                Ok(response) as Result<Vec<KeyGenResponseValues>, StdError>
            },
        )?;
        Ok(())
    }

    /// Save a CRS gen response value in the storage
    pub fn save_crs_response_values(
        &self,
        storage: &mut dyn Storage,
        crs_response_values: CrsGenResponseValues,
    ) -> StdResult<()> {
        self.crs_gen_response_values.update(
            storage,
            crs_response_values.request_id().to_string(),
            |crs_response| {
                let mut response = crs_response.unwrap_or_default();
                response.push(crs_response_values);
                Ok(response) as Result<Vec<CrsGenResponseValues>, StdError>
            },
        )?;
        Ok(())
    }
}
