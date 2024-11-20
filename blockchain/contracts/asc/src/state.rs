use crate::versioned_storage::{VersionedItem, VersionedMap};
use cosmwasm_std::{Api, Env, Order, StdError, StdResult, Storage};
use cw_storage_plus::PrefixBound;
use events::kms::{
    AdminsOperations, AllowedAddresses, KmsCoreConf, KmsOperation, OperationType, OperationValue,
    Transaction, TransactionId,
};

const ERR_MODIFY_NUM_PARTIES: &str =
    "It is not possible to change the number of parties participating";

// This storage struct is used to handle storage in the ASC contract. It contains:
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
    core_conf: VersionedItem<KmsCoreConf>,
    transactions: VersionedMap<Vec<u8>, Transaction>,
    response_values: VersionedMap<(Vec<u8>, u32), OperationValue>,
    response_counters: VersionedMap<Vec<u8>, u32>,
    debug_proof: VersionedItem<bool>,
    verify_proof_contract_address: VersionedItem<String>,
    allowed_addresses: VersionedItem<AllowedAddresses>,
}

impl Default for KmsContractStorage {
    fn default() -> Self {
        Self {
            core_conf: VersionedItem::new("core_conf"),
            transactions: VersionedMap::new("transactions"),
            response_values: VersionedMap::new("response_values"),
            response_counters: VersionedMap::new("response_counters"),
            debug_proof: VersionedItem::new("debug_proof"),
            verify_proof_contract_address: VersionedItem::new("verify_proof_contract_address"),
            allowed_addresses: VersionedItem::new("allowed_addresses"),
        }
    }
}

impl KmsContractStorage {
    // Load the configuration parameters from the storage
    pub fn load_core_conf(&self, storage: &dyn Storage) -> StdResult<KmsCoreConf> {
        self.core_conf.load(storage)
    }

    // Update the configuration parameters in the storage
    pub fn update_core_conf(&self, storage: &mut dyn Storage, value: KmsCoreConf) -> StdResult<()> {
        if !value.is_conformant() {
            return Err(cosmwasm_std::StdError::generic_err(
                "KMS core configuration is not conformant.",
            ));
        }
        match &self.core_conf.may_load(storage)? {
            Some(conf) => {
                // Following https://github.com/zama-ai/planning-blockchain/issues/182#issuecomment-2429482934
                // we disallow changing the amount of parties participating
                if conf.parties.len() != value.parties.len() {
                    return Err(StdError::generic_err(ERR_MODIFY_NUM_PARTIES));
                }

                self.core_conf
                    .update(storage, |_| -> StdResult<KmsCoreConf> { Ok(value) })?;
            }
            None => {
                self.core_conf.save(storage, &value)?;
            }
        };
        Ok(())
    }

    /// Load a transaction from the storage and include its associated response values
    pub fn load_transaction_with_response_values(
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

    /// Check if a transaction exists in the storage using its ID, without loading the whole struct
    pub fn has_transaction(&self, storage: &dyn Storage, txn_id: &TransactionId) -> bool {
        self.transactions.has(storage, txn_id.to_vec())
    }

    /// Update a request transaction in the storage
    ///
    /// If this request is the first request for the given transaction ID, a new transaction struct
    /// will be saved in the storage. Otherwise, the request's value will be added to the existing
    /// transaction.
    /// Request values are stored within `Transaction` structs, which are themselves stored in the
    /// `transactions` map. They are separated from response values to avoid some size limits when
    /// updating transactions. More info in `save_response_value`.
    pub fn update_request_transaction(
        &self,
        storage: &mut dyn Storage,
        env: &Env,
        txn_id: &TransactionId,
        operation_value: &OperationValue,
    ) -> StdResult<()> {
        // Check that the operation is a request
        if !operation_value.is_request() {
            return Err(StdError::generic_err(format!(
                "Cannot save or update transaction (id: {:?}) with a non-request operation {:?}",
                txn_id, operation_value,
            )));
        }

        // Update the transaction in the storage, using the logic explained above
        self.transactions.update(storage, txn_id.to_vec(), |tx| {
            let tx_updated = tx
                .map(|mut tx| {
                    tx.add_operation(operation_value.clone());
                    Ok(tx) as Result<Transaction, StdError>
                })
                .unwrap_or_else(|| {
                    let tx = env
                        .transaction
                        .clone()
                        .ok_or_else(|| StdError::generic_err("Transaction not found in context"))?;
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
    pub fn save_response_value(
        &self,
        storage: &mut dyn Storage,
        transaction_id: &TransactionId,
        operation_value: &OperationValue,
    ) -> StdResult<()> {
        // Check that the operation is a response
        if !operation_value.is_response() {
            return Err(StdError::generic_err(format!(
                "Cannot save non-response operation {:?} for transaction (id: {:?})",
                operation_value, transaction_id,
            )));
        }

        // Update the current counter for this transaction ID, starting from 0 if no counter has
        // been set yet
        let new_counter = self.response_counters.update(
            storage,
            transaction_id.to_vec(),
            |counter| -> StdResult<u32> {
                let current = counter.unwrap_or(0) + 1;
                Ok(current)
            },
        )?;

        // Save the response value in the storage using this new counter and the given transaction ID
        self.response_values.save(
            storage,
            (transaction_id.to_vec(), new_counter),
            operation_value,
        )?;
        Ok(())
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
    /// given transaction ID
    /// Optionally, a specific operation type can be provided to filter the returned values
    fn get_request_values_from_transaction(
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
            .clone();

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
        let mut response_values = Vec::new();

        // Load all response operations associated to the given transaction ID from the storage
        // Optionally, a specific operation type can be provided to filter the returned values
        // Note that we use `prefix_range_raw` instead of `prefix_range` to avoid some deserialization
        // overhead for keys since we don't use them
        // Also, we prefer to use `prefix_range_raw` instead of calling `prefix` and then `range_raw`
        // because that would require us to implement a custom `VersionedPrefix` type. It is just simpler
        // to instead support `prefix_range_raw` in `VersionedMap`
        self.response_values
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
                        response_values.push(value);
                    }
                } else {
                    response_values.push(value);
                }
                Ok(())
            })?;
        Ok(response_values)
    }

    /// Return the list of all operation values found in the storage and associated to the given
    /// KMS operation.
    ///
    /// This includes all values from different transactions that ran the same operation
    pub fn get_all_values_from_operation(
        &self,
        storage: &dyn Storage,
        operation: &KmsOperation,
    ) -> StdResult<Vec<OperationValue>> {
        let mut operation_values = Vec::new();

        // We use `keys` instead of `range` to avoid loading all the transactions in memory directly
        // Instead, they are loaded on demand based on the operation type later
        for txn_id_result in self
            .transactions
            .keys(storage, None, None, Order::Ascending)
        {
            let txn_id = txn_id_result?;
            let ops =
                self.get_values_from_transaction_and_operation(storage, &txn_id.into(), operation)?;

            operation_values.extend(ops);
        }

        Ok(operation_values)
    }

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

    // Save the debug proof flag in the storage
    pub fn set_debug_proof(&self, storage: &mut dyn Storage, value: bool) -> StdResult<()> {
        self.debug_proof.save(storage, &value)
    }

    // Load the debug proof flag from the storage
    #[allow(dead_code)]
    pub fn get_debug_proof(&self, storage: &dyn Storage) -> StdResult<bool> {
        self.debug_proof.load(storage)
    }

    /// Set allowed addresses.
    ///
    /// Some exec operations must not be accessible to anyone. To allow some finer-grain control
    /// on who can launch said operations the contract holds several lists of addresses of who can
    /// call these operations:
    /// - `allowed_to_gen`: who can trigger gen calls (ex: `keygen`, `crs_gen`)
    /// - `allowed_to_response`: who can trigger response calls (ex: `decrypt_response`, `keygen_response`)
    /// - `allowed_to_admin`: who can trigger admin calls (ex: `update_kms_core_conf`, `remove_allowed_address`)
    pub fn set_allowed_addresses(
        &self,
        storage: &mut dyn Storage,
        allowed_addresses: AllowedAddresses,
    ) -> StdResult<()> {
        self.allowed_addresses.save(storage, &allowed_addresses)
    }

    /// Check that the given address is allowed to trigger the given operation type
    pub fn check_address_is_allowed(
        &self,
        storage: &dyn Storage,
        address: &str,
        operation_type: OperationType,
    ) -> Result<(), cosmwasm_std::StdError> {
        let allowed_addresses = self.allowed_addresses.load(storage)?;
        allowed_addresses
            .get_addresses(operation_type.clone())
            .check_is_allowed(address)
            .map_err(|e| StdError::generic_err(format!("Type `{}`: {}", operation_type, e)))
    }

    /// Allow an address to trigger the given operation type.
    pub fn add_allowed_address(
        &self,
        storage: &mut dyn Storage,
        address: &str,
        operation_type: OperationType,
        cosmwasm_api: &dyn Api,
    ) -> StdResult<()> {
        self.allowed_addresses
            .update(storage, |mut allowed_addresses| {
                allowed_addresses
                    .get_addresses_mut(operation_type.clone())
                    .add_allowed(address.to_string(), cosmwasm_api)
                    .map_err(|e| {
                        StdError::generic_err(format!("Type `{}`: {}", operation_type, e))
                    })?;
                Ok(allowed_addresses) as Result<AllowedAddresses, StdError>
            })?;
        Ok(())
    }

    /// Forbid an address from triggering the given operation type.
    pub fn remove_allowed_address(
        &self,
        storage: &mut dyn Storage,
        address: &str,
        operation_type: OperationType,
    ) -> StdResult<()> {
        self.allowed_addresses
            .update(storage, |mut allowed_addresses| {
                allowed_addresses
                    .get_addresses_mut(operation_type.clone())
                    .remove_allowed(address)
                    .map_err(|e| {
                        StdError::generic_err(format!("Type `{}`: {}", operation_type, e))
                    })?;
                Ok(allowed_addresses) as Result<AllowedAddresses, StdError>
            })?;
        Ok(())
    }

    /// Replace all of the allowed addresses for the given operation type.
    pub fn replace_allowed_addresses(
        &self,
        storage: &mut dyn Storage,
        addresses: Vec<String>,
        operation_type: OperationType,
        cosmwasm_api: &dyn Api,
    ) -> StdResult<()> {
        self.allowed_addresses
            .update(storage, |mut allowed_addresses| {
                allowed_addresses
                    .get_addresses_mut(operation_type.clone())
                    .replace_allowed(addresses, cosmwasm_api)
                    .map_err(|e| {
                        StdError::generic_err(format!("Type `{}`: {}", operation_type, e))
                    })?;
                Ok(allowed_addresses) as Result<AllowedAddresses, StdError>
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{
        BlockInfo, ContractInfo, DepsMut, Empty, Env, MessageInfo, QuerierWrapper, TransactionInfo,
    };
    use cw_multi_test::IntoAddr;
    use events::kms::{DecryptValues, FheParameter, KmsCoreParty, TransactionId};
    use sylvia::types::ExecCtx;

    #[test]
    fn test_core_conf_threshold() {
        let dyn_store = &mut MockStorage::new();
        let storage = KmsContractStorage::default();
        let core_conf = KmsCoreConf {
            parties: vec![KmsCoreParty::default(); 4],
            response_count_for_majority_vote: 3,
            response_count_for_reconstruction: 3,
            degree_for_reconstruction: 1,
            param_choice: FheParameter::Test,
        };
        storage
            .update_core_conf(dyn_store, core_conf.clone())
            .unwrap();
        assert_eq!(storage.load_core_conf(dyn_store).unwrap(), core_conf);

        // next try to update from threshold to centralized, which should fail
        let central_conf = KmsCoreConf {
            parties: vec![KmsCoreParty::default(); 1],
            response_count_for_majority_vote: 1,
            response_count_for_reconstruction: 1,
            degree_for_reconstruction: 0,
            param_choice: FheParameter::Test,
        };
        assert!(storage
            .update_core_conf(dyn_store, central_conf)
            .unwrap_err()
            .to_string()
            .contains(ERR_MODIFY_NUM_PARTIES));
    }

    #[test]
    fn test_core_conf_centralized() {
        let dyn_store = &mut MockStorage::new();
        let storage = KmsContractStorage::default();
        let core_conf = KmsCoreConf {
            parties: vec![KmsCoreParty::default(); 1],
            response_count_for_majority_vote: 1,
            response_count_for_reconstruction: 1,
            degree_for_reconstruction: 0,
            param_choice: FheParameter::Test,
        };
        storage
            .update_core_conf(dyn_store, core_conf.clone())
            .unwrap();
        assert_eq!(storage.load_core_conf(dyn_store).unwrap(), core_conf);

        // next try to update from centralized to threshold, which should fail
        let threshold_conf = KmsCoreConf {
            parties: vec![KmsCoreParty::default(); 4],
            response_count_for_majority_vote: 3,
            response_count_for_reconstruction: 3,
            degree_for_reconstruction: 1,
            param_choice: FheParameter::Test,
        };
        assert!(storage
            .update_core_conf(dyn_store, threshold_conf)
            .unwrap_err()
            .to_string()
            .contains(ERR_MODIFY_NUM_PARTIES));
    }

    #[test]
    fn test_transaction() {
        let dyn_storage = &mut MockStorage::new();
        let storage = KmsContractStorage::default();
        let mock_queries = MockQuerier::<Empty>::new(&[]);
        let ctx = ExecCtx {
            env: Env {
                block: BlockInfo {
                    height: 1,
                    time: Default::default(),
                    chain_id: Default::default(),
                },
                transaction: Some(TransactionInfo { index: 1 }),
                contract: ContractInfo {
                    address: "contract".into_addr(),
                },
            },
            deps: DepsMut {
                storage: dyn_storage,
                api: &mut MockApi::default(),
                querier: QuerierWrapper::<Empty>::new(&mock_queries),
            },
            info: MessageInfo {
                sender: "sender".into_addr(),
                funds: vec![],
            },
        };
        let txn_id = TransactionId::default();
        let operation = OperationValue::Decrypt(DecryptValues::default());
        storage
            .update_request_transaction(ctx.deps.storage, &ctx.env, &txn_id, &operation)
            .unwrap();
        let tx = storage
            .load_transaction_with_response_values(ctx.deps.storage, &txn_id)
            .unwrap();
        assert_eq!(tx.operations().len(), 1);
        assert_eq!(tx.operations()[0], operation);
    }
}
