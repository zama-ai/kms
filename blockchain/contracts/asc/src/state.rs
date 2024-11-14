use crate::versioned_storage::{VersionedItem, VersionedMap};
use cosmwasm_std::{Api, Env, Order, StdError, StdResult, Storage};
use events::kms::{
    AdminsOperations, AllowedAddresses, KmsCoreConf, KmsEvent, KmsOperation, OperationType,
    OperationValue, Transaction, TransactionId,
};

const ERR_MODIFY_NUM_PARTIES: &str =
    "It is not possible to change the number of parties participating";

// This storage struct is used to handle storage in the ASC contract. It contains:
// - the configuration parameters for the KMS (centralized or threshold mode)
// - the transactions stored in the ASC (along their operation values)
// - a debug proof flag
// This storage struct needs to use versionized types instead of direct CosmWasm types in order to
// make it able to save, load or update versioned data in a backward-compatible manner
// These versioned types are defined in the `versioned_storage` module and use the versionize features
// from tfhe-rs
pub struct KmsContractStorage {
    core_conf: VersionedItem<KmsCoreConf>,
    transactions: VersionedMap<Vec<u8>, Transaction>,
    debug_proof: VersionedItem<bool>,
    verify_proof_contract_address: VersionedItem<String>,
    allowed_addresses: VersionedItem<AllowedAddresses>,
}

impl Default for KmsContractStorage {
    fn default() -> Self {
        Self {
            core_conf: VersionedItem::new("core_conf"),
            transactions: VersionedMap::new("transactions"),
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

    // Load a transaction from the storage
    pub fn load_transaction(
        &self,
        storage: &dyn Storage,
        txn_id: TransactionId,
    ) -> StdResult<Transaction> {
        self.transactions.load(storage, txn_id.to_vec())
    }

    // Update a transaction in the storage
    // TODO: makes sense to propagate a `TransactionId` instead of a `Vec<u8>` for consistency with
    // load methods
    pub fn update_transaction<T>(
        &self,
        storage: &mut dyn Storage,
        env: &Env,
        txn_id: &[u8],
        operation: &T,
    ) -> StdResult<()>
    where
        T: Into<OperationValue> + Clone,
    {
        self.transactions.update(storage, txn_id.to_vec(), |tx| {
            let tx_updated = tx
                .map(|mut tx| {
                    tx.add_operation(operation.clone().into())
                        .map_err(|e| StdError::generic_err(e.to_string()))?;
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
                        vec![operation.clone().into()],
                    ))
                })?;
            Ok(tx_updated) as Result<Transaction, StdError>
        })?;
        Ok(())
    }

    // Return the list of all operation values found in the storage and associated to the given
    // KMS event (the combination of a KMS operation and a transaction ID)
    pub fn get_operations_value(
        &self,
        storage: &dyn Storage,
        event: KmsEvent,
    ) -> StdResult<Vec<OperationValue>> {
        let tx = self.transactions.load(storage, event.txn_id().to_vec())?;
        let result = tx
            .operations()
            .iter()
            .filter(|op| {
                <OperationValue as Into<KmsOperation>>::into((*op).clone())
                    == event.operation().clone()
            })
            .cloned()
            .collect::<Vec<OperationValue>>();
        if result.is_empty() {
            return Err(StdError::not_found(format!(
                "Operation not found for txn_id: {:?} and operation: {}",
                event.txn_id(),
                event.operation()
            )));
        }
        Ok(result)
    }

    // Return the list of all operation values found in the storage and associated to the given
    // KMS operation. This can include values from different transactions that ran the same operation
    pub fn get_all_values_from_operation(
        &self,
        storage: &dyn Storage,
        operation: KmsOperation,
    ) -> StdResult<Vec<OperationValue>> {
        let mut operation_values = Vec::new();

        self.transactions
            .range(storage, None, None, Order::Ascending)
            .for_each(|tx| {
                if let Ok((_, tx)) = tx {
                    let ops = tx
                        .operations()
                        .iter()
                        .filter(|&op| {
                            <OperationValue as Into<KmsOperation>>::into((*op).clone()) == operation
                        })
                        .cloned();
                    operation_values.extend(ops);
                }
            });
        if operation_values.is_empty() {
            return Err(StdError::not_found(format!(
                "Operation {} not found in any transaction",
                operation
            )));
        }
        Ok(operation_values)
    }

    // Return the list of all operation values from all transactions found in the storage
    pub fn get_all_operations_values(
        &self,
        storage: &dyn Storage,
    ) -> StdResult<Vec<OperationValue>> {
        let mut operation_values = Vec::new();

        self.transactions
            .range(storage, None, None, Order::Ascending)
            .for_each(|tx| {
                if let Ok((_, tx)) = tx {
                    let ops = tx.operations().iter().cloned();
                    operation_values.extend(ops);
                }
            });
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
            .update_transaction(ctx.deps.storage, &ctx.env, &txn_id.to_vec(), &operation)
            .unwrap();
        let tx = storage.load_transaction(ctx.deps.storage, txn_id).unwrap();
        assert_eq!(tx.operations().len(), 1);
        assert_eq!(tx.operations()[0], operation);
    }
}
