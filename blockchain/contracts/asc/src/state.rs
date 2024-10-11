use crate::versioned_storage::{VersionedItem, VersionedMap};
use cosmwasm_std::{Env, Order, Response, StdError, StdResult, Storage};
use events::kms::{
    KmsCoreConf, KmsEvent, KmsOperation, OperationValue, Transaction, TransactionId,
};

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
    allow_list: VersionedItem<Vec<String>>,
}

impl Default for KmsContractStorage {
    fn default() -> Self {
        Self {
            core_conf: VersionedItem::new("core_conf"),
            transactions: VersionedMap::new("transactions"),
            debug_proof: VersionedItem::new("debug_proof"),
            verify_proof_contract_address: VersionedItem::new("verify_proof_contract_address"),
            allow_list: VersionedItem::new("allow_list"),
        }
    }
}

impl KmsContractStorage {
    // Load the configuration parameters from the storage
    pub fn load_core_conf(&self, storage: &dyn Storage) -> StdResult<KmsCoreConf> {
        self.core_conf.load(storage)
    }

    // Update the configuration parameters in the storage
    pub fn update_core_conf(
        &self,
        storage: &mut dyn Storage,
        value: KmsCoreConf,
    ) -> StdResult<Response> {
        if self.core_conf.may_load(storage)?.is_none() {
            self.core_conf.save(storage, &value)?;
        } else {
            self.core_conf
                .update(storage, |_| -> StdResult<KmsCoreConf> { Ok(value) })?;
        }
        Ok(Response::default())
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

    /// Set allow list.
    ///
    /// Some exec operations like key-gen, crs-gen, etc ... take a lot of resources and shouldn't
    /// be accessible to anyone. To allow some finer-grain control on who can launch said
    /// operations the contract holds a list of addresses of who can call these operations.
    /// In the future we might have to add an endpoint to modify the allow-list.
    pub fn set_allow_list(&self, storage: &mut dyn Storage, value: Vec<String>) -> StdResult<()> {
        self.allow_list.save(storage, &value)
    }

    pub fn allow_list_contains(
        &self,
        storage: &dyn Storage,
        value: &String,
    ) -> Result<bool, cosmwasm_std::StdError> {
        let allow_list: Vec<String> = self.allow_list.load(storage)?;
        // Check if wild card is set
        if (allow_list.len() == 1) && (allow_list[0] == "*") {
            return Ok(true);
        }
        Ok(allow_list.contains(value))
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
    use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{
        BlockInfo, ContractInfo, DepsMut, Empty, Env, MessageInfo, QuerierWrapper, TransactionInfo,
    };
    use cw_multi_test::IntoAddr;
    use events::kms::{DecryptValues, FheParameter, KmsCoreThresholdConf, TransactionId};
    use sylvia::types::ExecCtx;

    #[test]
    fn test_core_conf() {
        let dyn_store = &mut MockStorage::new();
        let storage = KmsContractStorage::default();
        let core_conf = KmsCoreConf::Threshold(KmsCoreThresholdConf {
            parties: vec![],
            response_count_for_majority_vote: 3,
            response_count_for_reconstruction: 3,
            degree_for_reconstruction: 1,
            param_choice: FheParameter::Test,
        });
        storage
            .update_core_conf(dyn_store, core_conf.clone())
            .unwrap();
        assert_eq!(storage.load_core_conf(dyn_store).unwrap(), core_conf);
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
