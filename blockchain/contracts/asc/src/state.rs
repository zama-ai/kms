use cosmwasm_std::{Env, Response, StdError, StdResult, Storage};
use cw_storage_plus::{Item, Map};
use events::kms::{
    KmsCoreConf, KmsEvent, KmsOperation, OperationValue, Transaction, TransactionId,
};

pub struct KmsContractStorage {
    core_conf: Item<KmsCoreConf>,
    transactions: Map<Vec<u8>, Transaction>,
    id_replies: Item<u64>,
    pending_transactions: Map<u64, OperationValue>,
    debug_proof: Item<bool>,
}

impl Default for KmsContractStorage {
    fn default() -> Self {
        Self {
            core_conf: Item::new("core_conf"),
            transactions: Map::new("transactions"),
            id_replies: Item::new("id_replies"),
            pending_transactions: Map::new("pending_transactions"),
            debug_proof: Item::new("debug_proof"),
        }
    }
}

impl KmsContractStorage {
    pub fn load_core_conf(&self, storage: &dyn Storage) -> StdResult<KmsCoreConf> {
        self.core_conf.load(storage)
    }

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

    pub fn load_transaction(
        &self,
        storage: &dyn Storage,
        key: TransactionId,
    ) -> StdResult<Transaction> {
        self.transactions.load(storage, key.to_vec())
    }

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
                    Ok(Transaction::builder()
                        .block_height(env.block.height)
                        .transaction_index(tx.index)
                        .operations(vec![operation.clone().into()])
                        .build())
                })?;
            Ok(tx_updated) as Result<Transaction, StdError>
        })?;
        Ok(())
    }

    pub fn next_id(&self, storage: &mut dyn Storage) -> StdResult<u64> {
        if self.id_replies.may_load(storage)?.is_none() {
            self.id_replies.save(storage, &0)?;
        }
        self.id_replies
            .update(storage, |count| -> StdResult<u64> { Ok(count + 1) })
    }

    pub fn add_pending_transaction<T: Into<OperationValue>>(
        &self,
        storage: &mut dyn Storage,
        reply_id: u64,
        operation: T,
    ) -> StdResult<()> {
        self.pending_transactions
            .save(storage, reply_id, &operation.into())
    }

    pub fn get_pending_transaction(
        &self,
        storage: &dyn Storage,
        reply_id: u64,
    ) -> StdResult<OperationValue> {
        self.pending_transactions.load(storage, reply_id)
    }

    pub fn remove_pending_transaction(
        &self,
        storage: &mut dyn Storage,
        reply_id: u64,
    ) -> StdResult<()> {
        self.pending_transactions.remove(storage, reply_id);
        Ok(())
    }

    pub fn set_debug_proof(&self, storage: &mut dyn Storage, value: bool) -> StdResult<()> {
        self.debug_proof.save(storage, &value)
    }

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
