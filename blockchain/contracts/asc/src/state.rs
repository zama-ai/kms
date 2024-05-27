use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Response, StdError, StdResult, Storage};
use cw_storage_plus::{Item, Map};
use events::kms::{KmsEvent, KmsOperation, OperationValue, Transaction, TransactionId};
use events::HexVector;
use sylvia::types::ExecCtx;

#[cw_serde]
pub enum KmsCoreConf {
    Centralized,
    Threshold(KmsCoreThresholdConf),
}

#[cw_serde]
pub struct KmsCoreThresholdConf {
    pub parties: Vec<KmsCoreParty>,
}

impl KmsCoreThresholdConf {
    pub fn calculate_threshold(&self) -> usize {
        (self.parties.len().saturating_sub(1) as u8 / 3) as usize
    }
}

impl KmsCoreConf {
    pub fn calculate_threshold(&self) -> usize {
        match self {
            KmsCoreConf::Centralized => 0,
            KmsCoreConf::Threshold(conf) => conf.calculate_threshold(),
        }
    }
}

#[cw_serde]
#[derive(Default)]
pub struct KmsCoreParty {
    pub party_id: HexVector,
    pub public_key: HexVector,
    pub address: String,
    pub tls_pub_key: Option<HexVector>,
}

pub struct KmsContractStorage {
    core_conf: Item<KmsCoreConf>,
    transactions: Map<Vec<u8>, Transaction>,
}

impl KmsContractStorage {
    pub fn new() -> Self {
        Self {
            core_conf: Item::new("core_conf"),
            transactions: Map::new("transactions"),
        }
    }

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
        ctx: &mut ExecCtx,
        txn_id: &[u8],
        operation: &T,
    ) -> StdResult<()>
    where
        T: Into<OperationValue> + Clone,
    {
        self.transactions
            .update(ctx.deps.storage, txn_id.to_vec(), |tx| {
                let tx_updated = tx
                    .map(|mut tx| {
                        tx.add_operation(operation.clone().into())
                            .map_err(|e| StdError::generic_err(e.to_string()))?;
                        Ok(tx) as Result<Transaction, StdError>
                    })
                    .unwrap_or_else(|| {
                        let tx = ctx.env.transaction.clone().ok_or_else(|| {
                            StdError::generic_err("Transaction not found in context")
                        })?;
                        Ok(Transaction::builder()
                            .block_height(ctx.env.block.height)
                            .transaction_index(tx.index)
                            .operations(vec![operation.clone().into()])
                            .build())
                    })?;
                Ok(tx_updated) as Result<Transaction, StdError>
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
    use events::kms::{DecryptValues, TransactionId};

    #[test]
    fn test_calculate_threshold_centralized() {
        let core_conf = KmsCoreConf::Centralized;
        assert_eq!(core_conf.calculate_threshold(), 0);
    }

    #[test]
    fn test_calculate_threshold() {
        let core_conf = KmsCoreThresholdConf { parties: vec![] };
        assert_eq!(core_conf.calculate_threshold(), 0);
        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default()],
        };
        assert_eq!(core_conf.calculate_threshold(), 0);

        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 3],
        };
        assert_eq!(core_conf.calculate_threshold(), 0);

        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 4],
        };
        assert_eq!(core_conf.calculate_threshold(), 1);

        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 5],
        };
        assert_eq!(core_conf.calculate_threshold(), 1);

        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 6],
        };

        assert_eq!(core_conf.calculate_threshold(), 1);

        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 7],
        };

        assert_eq!(core_conf.calculate_threshold(), 2);
    }

    #[test]
    fn test_core_conf() {
        let dyn_store = &mut MockStorage::new();
        let storage = KmsContractStorage::new();
        let core_conf = KmsCoreConf::Threshold(KmsCoreThresholdConf { parties: vec![] });
        storage
            .update_core_conf(dyn_store, core_conf.clone())
            .unwrap();
        assert_eq!(storage.load_core_conf(dyn_store).unwrap(), core_conf);
    }

    #[test]
    fn test_transaction() {
        let dyn_storage = &mut MockStorage::new();
        let storage = KmsContractStorage::new();
        let mock_queries = MockQuerier::<Empty>::new(&[]);
        let mut ctx = ExecCtx {
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
                querier: QuerierWrapper::new(&mock_queries),
            },
            info: MessageInfo {
                sender: "sender".into_addr(),
                funds: vec![],
            },
        };
        let txn_id = TransactionId::default();
        let operation = OperationValue::Decrypt(DecryptValues::default());
        storage
            .update_transaction(&mut ctx, &txn_id.to_vec(), &operation)
            .unwrap();
        let tx = storage.load_transaction(ctx.deps.storage, txn_id).unwrap();
        assert_eq!(tx.operations().len(), 1);
        assert_eq!(tx.operations()[0], operation);
    }
}
