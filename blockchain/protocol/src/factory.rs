use serde::Serialize;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use tendermint_proto::abci::{Event, RequestQuery, ResponseCheckTx, ResponseInfo, ResponseQuery};
use tendermint_proto::abci::{ExecTxResult, RequestInfo};

use crate::transactions::Transaction;

impl AsRef<Transaction> for Transaction {
    fn as_ref(&self) -> &Transaction {
        self
    }
}

pub(crate) trait Contract: Sync + Send + 'static {
    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        Default::default()
    }

    fn query(&self, _request: RequestQuery) -> ResponseQuery {
        Default::default()
    }

    fn check(&self, _transaction: &Transaction) -> ResponseCheckTx {
        Default::default()
    }

    fn finalize(&self, _transaction: &Transaction) -> (ExecTxResult, Option<Event>) {
        Default::default()
    }
}

// implicit implementation of Serializable for all types that implement Serialize
pub(crate) trait ContractHelper: Any + Send + Sync + Contract + 'static {
    fn as_any(&self) -> &dyn Any;
    fn serialize(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

impl<T> ContractHelper for T
where
    T: Any + Default + Send + Sync + Contract + Serialize + ?Sized + 'static,
{
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn serialize(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        bincode::serialize(self).map_err(|e| e.into())
    }
}

#[derive(Default)]
pub(crate) struct ChainContracts {
    applications: HashMap<TypeId, Box<dyn ContractHelper>>,
}

impl ChainContracts {
    pub(crate) fn new() -> Self {
        ChainContracts {
            applications: HashMap::new(),
        }
    }

    pub(crate) fn register<T: ContractHelper + 'static>(&mut self, app: T) {
        self.applications.insert(TypeId::of::<T>(), Box::new(app));
    }

    pub(crate) fn get<T: Contract>(&self) -> &T {
        let binding = self.applications.get(&TypeId::of::<T>()).unwrap();
        binding.as_any().downcast_ref::<T>().unwrap()
    }

    pub(crate) fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&dyn ContractHelper),
    {
        for app in self.applications.values() {
            f(app.as_ref());
        }
    }
}
