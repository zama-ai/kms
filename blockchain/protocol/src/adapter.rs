use crate::contracts::config::ConfigContract;
use crate::factory::ChainContracts;
use crate::factory::Contract;
use crate::factory::ContractHelper;
use crate::transactions::transaction::Payload;
use crate::transactions::Transaction;
use crate::wallet::Verify;
use core::fmt::Display;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::{self, Formatter};
use std::sync::Arc;
use tendermint_abci::Application;
use tendermint_proto::abci::{
    RequestCheckTx, RequestFinalizeBlock, RequestInfo, RequestQuery, ResponseCheckTx,
    ResponseCommit, ResponseFinalizeBlock, ResponseInfo, ResponseQuery,
};
use tracing::info;

impl Display for Payload {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Payload::Decryption(decryption) => write!(f, "Decryption: {:?}", decryption),
            Payload::Reencryption(reencryption) => write!(f, "Reencryption: {:?}", reencryption),
            Payload::SetConfig(config) => write!(f, "SetConfig: {:?}", config),
        }
    }
}

#[derive(Clone)]
pub struct ContractAdapter {
    _store: HashMap<String, String>,
    height: i64,
    app_hash: Vec<u8>,
    app_factory: Arc<ChainContracts>,
}

impl Default for ContractAdapter {
    fn default() -> Self {
        let mut factory = ChainContracts::new();
        factory.register(ConfigContract::default());

        Self {
            _store: HashMap::new(),
            height: 0,
            app_hash: Vec::new(),
            app_factory: Arc::new(factory),
        }
    }
}

impl Application for ContractAdapter {
    fn info(&self, request: RequestInfo) -> ResponseInfo {
        let mut data: Vec<String> = Vec::new();
        self.app_factory
            .for_each(|instance| data.push(instance.info(request.clone()).data));

        ResponseInfo {
            data: format!("Contracts Adapter: [ {} ]", data.join(", ")),
            version: "0.1.0".to_string(),
            app_version: 1,
            last_block_height: self.height,
            last_block_app_hash: self.app_hash.clone().into(),
        }
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        info!("Query request: {:?}", request);
        match request.path.as_str() {
            "/kms/config" => {
                println!("SetConfig path: {:?}", request.path);
                self.app_factory.get::<ConfigContract>().query(request)
            }
            _ => ResponseQuery {
                code: 1,
                log: "Invalid query path".to_string(),
                info: "".to_string(),
                index: 0,
                key: request.data.clone(),
                value: Default::default(),
                proof_ops: None,
                height: 0,
                codespace: "".to_string(),
            },
        }
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        info!("Checking transaction {:?}", request);
        let transaction: Transaction = bincode::deserialize(&request.tx).unwrap();
        println!("Transaction: {:?}", transaction);
        println!("verified: {:?}", transaction.verify());

        // match on the transaction payload type
        match transaction.payload {
            Some(ref payload) => match payload {
                Payload::Decryption(decryption) => {
                    println!("Decryption payload: {:?}", decryption);
                    todo!("Implement decryption")
                }
                Payload::Reencryption(reencryption) => {
                    println!("Reencryption payload: {:?}", reencryption);
                    todo!("Implement reencryption")
                }
                Payload::SetConfig(config) => {
                    println!("SetConfig payload: {:?}", config);
                    self.app_factory.get::<ConfigContract>().check(&transaction);
                }
            },
            None => {
                println!("No payload found");
            }
        }

        // info!("Checked transaction {:?}", request);
        ResponseCheckTx {
            code: 0,
            data: Default::default(),
            log: "".to_string(),
            info: "".to_string(),
            gas_wanted: 1,
            gas_used: 0,
            events: vec![],
            codespace: "".to_string(),
        }
    }

    fn commit(&self) -> ResponseCommit {
        let mut self_mut = self.clone();
        self.app_factory
            .for_each(|instance| self_mut.do_commit(instance));
        info!("Committed height {}", self.height);
        ResponseCommit {
            retain_height: self.height - 1,
        }
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        info!("Finalizing block with {} transactions", request.txs.len());
        let mut events = Vec::new();
        let mut tx_results = Vec::new();
        for tx in &request.txs {
            info!("Checking transaction {:?}", request);
            let transaction: Transaction = bincode::deserialize(tx).unwrap();
            println!("Transaction: {:?}", transaction);
            //println!("verified: {:?}", transaction.verify());

            let (result, event) = match transaction.payload {
                Some(ref payload) => match payload {
                    Payload::Decryption(decryption) => {
                        println!("Decryption payload: {:?}", decryption);
                        todo!("Implement decryption")
                    }
                    Payload::Reencryption(reencryption) => {
                        println!("Reencryption payload: {:?}", reencryption);
                        todo!("Implement reencryption")
                    }
                    Payload::SetConfig(config) => {
                        println!("SetConfig payload: {:?}", config);
                        let contract: &ConfigContract = self.app_factory.get();
                        contract.finalize(&transaction)
                    }
                },
                None => {
                    println!("No payload found");
                    (Default::default(), None)
                }
            };

            // intercept here
            //let _ = self.set(key, value).unwrap();
            //
            events.push(event.unwrap());
            tx_results.push(result);
        }
        info!("Finalized block with {:?} events", events);

        ResponseFinalizeBlock {
            events,
            tx_results,
            ..Default::default()
        }
    }
}

impl ContractAdapter {
    fn do_commit<T: ContractHelper + ?Sized>(&mut self, contract: &T) {
        self.app_hash = self.hash_contract(contract).unwrap();
        self.height += 1;
    }

    fn hash_contract<T: ContractHelper + ?Sized>(
        &self,
        contract: &T,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Serialize the contract using bincode
        let serialized = contract.serialize()?;
        // Compute SHA256 hash of the binary serialization
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let hash = hasher.finalize().to_vec();
        Ok(hash)
    }
}
