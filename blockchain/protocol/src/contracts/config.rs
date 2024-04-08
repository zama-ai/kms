use std::collections::HashMap;

use crate::factory::Contract;
use crate::transactions::transaction::Payload;
use crate::transactions::Transaction;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tendermint_proto::abci::{
    Event, EventAttribute, ExecTxResult, RequestInfo, RequestQuery, ResponseCheckTx, ResponseInfo,
    ResponseQuery,
};
use tracing::info;

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct ConfigContract {
    store: Mutex<HashMap<String, String>>,
}

impl Contract for ConfigContract {
    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        ResponseInfo {
            data: "ConfigContract".to_string(),
            version: "0.1.0".to_string(),
            app_version: 1,
            last_block_height: 0,
            last_block_app_hash: Vec::new().into(),
        }
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        let key = match std::str::from_utf8(&request.data) {
            Ok(s) => s,
            Err(e) => panic!("Failed to interpret key as UTF-8: {e}"),
        };
        info!("Attempting to get key: {}", key);
        let store = self.store.lock().unwrap();

        match store.get(key).cloned() {
            Some(value) => ResponseQuery {
                code: 0,
                log: "Success".to_string(),
                info: "".to_string(),
                index: 0,
                key: request.data,
                value: value.clone().into_bytes().into(),
                proof_ops: None,
                height: 0,
                codespace: "".to_string(),
            },
            None => ResponseQuery {
                code: 1,
                log: "Key not found".to_string(),
                info: "".to_string(),
                index: 0,
                key: request.data,
                value: Default::default(),
                proof_ops: None,
                height: 0,
                codespace: "".to_string(),
            },
        }
    }

    fn check(&self, _transaction: &Transaction) -> ResponseCheckTx {
        ResponseCheckTx {
            ..Default::default()
        }
    }

    fn finalize(&self, transaction: &Transaction) -> (ExecTxResult, Option<Event>) {
        match transaction.payload.as_ref().unwrap() {
            Payload::SetConfig(config) => {
                let mut store = self.store.lock().unwrap();
                store.insert(config.key.clone(), config.value.clone());
                let result = ExecTxResult {
                    log: format!("set key = {:#?}", config.key),
                    ..Default::default()
                };
                let event = Event {
                    r#type: "config_contract".to_string(),
                    attributes: vec![EventAttribute {
                        key: config.key.to_owned(),
                        value: config.value.to_owned(),
                        index: true,
                    }],
                };
                (result, Some(event))
            }
            _ => (
                ExecTxResult {
                    code: 1,
                    log: "Invalid payload".to_string(),
                    ..Default::default()
                },
                None,
            ),
        }
    }
}
