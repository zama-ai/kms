use crate::command::decrypt::handler::handle_event_decryption;
use crate::common::config::oracle_predeploy_address;
use crate::common::provider::EventDecryptionFilter;
use crate::common::provider::ResultCallbackFilter;
use crate::events::manager::k256::ecdsa::SigningKey;
use crate::util::height::AtomicBlockHeight;
use ethers::prelude::*;
use eyre::Result;
use std::error::Error;
use std::sync::Arc;
use tracing::{debug, error, info};

#[derive(Debug)]
pub enum EventType {
    EventDecryptionLog(Log),
    ResultCallbackLog(Log),
}

pub struct EventManager<'a> {
    provider: Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
    atomic_height: &'a Arc<AtomicBlockHeight>,
}

impl<'a> EventManager<'a> {
    pub fn new(
        provider: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
        atomic_height: &'a Arc<AtomicBlockHeight>,
    ) -> Self {
        Self {
            provider: Arc::clone(provider),
            atomic_height,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
        let last_block = self
            .provider
            .get_block(BlockNumber::Latest)
            .await
            .unwrap_or_else(|e| {
                error!("Failed to get latest block: {:?}", e);
                std::process::exit(1);
            })
            .unwrap()
            .number
            .unwrap();
        info!("last_block: {last_block}");
        let event_decryption_stream = self
            .provider
            .subscribe_logs(
                &Filter::new()
                    .address(oracle_predeploy_address())
                    .from_block(last_block)
                    .event(
                        "EventDecryption(uint256,(uint256,uint8)[],address,bytes4,uint256,uint256)",
                    ),
            )
            .await
            .unwrap_or_else(|e| {
                error!("Failed to subscribe to EventDecryption logs: {:?}", e);
                std::process::exit(1);
            });

        let result_callback_stream = self
            .provider
            .subscribe_logs(
                &Filter::new()
                    .address(oracle_predeploy_address())
                    .from_block(last_block)
                    .event("ResultCallback(uint256,bool,bytes)"),
            )
            .await
            .unwrap_or_else(|e| {
                error!("Failed to subscribe to ResultCallback logs: {:?}", e);
                std::process::exit(1);
            });

        let mut combined_stream = futures::stream::select_all(vec![
            event_decryption_stream
                .map(EventType::EventDecryptionLog)
                .boxed(),
            result_callback_stream
                .map(EventType::ResultCallbackLog)
                .boxed(),
        ]);

        while let Some(event) = combined_stream.next().await {
            match event {
                EventType::EventDecryptionLog(log) => {
                    let block_number = log.block_number.unwrap().as_u64();
                    debug!("Block: {:?}", block_number);
                    let _ = self.atomic_height.try_update(block_number);
                    match <EventDecryptionFilter as EthLogDecode>::decode_log(&log.into()) {
                        Ok(event) => {
                            debug!("Parsed Event: {:?}", event);
                            debug!("EventDecryptionFilter: {:?}", event);
                            if let Err(e) = handle_event_decryption(
                                &self.provider,
                                &Arc::new(event.clone()),
                                block_number,
                            )
                            .await
                            {
                                error!("Error handling event decryption: {:?}", e);
                            }
                            debug!("Handled event decryption: {:?}", event.request_id);
                        }
                        Err(e) => error!("Failed to parse event: {:?}", e),
                    }
                }
                EventType::ResultCallbackLog(log) => {
                    let block_number = log.block_number.unwrap().as_u64();
                    debug!("Block: {:?}", block_number);
                    let _ = self.atomic_height.try_update(block_number);
                    match <ResultCallbackFilter as EthLogDecode>::decode_log(&log.into()) {
                        Ok(event) => {
                            debug!("Parsed Event: {:?}", event);
                            debug!("Handled result callback: {:?}", event.request_id);
                        }
                        Err(e) => error!("Failed to parse event: {:?}", e),
                    }
                }
            }
        }
        Ok(())
    }
}
