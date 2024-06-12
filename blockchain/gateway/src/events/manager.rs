use crate::command::decrypt::handler::handle_event_decryption;
use crate::common::provider::EventDecryptionFilter;
use crate::config::GatewayConfig;
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
    config: GatewayConfig,
}

impl<'a> EventManager<'a> {
    pub fn new(
        provider: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
        atomic_height: &'a Arc<AtomicBlockHeight>,
        config: GatewayConfig,
    ) -> Self {
        Self {
            provider: Arc::clone(provider),
            atomic_height,
            config,
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

        let mut last_block = self
            .provider
            .get_block(BlockNumber::Latest)
            .await?
            .unwrap()
            .number
            .unwrap();
        debug!("last_block: {last_block}");
        let mut last_request_id = U256::zero();
        debug!("last_request_id: {last_request_id}");
        let mut stream = self.provider.subscribe_blocks().await?;
        while let Some(block) = stream.next().await {
            info!("🧱 block number: {}", block.number.unwrap(),);

            // process any EventDecryption logs
            let events = self.provider
            .get_logs(
                &Filter::new()
                    .from_block(last_block)
                    .address(self.config.ethereum.oracle_predeploy_address)
                    .event(
                        "EventDecryption(uint256,(uint256,uint8)[],address,bytes4,uint256,uint256)",
                    ),
            )
            .await?;

            for log in events {
                let block_number = log.block_number.unwrap().as_u64();
                debug!("Block: {:?}", block_number);
                let _ = self.atomic_height.try_update(block_number);
                let event_decryption: EventDecryptionFilter =
                    EthLogDecode::decode_log(&log.clone().into())?;
                if event_decryption.request_id > last_request_id {
                    last_request_id = event_decryption.request_id;
                    info!("⭐ event_decryption: {:?}", event_decryption.request_id);
                    debug!("EventDecryptionFilter: {:?}", event_decryption);

                    if let Err(e) = handle_event_decryption(
                        &self.provider,
                        &Arc::new(event_decryption.clone()),
                        &self.config,
                        log.block_number.unwrap().as_u64(),
                    )
                    .await
                    {
                        error!("Error handling event decryption: {:?}", e);
                    }

                    info!(
                        "Handled event decryption: {:?}",
                        event_decryption.request_id
                    );
                }
            }

            last_block = block.number.unwrap();
        }

        Ok(())
    }
}
