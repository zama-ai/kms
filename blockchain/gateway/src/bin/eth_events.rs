use ethers::prelude::*;
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use ethers::types::BlockNumber;
use eyre::Result;
use gateway::common::provider::EventDecryptionFilter;
use gateway::config::{GatewayConfig, Settings};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let provider = Provider::<Ws>::connect_with_reconnects("ws://localhost:8546", 10).await?;
    let config: GatewayConfig = Settings::builder()
        .path(Some("config/gateway"))
        .build()
        .init_conf()
        .unwrap();
    let provider = Arc::new(provider);

    let mut last_block = provider
        .get_block(BlockNumber::Latest)
        .await?
        .unwrap()
        .number
        .unwrap();
    println!("last_block: {last_block}");
    let mut last_request_id = U256::zero();
    println!("last_request_id: {last_request_id}");
    let mut stream = provider.subscribe_blocks().await?;
    while let Some(block) = stream.next().await {
        println!("🧱 block number: {}", block.number.unwrap(),);

        // process any EventDecryption logs
        let events = provider
            .get_logs(
                &Filter::new()
                    .from_block(last_block)
                    .address(config.ethereum.oracle_predeploy_address)
                    .event(
                        "EventDecryption(uint256,(uint256,uint8)[],address,bytes4,uint256,uint256)",
                    ),
            )
            .await?;

        for log in events {
            let event_decryption: EventDecryptionFilter = EthLogDecode::decode_log(&log.into())?;
            if event_decryption.request_id > last_request_id {
                println!("\t⭐ event_decryption: {:?}", event_decryption.request_id);
                last_request_id = event_decryption.request_id;
            }
        }

        last_block = block.number.unwrap();
    }

    Ok(())
}
