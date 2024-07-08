use ethers::prelude::*;
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use ethers::types::BlockNumber;
use eyre::Result;
use gateway::common::provider::EventDecryptionFilter;
use gateway::config::{init_conf_with_trace_gateway, GatewayConfig};
use std::sync::Arc;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "eth_events")]
struct Opts {
    /// WebSocket URL to connect to the Ethereum node
    #[structopt(short, long, default_value = "ws://localhost:8546")]
    url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::from_args();
    let provider = Provider::<Ws>::connect_with_reconnects(&opts.url, 10).await?;
    provider.get_chainid().await?;
    let config: GatewayConfig =
        init_conf_with_trace_gateway("config/gateway").map_err(|e| eyre::eyre!(e))?;

    let chain_id = provider.get_chainid().await?;
    println!("chain_id: {}", chain_id);

    println!("🔗 connected to Ethereum node: {}", opts.url);
    println!(
        "🔗 oracle_predeploy_address: {}",
        &config.ethereum.oracle_predeploy_address,
    );

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
                        "EventDecryption(uint256,uint256[],address,bytes4,uint256,uint256,bool)",
                    ),
            )
            .await?;

        for log in events {
            println!("\t🔍 log: {:?}", log);
            let event_decryption: EventDecryptionFilter = EthLogDecode::decode_log(&log.into())?;
            if event_decryption.request_id > last_request_id {
                println!("\t\t⭐ event_decryption: {:?}", event_decryption.request_id);
                last_request_id = event_decryption.request_id;
            }
        }

        last_block = block.number.unwrap();
    }

    Ok(())
}
