use gateway::{
    config::{init_conf_with_trace_gateway, GatewayConfig},
    events::tendermint::event_manager::EventManager,
};
use std::str::FromStr;
use tendermint_rpc::{
    event::{Event, EventData},
    Error, Url,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = Url::from_str("ws://localhost:36657/websocket").unwrap();
    let config: GatewayConfig = init_conf_with_trace_gateway("config/gateway")?;
    let contract_addr = config.kms.contract_address.to_string();

    let event_manager = EventManager::new(url, &contract_addr);
    event_manager.start(on_event).await?;
    Ok(())
}

fn on_event(event: Event) -> Result<(), Error> {
    // match on the event data

    match event.data {
        EventData::Tx { tx_result } => {
            // for all of the events, match on the event kind and print the attributes
            println!("🔥 Tx: (size: {:?})", tx_result.tx.len());
            //println!("Tx: {:?}", tx_result.tx);
            for event in tx_result.result.events.iter() {
                println!("\t - Event: {:?}", event.kind.as_str());

                // match events that start with wasm-
                if event.kind.as_str().starts_with("wasm-") {
                    println!("\t - Event: {:?}", event.kind.as_str());
                    println!(
                        "\t\t ➡️ Wasm Decrypt Event Attributes: {:#?}",
                        event.attributes
                    );
                }
            }
        }
        EventData::NewBlock {
            block,
            block_id: _,
            result_finalize_block: _,
        } => {
            println!("New Block Event: {:?}", block);
        }
        EventData::GenericJsonEvent(data) => {
            println!("Generic JSON Event: {:?}", data);
        }
        _ => {
            //println!("Event Data: {:?}", event.data);
        }
    }
    Ok(())
}
