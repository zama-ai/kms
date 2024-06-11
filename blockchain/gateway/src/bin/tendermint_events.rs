use gateway::common::config::kms_contract_address;
use gateway::events::tendermint::event_manager::EventManager;
use std::str::FromStr;
use tendermint_rpc::{
    event::{Event, EventData},
    Error, Url,
};

#[tokio::main]
async fn main() {
    let url = Url::from_str("ws://localhost:36657/websocket").unwrap();
    let contract_addr = kms_contract_address().to_string();

    let event_manager = EventManager::new(url, &contract_addr);
    event_manager.start(on_event).await.unwrap();
}

fn on_event(event: Event) -> Result<(), Error> {
    // match on the event data
    match event.data {
        EventData::Tx { tx_result } => {
            // for all of the events, match on the event kind and print the attributes
            println!("🔥 Tx: (size: {:?})", tx_result.tx.len());
            //println!("Tx: {:?}", tx_result.tx);
            for event in tx_result.result.events.iter() {
                // println!("\t - Event: {:?}", event.kind.as_str());

                match event.kind.as_str() {
                    //"message" => {
                    //    println!("\t Message Event Attributes: {:#?}", event.attributes);
                    //}
                    "wasm-decrypt" => {
                        //println!(
                        //    "\n ➡️ Wasm Decrypt Event Attributes: {:#?}",
                        //    event.attributes
                        //);
                        println!("\t ➡️ Wasm Decrypt");
                    }
                    "wasm-decrypt_response" => {
                        //println!(
                        //    "\t ⬅️ Wasm Decrypt Response Event Attributes: {:#?}",
                        //    event.attributes
                        //);
                        println!("\t ⬅️ Wasm Decrypt Response");
                    }
                    _ => {}
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
