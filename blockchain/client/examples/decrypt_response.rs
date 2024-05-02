use clap::Parser;
use kms_blockchain_client::client::{Client, ClientBuilder};
use serde_json::json;

#[derive(Debug, Parser)]
struct Params {
    #[clap(short, long)]
    txn_id: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_line_number(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    let params = Params::parse();
    // Alice's mnemonic; ensure you use a secure way to handle the real mnemonic!
    // let alice_mnemonic_phrase = "bachelor similar spirit copper rely carbon web hobby conduct wrap conduct wire shine parrot erosion divert crucial balance lock reason price ignore educate open";
    let bob_mnemonic_phrase = "feel wife neither never floor volume express actor initial year throw hawk pink gaze deny prevent helmet clump hurt hour river behind employ ribbon";
    let mut client: Client = ClientBuilder::builder()
        .mnemonic_wallet(bob_mnemonic_phrase)
        .grpc_addresses(vec!["http://localhost:9090"])
        .contract_address("wasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4d")
        .build()
        .try_into()
        .unwrap();

    let txn_id = hex::decode(params.txn_id).unwrap();
    let plaintext = vec![6, 7, 8, 9, 10];

    let msg = json!({
        "decrypt_response": {
            "txn_id": txn_id,
            "plaintext": plaintext,
        }
    })
    .to_string();

    // send the decrypted response to the contract
    let response = client
        .execute_contract(msg.as_bytes(), 100_000u64)
        .await
        .unwrap();
    tracing::info!("Response: {:?}", response.clone().tx_response.unwrap());
}
